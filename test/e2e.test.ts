import { test, expect, describe, afterAll } from "bun:test";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { scanProject, meetsFail, SEVERITY_ORDER } from "../src/index";

const tmp = mkdtempSync(join(tmpdir(), "vibecheck-e2e-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
const dec = new TextDecoder();
const run = (...a: string[]) => {
  const p = Bun.spawnSync(["bun", "src/cli.ts", ...a], { cwd: process.cwd() });
  return { code: p.exitCode ?? -1, out: dec.decode(p.stdout) + dec.decode(p.stderr) };
};
const mk = (root: string, rel: string, content: string) => {
  const f = join(root, rel);
  mkdirSync(dirname(f), { recursive: true });
  writeFileSync(f, content);
};

// ---- vulnerable fixture app ----
const vuln = join(tmp, "vuln");
mk(vuln, ".env", "API_KEY=supersecretvalue1234567\n");
mk(vuln, "server.ts", [
  'import express from "express";',
  'const app = express();',
  'const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";',
  'app.get("/users", (req, res) => { res.json(db.users); });',
  'app.post("/run", (req, res) => { eval(req.body.code); });',
  'app.get("/q", (req, res) => { db.query(`SELECT * FROM u WHERE id=${req.query.id}`); });',
  'app.use(cors({ origin: "*", credentials: true }));',
  'jwt.verify(token, secret);',
  'res.cookie("session", t, { httpOnly: true });',
].join("\n"));

// ---- clean fixture app ----
const clean = join(tmp, "clean");
mk(clean, ".gitignore", ".env\n");
mk(clean, ".env", "API_KEY=whatever\n"); // gitignored ⇒ not scanned
mk(clean, "server.ts", [
  'import express from "express";',
  'import { z } from "zod";',
  'import { requireAuth } from "./auth";',
  'const app = express();',
  'app.get("/users", requireAuth, (req, res) => { res.json(safe); });',
  'app.post("/run", requireAuth, (req, res) => { const b = z.object({}).parse(req.body); });',
  'app.get("/q", requireAuth, (req, res) => { db.query("SELECT * FROM u WHERE id=$1", [req.query.id]); });',
  'app.use(cors({ origin: "https://app.example.com", credentials: true }));',
  'jwt.verify(token, secret, { algorithms: ["HS256"] });',
  'res.cookie("session", t, { httpOnly: true, secure: true, sameSite: "lax" });',
].join("\n"));

describe("AC5.5 end-to-end", () => {
  test("vulnerable app trips the expected rule set incl. critical", () => {
    const r = scanProject(vuln);
    const ids = new Set(r.findings.map((f) => f.ruleId));
    for (const id of ["VC-SECRET-GITHUB", "VC-ENV-COMMITTED", "VC-RCE-EVAL", "VC-SQLI-TEMPLATE", "VC-CORS-WILDCARD", "VC-JWT-UNPINNED", "VC-COOKIE-INSECURE", "VC-ROUTE-NO-AUTH"]) {
      expect(ids.has(id)).toBe(true);
    }
    expect(r.counts.critical).toBeGreaterThan(0);
    expect(meetsFail(r.findings, "high")).toBe(true);
  });
  test("clean app yields zero findings at or above medium", () => {
    const r = scanProject(clean);
    const atMedium = r.findings.filter((f) => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.medium);
    expect(atMedium).toEqual([]);
  });
});

describe("AC5.1/5.2/5.3/5.4 CLI", () => {
  test("--ci exit codes: vuln non-zero, clean zero", () => {
    expect(run(vuln, "--ci").code).toBe(1);
    expect(run(clean, "--ci").code).toBe(0);
  });
  test("--json emits parseable findings; no --ci ⇒ exit 0", () => {
    const r = run(vuln, "--json");
    expect(r.code).toBe(0);
    const parsed = JSON.parse(r.out) as { findings: unknown[]; counts: Record<string, number> };
    expect(parsed.findings.length).toBeGreaterThan(5);
    expect(parsed.counts.critical).toBeGreaterThan(0);
  });
  test("explain known + unknown rule", () => {
    expect(run("explain", "VC-RCE-EVAL").code).toBe(0);
    expect(run("explain", "VC-RCE-EVAL").out).toContain("eval");
    expect(run("explain", "NOPE").code).toBe(2);
  });
  test("missing directory ⇒ non-zero", () => {
    expect(run(join(tmp, "ghost")).code).not.toBe(0);
  });
  test(".vibecheck.json ignoreRules suppresses", () => {
    writeFileSync(join(vuln, ".vibecheck.json"), JSON.stringify({ ignoreRules: ["VC-SECRET-GITHUB"] }));
    const r = scanProject(vuln, { ignoreRules: ["VC-SECRET-GITHUB"] });
    expect(r.findings.some((f) => f.ruleId === "VC-SECRET-GITHUB")).toBe(false);
    rmSync(join(vuln, ".vibecheck.json"));
  });
});
