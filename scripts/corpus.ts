/** Real-world corpus harness: shallow-clone pinned OSS repos, run scanProject, and aggregate
 *  HIGH-confidence findings (what `--ci`/MCP would surface) per rule, with timing. Reproducible. */
import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { scanProject } from "../src/engine";
import { collectFiles } from "../src/walk";

const REPOS = [
  { name: "expressjs/express", url: "https://github.com/expressjs/express.git", ref: "4.21.2", kind: "JS — mature web framework" },
  { name: "fastify/fastify", url: "https://github.com/fastify/fastify.git", ref: "v4.28.1", kind: "JS/TS — mature web framework" },
  { name: "OWASP/NodeGoat", url: "https://github.com/OWASP/NodeGoat.git", ref: "master", kind: "JS — intentionally vulnerable app" },
  { name: "pallets/flask", url: "https://github.com/pallets/flask.git", ref: "3.0.3", kind: "Python — mature web framework" },
  { name: "gin-gonic/gin", url: "https://github.com/gin-gonic/gin.git", ref: "v1.10.0", kind: "Go — mature web framework" },
];
const WORK = join(process.env.TMPDIR ?? "/tmp", "vibecheck-corpus");

function clone(url: string, ref: string, dir: string): string {
  rmSync(dir, { recursive: true, force: true });
  execFileSync("git", ["clone", "--depth", "1", "--branch", ref, url, dir], { stdio: "ignore" });
  return execFileSync("git", ["-C", dir, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
}

mkdirSync(WORK, { recursive: true });
const report: unknown[] = [];
for (const r of REPOS) {
  const dir = join(WORK, r.name.replace("/", "__"));
  let sha = "";
  try { sha = clone(r.url, r.ref, dir); } catch (e) { console.error(`clone FAILED ${r.name}: ${String(e)}`); continue; }
  const files = collectFiles(dir);
  const t0 = Date.now();
  const { findings } = scanProject(dir);
  const ms = Date.now() - t0;
  const high = findings.filter((f) => f.confidence === "high");
  const perRule: Record<string, number> = {};
  for (const f of high) perRule[f.ruleId] = (perRule[f.ruleId] ?? 0) + 1;
  report.push({ name: r.name, kind: r.kind, ref: r.ref, sha, files: files.length, ms, high: high.length, perRule,
    findings: high.map((f) => ({ rule: f.ruleId, sev: f.severity, file: f.file, line: f.line, snippet: f.snippet })) });
  console.log(`${r.name.padEnd(20)} @ ${sha.slice(0, 10)} | files=${String(files.length).padStart(5)} | ${String(ms).padStart(6)}ms | high=${String(high.length).padStart(3)} ${JSON.stringify(perRule)}`);
}
writeFileSync(join(WORK, "corpus-raw.json"), JSON.stringify(report, null, 2));
console.log(`\nRaw high-confidence findings → ${join(WORK, "corpus-raw.json")}`);
