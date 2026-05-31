import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { type SourceFile, type Finding, type Severity, type Confidence } from "./types";

const SRC = fileURLToPath(new URL("./go.go", import.meta.url));
const GOCACHE = process.env.GOCACHE ?? join(tmpdir(), "vibecheck-gocache");

function findGo(): string | null {
  for (const g of ["go", `${process.env.HOME}/.local/go/bin/go`]) {
    try { if (spawnSync(g, ["version"]).status === 0) return g; } catch { /* keep trying */ }
  }
  return null;
}

let resolved: string | null | undefined;
/** Compile the analyzer once to a cached binary (keyed by source hash). Returns its path, or null if go is unavailable. */
function bin(): string | null {
  if (resolved !== undefined) return resolved;
  const go = findGo();
  if (!go) { resolved = null; return resolved; }
  const hash = createHash("sha256").update(readFileSync(SRC)).digest("hex").slice(0, 16);
  const out = join(tmpdir(), `vibecheck-go-${hash}`);
  if (!existsSync(out)) {
    const r = spawnSync(go, ["build", "-o", out, SRC], { encoding: "utf8", env: { ...process.env, GOCACHE } });
    if (r.status !== 0 || !existsSync(out)) {
      process.stderr.write(`vibecheck: Go analyzer failed to compile; .go files will be skipped${r.stderr ? `: ${String(r.stderr).split("\n")[0]}` : ""}\n`);
      resolved = null;
      return resolved;
    }
  }
  resolved = out;
  return resolved;
}

/** Is the Go analyzer usable (a working `go` toolchain present)? */
export function goAvailable(): boolean { return bin() !== null; }

/** Analyze .go files with the real go/parser analyzer. Returns [] (skips) if `go` is unavailable. */
export function goFindings(files: SourceFile[]): Finding[] {
  const go = files.filter((f) => f.rel.endsWith(".go"));
  if (go.length === 0) return [];
  const exe = bin();
  if (!exe) return [];
  const input = JSON.stringify(go.map((f) => ({ path: f.rel, content: f.content })));
  const r = spawnSync(exe, [], { input, encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  if (r.status !== 0 || !r.stdout) {
    process.stderr.write(`vibecheck: Go analyzer failed — ${go.length} .go file(s) NOT scanned${r.stderr ? `: ${String(r.stderr).split("\n")[0]}` : ""}\n`);
    return [];
  }
  let raw: Array<Record<string, unknown>>;
  try { raw = JSON.parse(r.stdout); } catch {
    process.stderr.write(`vibecheck: Go analyzer emitted invalid output — ${go.length} .go file(s) NOT scanned\n`);
    return [];
  }
  const byRel = new Map(go.map((f) => [f.rel, f]));
  return raw.map((x) => {
    const rel = String(x.File);
    const line = Number(x.Line) || 1;
    const content = byRel.get(rel)?.content ?? "";
    return {
      ruleId: String(x.RuleId), severity: x.Severity as Severity, confidence: x.Confidence as Confidence,
      file: rel, line, col: Number(x.Col) || 1, message: String(x.Message),
      snippet: (content.split("\n")[line - 1] ?? "").trim(), remediation: String(x.Remediation),
    };
  });
}
