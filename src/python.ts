import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { type SourceFile, type Finding, type Severity, type Confidence } from "./types";

const SCRIPT = fileURLToPath(new URL("./python.py", import.meta.url));
let pyOk: boolean | null = null;

/** Is python3 available? (Python scanning needs it only to parse via the stdlib ast.) */
export function pythonAvailable(): boolean {
  if (pyOk === null) {
    try { pyOk = spawnSync("python3", ["--version"]).status === 0; } catch { pyOk = false; }
  }
  return pyOk;
}

/** Analyze .py files with the real-ast Python analyzer. Returns [] (skips) if python3 is unavailable. */
export function pythonFindings(files: SourceFile[]): Finding[] {
  const py = files.filter((f) => f.rel.endsWith(".py"));
  if (py.length === 0 || !pythonAvailable()) return [];
  const input = JSON.stringify(py.map((f) => ({ path: f.rel, content: f.content })));
  const r = spawnSync("python3", [SCRIPT], { input, encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  if (r.status !== 0 || !r.stdout) return [];
  let raw: Array<Record<string, unknown>>;
  try { raw = JSON.parse(r.stdout); } catch { return []; }
  const byRel = new Map(py.map((f) => [f.rel, f]));
  return raw.map((x) => {
    const rel = String(x.file);
    const line = Number(x.line) || 1;
    const content = byRel.get(rel)?.content ?? "";
    return {
      ruleId: String(x.ruleId), severity: x.severity as Severity, confidence: x.confidence as Confidence,
      file: rel, line, col: Number(x.col) || 1, message: String(x.message),
      snippet: (content.split("\n")[line - 1] ?? "").trim(), remediation: String(x.remediation),
    };
  });
}
