import { collectFiles } from "./walk";
import { secretFindings } from "./secrets";
import { envFindings } from "./envcheck";
import { astFindings } from "./analyze2";
import { miscFindings } from "./misc";
import { pythonFindings } from "./python";
import { interprocFindings } from "./interproc";
import { crossFileSummaries } from "./taint";
import { goFindings } from "./go";
import { type Finding, type Severity, type Confidence, SEVERITY_ORDER, CONFIDENCE_ORDER } from "./types";
import type { VibecheckConfig } from "./config";

export interface ScanResult {
  findings: Finding[];
  counts: Record<Severity, number>;
}

function globToRe(p: string): RegExp {
  return new RegExp(`^${p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`);
}

export function sortFindings(f: Finding[]): Finding[] {
  return [...f].sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
      a.file.localeCompare(b.file) || a.line - b.line || a.ruleId.localeCompare(b.ruleId),
  );
}

export function countBySeverity(f: Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, review: 0 };
  for (const x of f) c[x.severity]++;
  return c;
}

/** Scan a project directory with all detectors, honoring `.vibecheck.json`. */
export function scanProject(dir: string, cfg: VibecheckConfig = {}): ScanResult {
  const files = collectFiles(dir);
  const summaries = crossFileSummaries(files);
  const raw = [...secretFindings(files), ...envFindings(files), ...astFindings(files, summaries), ...miscFindings(files), ...pythonFindings(files), ...interprocFindings(files, summaries), ...goFindings(files)];
  const ignore = new Set(cfg.ignoreRules ?? []);
  const allow = (cfg.allowPaths ?? []).map(globToRe);
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of raw) {
    if (ignore.has(f.ruleId) || allow.some((re) => re.test(f.file))) continue;
    const k = `${f.file}:${f.line}:${f.ruleId}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(f);
  }
  return { findings: sortFindings(out), counts: countBySeverity(out) };
}

/** True if any finding meets the fail severity AND confidence (default: high-confidence only). */
export function meetsFail(findings: Finding[], failSeverity: Severity, minConfidence: Confidence = "high"): boolean {
  const s = SEVERITY_ORDER[failSeverity];
  const c = CONFIDENCE_ORDER[minConfidence];
  return findings.some((f) => SEVERITY_ORDER[f.severity] >= s && CONFIDENCE_ORDER[f.confidence] >= c);
}
