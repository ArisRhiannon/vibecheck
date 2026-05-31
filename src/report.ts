import type { ScanResult } from "./engine";

/** Human-readable report grouped/sorted by severity. */
export function formatText(r: ScanResult): string {
  if (r.findings.length === 0) return "vibecheck: no findings.";
  const lines = r.findings.map(
    (f) => `${f.severity.toUpperCase().padEnd(8)} ${f.ruleId.padEnd(24)} ${f.file}:${f.line}  ${f.message}`,
  );
  const c = r.counts;
  lines.push("", `critical=${c.critical} high=${c.high} medium=${c.medium} review=${c.review} low=${c.low}`);
  return lines.join("\n");
}

/** Stable machine-readable report for agents/CI. */
export function toJSON(r: ScanResult): string {
  return JSON.stringify({ findings: r.findings, counts: r.counts }, null, 2);
}
