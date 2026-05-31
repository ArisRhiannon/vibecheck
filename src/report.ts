import type { ScanResult } from "./engine";

/** Human-readable report grouped/sorted by severity. */
export function formatText(r: ScanResult): string {
  if (r.findings.length === 0) return "vibecheck: no findings.";
  const lines = r.findings.map(
    (f) => `${f.severity.toUpperCase().padEnd(8)} ${`(${f.confidence})`.padEnd(9)} ${f.ruleId.padEnd(22)} ${f.file}:${f.line}  ${f.message}`,
  );
  const c = r.counts;
  const hi = r.findings.filter((f) => f.confidence === "high").length;
  lines.push("", `critical=${c.critical} high=${c.high} medium=${c.medium} review=${c.review} low=${c.low}  |  high-confidence=${hi}`);
  return lines.join("\n");
}

/** Stable machine-readable report for agents/CI. */
export function toJSON(r: ScanResult): string {
  return JSON.stringify({ findings: r.findings, counts: r.counts }, null, 2);
}
