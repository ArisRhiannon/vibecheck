import { writeFileSync } from "node:fs";
import { CORPUS, type Case } from "./corpus";
import { astFindings, miscFindings, pythonFindings, interprocFindings, goFindings, type SourceFile } from "../src/index";

const ADVISORY = new Set(["VC-ROUTE-NO-AUTH", "VC-INPUT-NO-VALIDATION"]);

function emittedIds(c: Case): Set<string> {
  const f: SourceFile = { path: c.rel, rel: c.rel, content: c.code };
  const found = [...astFindings([f]), ...miscFindings([f]), ...pythonFindings([f]), ...interprocFindings([f]), ...goFindings([f])];
  return new Set(found.filter((x) => x.confidence !== "review" && !ADVISORY.has(x.ruleId)).map((x) => x.ruleId));
}

type Cell = { tp: number; fp: number; fn: number };
export interface Metrics {
  tp: number; fp: number; fn: number; precision: number; recall: number; f1: number; total: number;
  perRule: Record<string, Cell>;
  failures: { name: string; expected: string[]; emitted: string[] }[];
}

export function runBenchmark(): Metrics {
  let tp = 0, fp = 0, fn = 0;
  const per: Record<string, Cell> = {};
  const failures: Metrics["failures"] = [];
  const bump = (id: string, k: keyof Cell) => { (per[id] ??= { tp: 0, fp: 0, fn: 0 })[k]++; };
  for (const c of CORPUS) {
    const emitted = emittedIds(c);
    const expected = new Set(c.expect);
    let ok = true;
    for (const id of expected) { if (emitted.has(id)) { tp++; bump(id, "tp"); } else { fn++; bump(id, "fn"); ok = false; } }
    for (const id of emitted) { if (!expected.has(id)) { fp++; bump(id, "fp"); ok = false; } }
    if (!ok) failures.push({ name: c.name, expected: [...expected], emitted: [...emitted] });
  }
  const precision = tp / ((tp + fp) || 1);
  const recall = tp / ((tp + fn) || 1);
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return { tp, fp, fn, precision, recall, f1, total: CORPUS.length, perRule: per, failures };
}

const pct = (x: number) => `${(x * 100).toFixed(1)}%`;

export function metricsMarkdown(m: Metrics): string {
  const rows = Object.keys(m.perRule).sort().map((id) => { const r = m.perRule[id] as Cell; return `| ${id} | ${r.tp} | ${r.fp} | ${r.fn} |`; });
  return [
    "# Benchmark metrics",
    "",
    `Corpus: **${m.total}** labeled cases (vulnerable + safe + tricky-safe). Advisory rules`,
    "(`VC-ROUTE-NO-AUTH`, `VC-INPUT-NO-VALIDATION`) and `review`-confidence findings are excluded",
    "from these core numbers by design (they are advisory, not assertions). Re-run: `bun benchmark/run.ts`.",
    "",
    `- **Precision: ${pct(m.precision)}** (TP ${m.tp} / FP ${m.fp})`,
    `- **Recall: ${pct(m.recall)}** (TP ${m.tp} / FN ${m.fn})`,
    `- **F1: ${pct(m.f1)}**`,
    "",
    "| rule | TP | FP | FN |",
    "|------|----|----|----|",
    ...rows,
    "",
    m.failures.length ? `## Cases not matching labels\n${m.failures.map((f) => `- ${f.name}: expected [${f.expected}] got [${f.emitted}]`).join("\n")}` : "All cases match their labels.",
    "",
  ].join("\n");
}

if (import.meta.main) {
  const m = runBenchmark();
  writeFileSync(new URL("../METRICS.md", import.meta.url), metricsMarkdown(m));
  console.log(metricsMarkdown(m));
}
