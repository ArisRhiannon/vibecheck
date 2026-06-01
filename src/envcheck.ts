import { type SourceFile, type Finding } from "./types";

const EXAMPLE = /\.env\.(?:example|sample|template|dist)$/i;
const base = (rel: string): string => rel.split("/").pop() ?? rel;
const isEnv = (rel: string): boolean => { const b = base(rel); return b === ".env" || /^\.env(\.|$)/.test(b); };
const isExample = (rel: string): boolean => EXAMPLE.test(base(rel));

function envKeys(content: string): Set<string> {
  const ks = new Set<string>();
  for (const line of content.split("\n")) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/);
    if (m) ks.add(m[1] as string);
  }
  return ks;
}

/** Detect a committed .env (collected ⇒ not gitignored) and .env↔.env.example key drift. */
export function envFindings(files: SourceFile[]): Finding[] {
  const out: Finding[] = [];
  for (const f of files) {
    if (isEnv(f.rel) && !isExample(f.rel)) {
      out.push({ ruleId: "VC-ENV-COMMITTED", severity: "high", confidence: "high", file: f.rel, line: 1, col: 1, message: `${base(f.rel)} is not gitignored — secrets in it are likely committed`, snippet: base(f.rel), remediation: "Add .env to .gitignore, purge it from git history, and rotate any secret it held." });
    }
  }
  const dirOf = (rel: string): string => (rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "");
  const examples = files.filter((f) => isExample(f.rel));
  for (const real of files.filter((f) => isEnv(f.rel) && !isExample(f.rel))) {
    const example = examples.find((e) => dirOf(e.rel) === dirOf(real.rel));
    if (!example) continue;
    const rk = envKeys(real.content), ek = envKeys(example.content);
    const undocumented = [...rk].filter((k) => !ek.has(k));
    const missing = [...ek].filter((k) => !rk.has(k));
    if (undocumented.length) out.push({ ruleId: "VC-ENV-DRIFT", severity: "low", confidence: "high", file: example.rel, line: 1, col: 1, message: `vars in ${base(real.rel)} not documented in ${base(example.rel)}: ${undocumented.join(", ")}`, snippet: "", remediation: "List every variable (keys only, no values) in .env.example so deploys don't miss config." });
    if (missing.length) out.push({ ruleId: "VC-ENV-MISSING", severity: "medium", confidence: "high", file: real.rel, line: 1, col: 1, message: `vars documented in ${base(example.rel)} but missing from ${base(real.rel)}: ${missing.join(", ")}`, snippet: "", remediation: "Set the missing variables before running or deploying." });
  }
  return out;
}
