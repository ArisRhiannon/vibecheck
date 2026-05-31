import { type SourceFile, type Finding } from "./types";

const JS = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/;

function lineOf(content: string, index: number): { line: number; snippet: string } {
  const line = content.slice(0, index).split("\n").length;
  const snippet = (content.split("\n")[line - 1] ?? "").trim();
  return { line, snippet };
}

/** String-level config rules where AST adds no value (env var names, key references). */
export function miscFindings(files: SourceFile[]): Finding[] {
  const out: Finding[] = [];
  for (const f of files) {
    if (!JS.test(f.rel)) continue;
    const c = f.content;
    for (const m of c.matchAll(/NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|PRIVATE|PASSWORD|TOKEN|API_KEY)/g)) {
      if (/PUBLISHABLE|ANON|PUBLIC_KEY/.test(m[0])) continue;
      const { line, snippet } = lineOf(c, m.index ?? 0);
      out.push({ ruleId: "VC-NEXT-PUBLIC-SECRET", severity: "high", confidence: "high", file: f.rel, line, col: 1, message: `${m[0]} is exposed to the browser (every NEXT_PUBLIC_* var is bundled into client JS)`, snippet, remediation: "Drop the NEXT_PUBLIC_ prefix and read the secret only on the server." });
    }
    const useClient = /['"]use client['"]/.test(c);
    for (const m of c.matchAll(/service_role/gi)) {
      const { line, snippet } = lineOf(c, m.index ?? 0);
      if (/^\s*(?:\/\/|\*|\/\*)/.test(snippet)) continue; // comment mention
      out.push({ ruleId: "VC-SUPABASE-SERVICE-ROLE", severity: useClient ? "critical" : "high", confidence: "high", file: f.rel, line, col: 1, message: `Supabase service_role key referenced${useClient ? " in a client component" : ""} — it bypasses Row-Level Security`, snippet, remediation: "Use the anon key on the client; keep service_role strictly server-side." });
      break;
    }
  }
  return out;
}
