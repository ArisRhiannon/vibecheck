import { type SourceFile, type Finding, type Severity } from "./types";
import { locate, lineAt } from "./walk";

const JS = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/;
const AUTH = /req\.user|require[_]?auth|isauthenticated|authenticate|authoriz|ensureauth|getserversession|getsession|\bgetuser\b|verifytoken|jwt\s*\.\s*verify|passport|withauth|clerk|currentuser|\bprotect\b|requirelogin|checkauth/i;
const VALIDATOR = /(?:from|require\s*\(?)\s*['"](?:zod|joi|yup|valibot|class-validator|@hapi\/joi|superstruct|ajv|@sinclair\/typebox)['"]/;

function mk(f: SourceFile, index: number, ruleId: string, severity: Severity, message: string, remediation: string): Finding {
  const { line, col } = locate(f.content, index);
  return { ruleId, severity, file: f.rel, line, col, message, snippet: lineAt(f.content, index), remediation };
}

/** Set-2 detectors: route auth, input validation, leaky config. */
export function routeFindings(files: SourceFile[]): Finding[] {
  const out: Finding[] = [];
  for (const f of files) {
    if (!JS.test(f.rel)) continue;
    const c = f.content;

    // Express route handlers without a visible auth check (review-grade: may be a public route)
    for (const m of c.matchAll(/\b(?:app|router|fastify|server)\s*\.\s*(?:get|post|put|delete|patch|all)\s*\(/gi)) {
      const idx = m.index ?? 0;
      if (!AUTH.test(c.slice(idx, idx + 500))) out.push(mk(f, idx, "VC-ROUTE-NO-AUTH", "review", "route handler with no visible authentication/authorization check", "Confirm this endpoint is meant to be public; otherwise add an auth middleware / session check."));
    }
    // Next.js app-router handlers without auth
    if (/(?:^|\/)route\.(?:t|j)sx?$/.test(f.rel)) {
      for (const m of c.matchAll(/export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(/g)) {
        const idx = m.index ?? 0;
        if (!AUTH.test(c.slice(idx, idx + 600))) out.push(mk(f, idx, "VC-ROUTE-NO-AUTH", "review", `Next.js ${m[1]} handler with no visible auth/session check`, "Verify this route is public; otherwise gate it with getServerSession()/auth()/middleware."));
      }
    }
    // Reads request input but imports no schema validator
    const read = c.search(/req\.(?:body|query|params)\b|await\s+req\.json\s*\(\s*\)/);
    if (read >= 0 && !VALIDATOR.test(c)) out.push(mk(f, read, "VC-INPUT-NO-VALIDATION", "medium", "request input is read without a schema validator imported (zod/joi/yup/valibot/…)", "Parse and validate req body/query/params with a schema before use."));

    // NEXT_PUBLIC_* holding a secret-looking name (bundled into client JS)
    for (const m of c.matchAll(/NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|PRIVATE|PASSWORD|TOKEN|API_KEY)/g)) {
      if (/PUBLISHABLE|ANON|PUBLIC_KEY/.test(m[0])) continue;
      out.push(mk(f, m.index ?? 0, "VC-NEXT-PUBLIC-SECRET", "high", `${m[0]} is exposed to the browser (every NEXT_PUBLIC_* var is bundled into client JS)`, "Drop the NEXT_PUBLIC_ prefix and read the secret only on the server."));
    }
    // Supabase service_role key (must never reach the client)
    const idx = c.search(/service_role/i);
    if (idx >= 0) {
      const client = /['"]use client['"]/.test(c);
      out.push(mk(f, idx, "VC-SUPABASE-SERVICE-ROLE", client ? "critical" : "high", `Supabase service_role key referenced${client ? " in a client component" : ""} — it bypasses Row-Level Security`, "Use the anon key on the client; keep service_role strictly server-side in env."));
    }
    // Error stack returned to the client
    for (const m of c.matchAll(/res\s*\.\s*(?:send|json|end)\s*\([^)\n]*\.stack\b/g)) out.push(mk(f, m.index ?? 0, "VC-STACK-EXPOSURE", "medium", "error stack trace sent in the HTTP response", "Log the stack server-side; return a generic error message to clients."));
  }
  return out;
}
