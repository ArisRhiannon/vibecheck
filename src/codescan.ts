import { type SourceFile, type Finding, type Severity } from "./types";
import { locate, lineAt } from "./walk";

const JS = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/;

function mk(file: SourceFile, index: number, ruleId: string, severity: Severity, message: string, remediation: string): Finding {
  const { line, col } = locate(file.content, index);
  return { ruleId, severity, file: file.rel, line, col, message, snippet: lineAt(file.content, index), remediation };
}

/** Is the first call argument starting at `openParen` a single plain string literal (e.g. "ls -la")? */
function firstArgIsLiteral(s: string, openParen: number): boolean {
  let i = openParen + 1;
  while (i < s.length && /\s/.test(s[i] as string)) i++;
  const q = s[i];
  if (q !== '"' && q !== "'") return false; // identifier / template / concat ⇒ non-literal
  i++;
  while (i < s.length) {
    const c = s[i] as string;
    if (c === "\\") { i += 2; continue; }
    if (c === q) { i++; break; }
    if (c === "\n") return false;
    i++;
  }
  while (i < s.length && /\s/.test(s[i] as string)) i++;
  return s[i] === ")";
}

function rce(f: SourceFile): Finding[] {
  const out: Finding[] = [], c = f.content;
  for (const m of c.matchAll(/\b(?:eval|new\s+Function)\s*\(/g)) {
    const idx = m.index ?? 0;
    if (firstArgIsLiteral(c, idx + m[0].length - 1)) continue;
    out.push(mk(f, idx, "VC-RCE-EVAL", "critical", "eval()/new Function() on a non-literal value (remote code execution)", "Never eval dynamic input; use JSON.parse or an explicit dispatch table."));
  }
  for (const m of c.matchAll(/\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(/g)) {
    const idx = m.index ?? 0;
    if (firstArgIsLiteral(c, idx + m[0].length - 1)) continue;
    out.push(mk(f, idx, "VC-RCE-CHILD-PROCESS", "high", "child_process call with a non-literal command (command injection)", "Pass a fixed program + args array to execFile; validate/escape any input."));
  }
  return out;
}

function sqli(f: SourceFile): Finding[] {
  const out: Finding[] = [], c = f.content;
  for (const m of c.matchAll(/\.\s*(?:query|execute|raw|unsafe)\s*\(\s*`([^`]*)`/g)) {
    const body = m[1] ?? "";
    if (/\$\{/.test(body) && /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|FROM|WHERE)\b/i.test(body)) {
      out.push(mk(f, m.index ?? 0, "VC-SQLI-TEMPLATE", "high", "SQL built via string interpolation (SQL injection)", "Use parameterized queries / placeholders ($1, ?) — never interpolate values into SQL."));
    }
  }
  for (const m of c.matchAll(/["'][^"'\n]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'\n]*["']\s*\+\s*[A-Za-z_$]/gi)) {
    out.push(mk(f, m.index ?? 0, "VC-SQLI-CONCAT", "high", "SQL built via string concatenation (SQL injection)", "Use parameterized queries instead of concatenating values into SQL."));
  }
  return out;
}

function cors(f: SourceFile): Finding[] {
  const out: Finding[] = [], c = f.content;
  const creds = /credentials\s*:\s*true/.test(c);
  const sev: Severity = creds ? "high" : "medium";
  for (const m of c.matchAll(/origin\s*:\s*['"]\*['"]/g)) out.push(mk(f, m.index ?? 0, "VC-CORS-WILDCARD", sev, `CORS allows any origin ('*')${creds ? " with credentials" : ""}`, "Restrict origin to an explicit allowlist; never combine '*' with credentials."));
  for (const m of c.matchAll(/Access-Control-Allow-Origin['"]\s*,\s*['"]\*/g)) out.push(mk(f, m.index ?? 0, "VC-CORS-WILDCARD", sev, "Access-Control-Allow-Origin set to '*'", "Restrict to an explicit allowlist of trusted origins."));
  return out;
}

function jwt(f: SourceFile): Finding[] {
  const out: Finding[] = [], c = f.content;
  for (const m of c.matchAll(/algorithms?\s*:\s*\[[^\]]*['"]none['"]/gi)) out.push(mk(f, m.index ?? 0, "VC-JWT-NONE", "critical", "JWT 'none' algorithm permitted (signature bypass)", "Pin a strong algorithm (e.g. ['HS256'] or ['RS256']) and reject 'none'."));
  for (const m of c.matchAll(/\bjwt\s*\.\s*verify\s*\(/g)) {
    const idx = m.index ?? 0;
    if (!/algorithms\s*:/.test(c.slice(idx, idx + 250))) out.push(mk(f, idx, "VC-JWT-UNPINNED", "high", "jwt.verify() without pinning algorithms (algorithm confusion)", "Pass { algorithms: ['HS256'] } so an attacker can't downgrade to 'none'/RS↔HS."));
  }
  return out;
}

function cookies(f: SourceFile): Finding[] {
  const out: Finding[] = [], c = f.content;
  for (const m of c.matchAll(/\.\s*cookie\s*\(\s*['"]([^'"]*(?:sess|token|auth|sid|jwt)[^'"]*)['"]/gi)) {
    const idx = m.index ?? 0, seg = c.slice(idx, idx + 300);
    if (!/httpOnly\s*:\s*true/i.test(seg) || !/secure\s*:\s*true/i.test(seg)) {
      out.push(mk(f, idx, "VC-COOKIE-INSECURE", "high", `auth/session cookie "${m[1]}" set without httpOnly + secure`, "Set { httpOnly: true, secure: true, sameSite: 'lax' } on session/auth cookies."));
    }
  }
  return out;
}

/** Run the set-1 code-pattern detectors over JS/TS source files. */
export function codeFindings(files: SourceFile[]): Finding[] {
  const out: Finding[] = [];
  for (const f of files) {
    if (!JS.test(f.rel)) continue;
    out.push(...rce(f), ...sqli(f), ...cors(f), ...jwt(f), ...cookies(f));
  }
  return out;
}
