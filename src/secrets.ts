import { type SourceFile, type Finding, type Severity } from "./types";
import { locate, lineAt } from "./walk";

interface TokenRule { id: string; severity: Severity; re: RegExp; message: string; remediation: string; }

const TOKENS: TokenRule[] = [
  { id: "VC-SECRET-PRIVATE-KEY", severity: "critical", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, message: "private key committed in source", remediation: "Remove it, rotate the key, and load keys from a secret manager at runtime." },
  { id: "VC-SECRET-AWS-KEY", severity: "critical", re: /\bAKIA[0-9A-Z]{16}\b/g, message: "AWS access key id committed", remediation: "Rotate the AWS key now; use IAM roles or env vars, never hardcode." },
  { id: "VC-SECRET-GITHUB", severity: "critical", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, message: "GitHub token committed", remediation: "Revoke the token in GitHub settings; store tokens in CI secrets." },
  { id: "VC-SECRET-OPENAI", severity: "critical", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, message: "OpenAI-style secret key committed", remediation: "Rotate the key and read it from process.env at runtime." },
  { id: "VC-SECRET-STRIPE", severity: "critical", re: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/g, message: "Stripe live secret key committed", remediation: "Roll the key in Stripe; never expose live keys client-side." },
  { id: "VC-SECRET-GOOGLE", severity: "high", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, message: "Google API key committed", remediation: "Restrict and rotate the key in Google Cloud console." },
  { id: "VC-SECRET-SLACK", severity: "high", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, message: "Slack token committed", remediation: "Revoke the Slack token; store it in secrets." },
];

const SECRET_KEY = /(?:secret|token|api[_-]?key|apikey|access[_-]?key|password|passwd|pwd|client[_-]?secret|private[_-]?key|auth[_-]?token|credential)/i;
const ASSIGN = /(["']?)([A-Za-z_][\w.-]*)\1\s*[:=]\s*(["'])([^"'\n]{12,})\3/g;
const PLACEHOLDER = /^(?:x{3,}|0{3,}|a{3,})$|x{4,}|example|your[_-]|placeholder|changeme|redacted|dummy|sample|<[^>]+>|\$\{|process\.env|import\.meta/i;

function shannon(s: string): number {
  const m = new Map<string, number>();
  for (const c of s) m.set(c, (m.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of m.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function looksLikeSecretValue(v: string): boolean {
  if (v.includes(" ")) return false;
  if (PLACEHOLDER.test(v)) return false;
  if (/^https?:\/\//.test(v)) return false;
  if (new Set(v).size <= 4) return false; // e.g. "aaaaaaaaaaaa"
  return shannon(v) >= 3.5;
}

function isToken(v: string): boolean {
  return TOKENS.some((t) => { t.re.lastIndex = 0; return t.re.test(v); });
}

/** Detect committed credentials: known token formats + high-entropy secret-named assignments. */
export function secretFindings(files: SourceFile[]): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  const push = (f: Finding) => {
    const k = `${f.file}:${f.line}:${f.ruleId}`;
    if (!seen.has(k)) { seen.add(k); out.push(f); }
  };
  for (const file of files) {
    for (const rule of TOKENS) {
      rule.re.lastIndex = 0;
      for (const m of file.content.matchAll(rule.re)) {
        if (/XXXX|EXAMPLE|REDACTED/i.test(m[0])) continue;
        const { line, col } = locate(file.content, m.index);
        push({ ruleId: rule.id, severity: rule.severity, file: file.rel, line, col, message: rule.message, snippet: lineAt(file.content, m.index), remediation: rule.remediation });
      }
    }
    ASSIGN.lastIndex = 0;
    for (const m of file.content.matchAll(ASSIGN)) {
      const name = m[2] as string;
      const value = m[4] as string;
      if (!SECRET_KEY.test(name) || isToken(value) || !looksLikeSecretValue(value)) continue;
      const { line, col } = locate(file.content, m.index);
      push({ ruleId: "VC-SECRET-HIGH-ENTROPY", severity: "high", file: file.rel, line, col, message: `hardcoded secret-looking value assigned to "${name}"`, snippet: lineAt(file.content, m.index), remediation: "Move the value to an env var / secret manager and reference it at runtime." });
    }
  }
  return out;
}
