# Plan — vibecheck (phased, gated, honest)

Role: PM. Author: Aris Rhiannon. `create-issue-gate` contract: ACs are testable/pass-fail. Each rule
ships with a **vulnerable fixture (must fire)** and a **safe fixture (must stay quiet)**. TDD,
**incremental human commits**. Stack: TypeScript (strict), Bun, zero runtime deps, AGPL+commercial.

## Phase 0 — Scaffold
AC0.1 `bun test` runs ≥1 test, exit 0. AC0.2 `tsc --noEmit` strict clean. AC0.3 `dependencies` empty;
`license`="SEE LICENSE IN LICENSE". AC0.4 CI runs install+typecheck+test.

## Phase 1 — Walk + file model + types
AC1.1 walk skips node_modules/.git/dist/build/coverage and honors root `.gitignore` simple globs.
AC1.2 returns files with path, content, and a `locate(index)→{line,col}` helper (1-based). 
AC1.3 Finding has `{ruleId, severity, file, line, message, snippet}`; severities `critical|high|medium|low|review`.
AC1.4 binary/huge files skipped safely; missing dir → typed error.

## Phase 2 — Secrets + env
AC2.1 detects ≥7 known token formats (AWS, GitHub `ghp_`, OpenAI `sk-`, Stripe `sk_live`, Google
`AIza`, Slack `xox`, PEM private key). AC2.2 flags high-entropy string assignments (Shannon ≥ ~3.5,
len ≥ 12) but NOT obvious placeholders (`xxxx`, `your-…`, `process.env.*`, example values). AC2.3 flags
`.env` that is tracked and not gitignored. AC2.4 flags keys present in `.env` but missing from
`.env.example` (and vice-versa). AC2.5 safe fixtures (placeholders, env refs) produce no findings.

## Phase 3 — Code patterns set 1
AC3.1 RCE: `eval(x)`, `new Function(x)`, `child_process.exec(x)`/`execSync` with **non-literal** arg ⇒
finding; literal `exec("ls -la")` ⇒ none. AC3.2 Injection: query string built with template/`+` that
includes `req.`/interpolated user input ⇒ high; parameterized (`$1`/`?` placeholders) ⇒ none.
AC3.3 CORS: `origin:"*"` ⇒ finding; with `credentials:true` ⇒ high; locked-down origin ⇒ none.
AC3.4 JWT: `algorithms:["none"]` or `jwt.verify` without `algorithms` ⇒ finding; pinned ⇒ none.
AC3.5 Cookies: `res.cookie(...)`/`Set-Cookie` for auth/session without `httpOnly`+`secure` ⇒ finding.

## Phase 4 — Code patterns set 2 (routes/validation/config)
AC4.1 Express (`app.get/post/...`, `router.*`) & Next app-router (`export async function GET/POST...`)
handlers with no auth/authorization reference in scope ⇒ `review` finding; handlers that call an
auth/`requireAuth`/`getServerSession`/middleware ⇒ none. AC4.2 handler reads `req.body`/`req.query`/
`await req.json()` with no validator import (`zod|joi|yup|valibot|class-validator`) ⇒ advisory.
AC4.3 `NEXT_PUBLIC_…` assigned a secret-looking value/name (`SECRET|KEY|TOKEN|PASSWORD`) ⇒ high.
AC4.4 Supabase `service_role` key string in client-tagged code ⇒ critical. AC4.5 `debug:true` /
stack-trace exposure (`res.send(err.stack)`) ⇒ medium. Safe variants ⇒ none.

## Phase 5 — Config + report + CLI (end-to-end)
AC5.1 `.vibecheck.json` (ignoreRules, allowPaths globs, failSeverity) honored. AC5.2 `scan [dir]` prints
findings grouped by severity with `file:line` + remediation; `--json` emits stable schema. AC5.3 `--ci`
exits non-zero iff any finding ≥ failSeverity (default `high`); clean app ⇒ exit 0. AC5.4 `--explain
<ruleId>` prints rule description + why + fix. AC5.5 end-to-end: a bundled **vulnerable fixture app**
trips the expected rule set; a **clean fixture app** yields zero findings ≥ medium.

## Phase 6 — MCP server + agent surface + docs
AC6.1 a real **MCP stdio JSON-RPC server** answers `initialize`, `tools/list` (advertises `scan`), and
`tools/call name=scan` returning findings JSON — verified by spawning the process and writing/reading
JSON-RPC. AC6.2 ships `AGENTS.md` (tells agents to run `vibecheck . --ci` before "done") and `llms.txt`.
AC6.3 README rule table lists **exactly** the implemented rules with honest limits; ≥2 ADRs. AC6.4
zero deps; `tsc` strict clean; `bun test` green; CI green.

## Role mapping
CEO/PM/Dev/Tester: me (incremental human commits). QA: code-reviewer subagent (verify NO stubs; real
detection; ReDoS-safe regexes; FP/FN behavior). Validator: independent subagent → VALIDATION.md.
