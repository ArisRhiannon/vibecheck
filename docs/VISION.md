# Vision — vibecheck

Role: CEO. Author: Aris Rhiannon. Status: accepted.

## One-liner
`vibecheck` — a zero-dependency, **offline, no-AI** "is this safe to ship?" gate for vibe-coded apps.
It finds the *specific* mistakes AI coding agents make (unprotected routes, committed secrets, eval-RCE,
permissive CORS, weak JWT, missing input validation, leaky config) and is built so the **agent runs it
as its own verification step** before saying "done". Run `vibecheck .` — human report, `--json` for
machines, `--ci` exit codes for pipelines.

## Honesty contract (non-negotiable)
- **Every rule in the README is actually implemented and proven by tests** with BOTH a vulnerable
  fixture (it fires) and a safe fixture (it stays quiet). No stubs, no "glorified JSON", no claimed-but-
  unbuilt features.
- Detectors are **heuristic / framework-aware**, not a full taint engine. We say so plainly and assign
  honest severities (`review`-grade findings are flagged as such, not as proven exploits).
- No network, no telemetry, no AI, no code execution of the target project.

## Why
Escape.tech scanned 5,600 deployed vibe-coded apps: ~1 in 3 shipped a serious flaw; 400+ exposed
secrets. Generic SAST/secret tools miss the AI-specific failure shapes. Agents lack a deterministic
"definition of done" security check. vibecheck is that check, and it is **agent-discoverable** (ships
`AGENTS.md`, `llms.txt`, `--json`, and a real MCP server).

## Success criteria (v1.0) — each backed by passing tests
- SC1: Project walk skips `node_modules/.git/dist/build/coverage` and respects root `.gitignore`
  globs; returns source/config files with content + a `line/col` locator. (test)
- SC2: **Secrets** — detects AWS keys, `ghp_`/GitHub tokens, OpenAI `sk-`, Stripe `sk_live`, Google API
  keys, Slack tokens, PEM private keys, and high-entropy assignments; flags a committed `.env` (present
  & not gitignored) and `.env`↔`.env.example` key drift. Safe fixtures (placeholders, `process.env.X`)
  do NOT fire. (test, both directions)
- SC3: **RCE** — flags `eval`/`new Function`/`child_process.exec(Sync)` whose argument is non-literal
  (interpolated/concatenated/user input); a literal-string `exec("ls")` does not fire. (test)
- SC4: **Injection** — flags SQL built by string concatenation/template containing `req.`/user input;
  a parameterized query (`$1`, `?`) does not fire. (test)
- SC5: **CORS/JWT/cookies** — flags `origin:"*"` (esp. with credentials) and reflected-origin+credentials;
  JWT `algorithms:["none"]` / verify without pinned algorithm; auth/session cookie without
  `httpOnly`+`secure`. Hardened versions do not fire. (test)
- SC6: **Routes/validation/config** — flags Express & Next route handlers with no auth/authorization
  reference (severity `review`); handlers reading `req.body`/`await req.json()` with no validator import
  (`zod`/`joi`/`yup`/`valibot`) (advisory); `NEXT_PUBLIC_`-exposed secret-looking vars; a Supabase
  `service_role` key used in client code; stack-trace/`debug:true` exposure. Safe versions clean. (test)
- SC7: CLI `scan`/`--json`/`--ci`/`--explain <rule>` + `.vibecheck.json` (ignoreRules, allowPaths,
  failSeverity); `--ci` exits non-zero iff a finding ≥ failSeverity (default `high`); clean project exits
  0. End-to-end tests on a full vulnerable fixture app and a clean app. (test)
- SC8: A **real MCP stdio server** exposing a `scan` tool (handles `initialize`, `tools/list`,
  `tools/call`), proven by spawning it and asserting the JSON-RPC responses; ships `AGENTS.md` +
  `llms.txt`; README rule table == implemented rules; ≥2 ADRs; zero deps; `tsc` strict clean; CI green.

## Scope (v1)
JS/TS/JSX/TSX projects (Express/Fastify/Next app-router + env/Supabase). Heuristic + light structural
matching over source. CLI + library + MCP server + agent docs.

## Non-goals (v1)
Full multi-language taint analysis; Python/Go/Ruby detectors; autofix; runtime/DAST; any AI; any network.

## Definition of done
SC1–SC8 met & independently validated (VALIDATION.md), QA addressed, pushed to GitHub under ArisRhiannon
(AGPL-3.0 + commercial), CI green, with incremental human commits.
