# vibecheck

[![ci](https://github.com/ArisRhiannon/vibecheck/actions/workflows/ci.yml/badge.svg)](https://github.com/ArisRhiannon/vibecheck/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**An offline, zero-dependency, no-AI "safe to ship?" gate for vibe-coded apps.** It finds the exact
mistakes AI coding agents make — committed secrets, unprotected routes, `eval`-RCE, SQL injection,
permissive CORS, weak JWT, insecure cookies, leaked `NEXT_PUBLIC`/Supabase keys, missing input
validation — and is built so **the agent runs it as its own verification step** before saying "done".

No network. No telemetry. No AI. It only reads your files.

```sh
vibecheck .          # human report
vibecheck . --ci     # exit 1 if anything >= high — drop into CI / agent loops
vibecheck . --json   # machine-readable findings
```

## Why

Researchers scanned 5,600 deployed vibe-coded apps and found ~1 in 3 shipped a serious flaw and 400+
exposed secrets. Generic SAST/secret scanners miss the *shapes* AI tends to introduce, and agents lack a
deterministic "definition of done" check. vibecheck is that check — and it's agent-discoverable
(`AGENTS.md`, `llms.txt`, `--json`, and a real MCP server).

## Install

```sh
bun add -d vibecheck    # or: npm i -D vibecheck   (Node >= 20)
```

## Use it as a human

```sh
vibecheck src/              # scan a directory
vibecheck . --ci            # CI gate (exit 1 on >= failSeverity)
vibecheck explain VC-JWT-UNPINNED
```

## Use it as / with an AI agent

- Tell your agent (see `AGENTS.md`): *run `vibecheck . --ci` before declaring done; fix all critical/high.*
- Parse `vibecheck . --json` → `{ findings: [{ ruleId, severity, file, line, message, remediation }], counts }`.
- MCP: run `vibecheck mcp` (stdio JSON-RPC) and call the `scan` tool with `{ "dir": "." }`.

## Rules (exactly what is implemented and tested)

| id | sev | what it catches |
|----|-----|-----------------|
| VC-SECRET-PRIVATE-KEY | critical | committed PEM private key |
| VC-SECRET-AWS-KEY | critical | AWS access key id (AKIA…) |
| VC-SECRET-GITHUB | critical | GitHub token (ghp_/github_pat_) |
| VC-SECRET-OPENAI | critical | OpenAI key (sk-…) |
| VC-SECRET-STRIPE | critical | Stripe live key (sk_live/rk_live) |
| VC-SECRET-GOOGLE | high | Google API key (AIza…) |
| VC-SECRET-SLACK | high | Slack token (xox…) |
| VC-SECRET-HIGH-ENTROPY | high | high-entropy value on a secret-named var |
| VC-ENV-COMMITTED | high | `.env` not gitignored (secrets likely committed) |
| VC-ENV-DRIFT / VC-ENV-MISSING | low/med | `.env` ↔ `.env.example` key drift |
| VC-RCE-EVAL | critical | `eval`/`new Function` on a non-literal value |
| VC-RCE-CHILD-PROCESS | high | `child_process` on a non-literal command |
| VC-SQLI-TEMPLATE / VC-SQLI-CONCAT | high | SQL built by interpolation / concatenation |
| VC-CORS-WILDCARD | med/high | `origin: '*'` (high with credentials) |
| VC-JWT-NONE | critical | JWT `none` algorithm allowed |
| VC-JWT-UNPINNED | high | `jwt.verify` without pinned algorithms |
| VC-COOKIE-INSECURE | high | auth/session cookie without httpOnly+secure |
| VC-ROUTE-NO-AUTH | review | Express/Next route handler with no visible auth |
| VC-INPUT-NO-VALIDATION | medium | request input read with no schema validator imported |
| VC-NEXT-PUBLIC-SECRET | high | secret in a `NEXT_PUBLIC_*` var (bundled to client) |
| VC-SUPABASE-SERVICE-ROLE | high/crit | Supabase `service_role` key referenced (crit in client) |
| VC-STACK-EXPOSURE | medium | error stack returned in an HTTP response |

`vibecheck explain <id>` prints the fix for any rule.

## Config — `.vibecheck.json`

```json
{
  "ignoreRules": ["VC-INPUT-NO-VALIDATION"],
  "allowPaths": ["test/**", "examples/**"],
  "failSeverity": "high"
}
```

## Threat model & honesty

vibecheck uses **heuristics and light structural matching**, not a full taint engine. It targets the
common, high-frequency mistakes in AI-generated JS/TS apps (Express/Fastify/Next + env/Supabase). It is
a **high-signal gate and early-warning, not a proof of security** — expect some false positives
(tune via `.vibecheck.json`) and false negatives (deep/obfuscated bugs). `review`-severity findings are
*possible* issues for a human/agent to confirm. It performs no network calls, no telemetry, and never
executes your code.

## Status & scope (v1)

JS/TS/JSX/TSX. CLI + library + MCP server + agent docs. **Roadmap:** Python/Go detectors, more
frameworks, autofix suggestions. Decisions in `docs/adr/`; acceptance criteria in `docs/PLAN.md`;
independent validation in `VALIDATION.md`.

## License

MIT © 2026 Aris Rhiannon — see [LICENSE](LICENSE).
