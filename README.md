# vibecheck

[![ci](https://github.com/ArisRhiannon/vibecheck/actions/workflows/ci.yml/badge.svg)](https://github.com/ArisRhiannon/vibecheck/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A fast, **agent-native** "safe to ship?" gate for vibe-coded apps. It parses your **JS/TS/JSX/TSX**
(`@babel/parser`) and **Python** (the stdlib `ast`) with **real parsers** and uses **intra-procedural
taint analysis** to flag the security classes AI coding agents get wrong — committed secrets, SQL
injection through *abstracted* raw-query APIs, XSS, SSRF, path traversal, command injection, insecure
deserialization, weak JWT/CORS/cookies — and ranks every finding by **confidence** so an agent can fix
the real ones and ignore the noise.

```sh
vibecheck .          # human report (severity + confidence)
vibecheck . --ci     # exit 1 only on high-confidence (taint-backed) issues
vibecheck . --json   # machine-readable findings for agents / CI
```

## What it is — and what it is not (read this)

vibecheck is **not** a replacement for [Semgrep](https://semgrep.dev) or
[CodeQL](https://codeql.github.com). Those are deeper, broader, multi-language engines and you should
run them for full coverage. vibecheck aims to be **better on one narrow, measurable axis**: a
**low-false-positive, taint-backed gate for the AI-vibe-coding failure classes that runs inside agent
loops and pre-commit in milliseconds**, with **published precision/recall** so you can trust the
`--ci`/MCP signal. Use it *alongside* the big engines, not instead of them.

| | vibecheck | Semgrep | CodeQL |
|--|--|--|--|
| Parsing | real AST (Babel JS/TS/JSX + Python `ast`) | real, many langs | real, many langs |
| Data-flow | intra-procedural taint | taint (Pro) | full inter-procedural |
| Languages (v0.2) | **JS/TS/JSX/TSX + Python** | many | many |
| Speed / infra | ms, local, no account | fast | slower, CI-oriented |
| Agent-native (MCP, confidence gating) | **yes, first-class** | partial | no |
| Breadth of rules | small, focused | 2000+ | huge |

If you only adopt one general SAST, adopt Semgrep or CodeQL. Adopt vibecheck as the **fast agent/CI
pre-flight** that won't drown an agent in false positives.

## Measured quality (not claimed)

Against a labeled benchmark of **60 cases** across JS/TS **and** Python (vulnerable + safe + deliberately
tricky-safe), the core detectors score (see [`METRICS.md`](METRICS.md), reproduce with `bun benchmark/run.ts`):

- **Precision 100%**, **Recall 100%**, **F1 100%** on the corpus.

The tricky-safe cases that produce **zero false positives** include: parameterized queries, tagged-
template SQL, numeric-coerced and schema-validated input, ORM/RegExp `.exec()`, Supabase **anon** /
Stripe **publishable** keys, hardened cookies, allow-listed CORS, and pinned JWT algorithms — exactly
the patterns a regex linter trips on. This benchmark is curated (not "scanned N real repos"); a
real-world corpus is on the roadmap.

## Confidence (the anti-false-positive-loop design)

Every finding has a **confidence**:
- `high` — a user-input **source provably flows into the sink** (taint-backed), or a deterministic fact
  (committed secret, JWT `none`). These fail `--ci` and are what the MCP `scan` tool returns by default.
- `medium` — a dangerous sink on a non-literal value with no proven source (e.g. `eval(x)`).
- `review` — a structural smell that needs a human (e.g. a route with no visible auth). **Excluded from
  `--ci` and from the agent loop by default**, so agents never chase phantom work. Add `--all` to include them.

## Install & use

```sh
bun add -d vibecheck    # or: npm i -D vibecheck (Node >= 20)
vibecheck . --ci
vibecheck explain VC-SQLI
vibecheck mcp           # MCP stdio server exposing a `scan` tool (high-confidence by default)
```

Agents: see [`AGENTS.md`](AGENTS.md) — run `vibecheck . --ci` before declaring a task done and fix every
high-confidence finding.

> JS/TS scanning needs nothing extra. **Python scanning** additionally requires **`python3` on PATH**
> (used only to parse via the stdlib `ast`); if it's absent, `.py` files are silently skipped.

## Rules (exactly what is implemented + benchmarked)

Taint-backed: `VC-RCE-EVAL`, `VC-RCE-CHILD-PROCESS`, `VC-SQLI`, `VC-XSS-REACT`, `VC-XSS-DOM`, `VC-SSRF`,
`VC-PATH-TRAVERSAL`, `VC-OPEN-REDIRECT`. AST config: `VC-CORS-WILDCARD`, `VC-JWT-NONE`,
`VC-JWT-UNPINNED`, `VC-COOKIE-INSECURE`, `VC-STACK-EXPOSURE`. Provenance/secrets: `VC-SECRET-*` (8),
`VC-ENV-COMMITTED/DRIFT/MISSING`, `VC-NEXT-PUBLIC-SECRET`, `VC-SUPABASE-SERVICE-ROLE`. Advisory:
`VC-ROUTE-NO-AUTH` (review), `VC-INPUT-NO-VALIDATION`. **Python** (`VC-PY-*`): `VC-PY-RCE`,
`VC-PY-CMDI`, `VC-PY-SQLI`, `VC-PY-DESERIALIZE`, `VC-PY-YAML`, `VC-PY-SSTI`, `VC-PY-OPEN-REDIRECT`,
`VC-PY-PATH`. `vibecheck explain <id>` prints the fix for each.

## Limitations (honest)

- **JS/TS/JSX/TSX + Python** in v0.2 (Python needs `python3` on PATH). More languages are roadmap (via
  each language's own real parser / tree-sitter, never hand-rolled).
- **Intra-procedural** taint: flow across functions/files/modules is not tracked (false negatives there).
- Config/secret rules are pattern-based where AST adds no value.
- A high-signal gate and early-warning — **not a proof of security**. Pair it with Semgrep/CodeQL and review.

## Config — `.vibecheck.json`

```json
{ "ignoreRules": ["VC-INPUT-NO-VALIDATION"], "allowPaths": ["test/**"], "failSeverity": "high" }
```

## License

MIT © 2026 Aris Rhiannon — see [LICENSE](LICENSE).
