# vibecheck

[![ci](https://github.com/ArisRhiannon/vibecheck/actions/workflows/ci.yml/badge.svg)](https://github.com/ArisRhiannon/vibecheck/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A fast, **agent-native** "safe to ship?" gate for vibe-coded apps. It parses your **JS/TS/JSX/TSX**
(`@babel/parser`), **Python** (the stdlib `ast`), and **Go** (`go/parser`) with **real parsers** and uses **taint analysis**
(inter-procedural for JS/TS, Python, and Go — return-taint + param→sink summaries, within a file and across files) to flag the security classes AI coding agents get wrong — committed secrets, SQL
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
| Data-flow | inter-procedural (return-taint + param→sink; intra-file + cross-file by import) | taint (Pro) | full inter-procedural |
| Languages | **JS/TS/JSX/TSX + Python + Go** | many | many |
| Speed / infra | ms, local, no account | fast | slower, CI-oriented |
| Agent-native (MCP, confidence gating) | **yes, first-class** | partial | no |
| Breadth of rules | small, focused | 2000+ | huge |

If you only adopt one general SAST, adopt Semgrep or CodeQL. Adopt vibecheck as the **fast agent/CI
pre-flight** that won't drown an agent in false positives.

## Measured quality (not claimed)

Against a labeled benchmark of **91 cases** across JS/TS, Python **and** Go (vulnerable + safe + deliberately
tricky-safe), the core detectors score (see [`METRICS.md`](METRICS.md), reproduce with `bun benchmark/run.ts`):

- **Precision 100%**, **Recall 100%**, **F1 100%** on the corpus.

The tricky-safe cases that produce **zero false positives** include: parameterized queries, tagged-
template SQL, numeric-coerced and schema-validated input, ORM/RegExp `.exec()`, Supabase **anon** /
Stripe **publishable** keys, hardened cookies, allow-listed CORS, and pinned JWT algorithms — exactly
the patterns a regex linter trips on. This benchmark is curated; for a **real-world** measurement (9 pinned
OSS repos, 1,218 files, manually triaged), see [`docs/CORPUS.md`](docs/CORPUS.md) — which exposed a
critical bug (Python/Go files weren't being scanned in real scans) and drove precision fixes (relative
redirects, server-source-only SSRF).

## Confidence 

Every finding has a **confidence**:
- `high` — a user-input **source provably flows into the sink** (taint-backed), or a deterministic fact
  (committed secret, JWT `none`). These fail `--ci` and are what the MCP `scan` tool returns by default.
- `medium` — a dangerous sink on a non-literal value with no proven source (e.g. `eval(x)`).
- `review` — a structural smell that needs a human (e.g. a route with no visible auth). **Excluded from
  `--ci` and from the agent loop by default**, so agents never chase phantom work. Add `--all` to include them.

## Install & use

```sh
npm i -D @arisrhiannon/vibecheck    # or: bun add -d @arisrhiannon/vibecheck (Node >= 20)
vibecheck . --ci
vibecheck explain VC-SQLI
vibecheck mcp           # MCP stdio server exposing a `scan` tool (high-confidence by default)
```

Agents: see [`AGENTS.md`](AGENTS.md) — run `vibecheck . --ci` before declaring a task done and fix every
high-confidence finding.

> JS/TS scanning needs nothing extra. **Python** scanning requires **`python3` on PATH**; **Go** scanning
> requires a **`go` toolchain on PATH** (the analyzer is compiled once and cached). If a runtime is absent
> those files are skipped; if an analyzer **fails**, a warning is printed to **stderr** (so a crash never
> silently drops findings).

## Rules (implemented + benchmarked)

Taint-backed: `VC-RCE-EVAL`, `VC-RCE-CHILD-PROCESS`, `VC-SQLI`, `VC-XSS-REACT`, `VC-XSS-DOM`, `VC-SSRF`,
`VC-PATH-TRAVERSAL`, `VC-OPEN-REDIRECT`. AST config: `VC-CORS-WILDCARD`, `VC-JWT-NONE`,
`VC-JWT-UNPINNED`, `VC-COOKIE-INSECURE`, `VC-STACK-EXPOSURE`. Provenance/secrets: `VC-SECRET-*` (8),
`VC-ENV-COMMITTED/DRIFT/MISSING`, `VC-NEXT-PUBLIC-SECRET`, `VC-SUPABASE-SERVICE-ROLE`. Advisory:
`VC-ROUTE-NO-AUTH` (review), `VC-INPUT-NO-VALIDATION`. **Python** (`VC-PY-*`): `VC-PY-RCE`,
`VC-PY-CMDI`, `VC-PY-SQLI`, `VC-PY-DESERIALIZE`, `VC-PY-YAML`, `VC-PY-SSTI`, `VC-PY-OPEN-REDIRECT`,
`VC-PY-PATH`. **Go** (`VC-GO-*`): `VC-GO-CMDI`, `VC-GO-SQLI`, `VC-GO-PATH`, `VC-GO-OPEN-REDIRECT`,
`VC-GO-SSRF`. `vibecheck explain <id>` prints the fix for each.

## Limitations

- **JS/TS/JSX/TSX + Python + Go** (Python needs `python3`, Go needs a `go` toolchain on PATH). More
  languages are roadmap (each via its own real parser, never hand-rolled).
- **Taint scope:** JS/TS taint is **inter-procedural with real cross-file module resolution** — function
  summaries carry **return-taint** and **parameter→sink** reachability, resolved within a file and **across
  files via resolved relative imports** (named, **aliased** `a as b`, and **namespace** `* as ns`),
  propagated **multi-hop** by a fixpoint; sanitizers respected. Not tracked (false negatives): re-exports
  (`export { x } from …`), default exports, CommonJS `require`/dynamic `import()`, bare/package imports,
  chains deeper than ~7 hops in worst-case file order, methods, and destructured params. **Python** is also
  inter-procedural (return-taint + param→sink **and class `@staticmethod` resolution**, intra-file and cross-file via resolved `from .mod import`/
  `import mod`; not resolved: `import a.b` dotted-unaliased, `*`/re-exports, decorators). Python request
  **sources** span Flask, Django, **aiohttp** (`request.match_info`, `await request.post()`), FastAPI/
  Starlette (`request.query_params`/`path_params`, `await request.json()/form()`), Tornado, Bottle, Pyramid. **Go** is
  inter-procedural **within and across packages** (return-taint + param→sink; unaliased `pkg.Func`
  resolves by package name). Aliased package imports (`import u "…/util"`) and multi-return assignments
  (`x, _ := f(src)`) are not tracked.
- Config/secret rules are pattern-based where AST adds no value.
- A high-signal gate and early-warning — **not a proof of security**. Pair it with Semgrep/CodeQL and review.

## Config — `.vibecheck.json`

```json
{ "ignoreRules": ["VC-INPUT-NO-VALIDATION"], "allowPaths": ["test/**"], "failSeverity": "high" }
```

## License

MIT © 2026 Aris Rhiannon — see [LICENSE](LICENSE).
