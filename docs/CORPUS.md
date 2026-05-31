# Real-world corpus measurement

Beyond the curated [`METRICS.md`](METRICS.md) benchmark, vibecheck is run against real, widely-used
open-source repositories at pinned commits. This is an **honest, manually-triaged** measurement of the
**high-confidence** findings (exactly what `--ci` and the MCP `scan` tool surface). Reproduce with
`bun scripts/corpus.ts` (clones the repos below, scans, writes `corpus-raw.json`).

> **This corpus earned its keep: it exposed a critical bug.** `collectFiles` (used by the real
> `scanProject`/CLI/MCP path) was missing `.py`/`.go` from its text-extension allowlist, so the Python
> and Go analyzers **never ran in real scans** — they only ran in unit tests/benchmark, which call them
> directly. Fixed (`.py`/`.go` added + regression test). The file counts below jumped accordingly
> (e.g. flask 62→144, gin 18→110), and dvpwa's real SQLi is now caught.

## Method
- Shallow-clone each repo at a pinned tag / full SHA; record the exact commit.
- Run `scanProject()` (all detectors, all three languages) and keep the **`confidence:"high"`** findings.
- **Manually triage every high-confidence finding** (no sampling). `medium`/`review` (excluded from
  `--ci`) are reported as counts only.

## Corpus (9 repos, 1,218 files)

| repo | kind | commit | files | scan | **high** | med | review |
|--|--|--|--|--|--|--|--|
| expressjs/express @ 4.21.2 | JS — mature framework | `1faf228935` | 191 | ~1.3 s | 1 | 26 | 258 |
| fastify/fastify @ v4.28.1 | JS/TS — mature framework | `94068edf59` | 355 | ~7.6 s | 0 | 41 | 961 |
| OWASP/NodeGoat @ `c5cb68a7` | JS — intentionally vulnerable | `c5cb68a708` | 92 | ~1.0 s | **4** | 16 | 20 |
| pallets/flask @ 3.0.3 | Python — mature framework | `c12a5d874c` | 144 | ~1.2 s | 1 | 2 | 0 |
| pallets/werkzeug @ 3.0.3 | Python — mature WSGI toolkit | `f9995e9679` | 209 | ~2.8 s | 0 | 4 | 0 |
| psf/requests @ v2.32.3 | Python — mature HTTP lib | `0e322af877` | 65 | ~0.9 s | 0 | 1 | 0 |
| anxolerd/dvpwa @ master | Python (aiohttp) — intentionally vulnerable | `a1d8f89fac` | 31 | ~1.5 s | **1** | 7 | 0 |
| gin-gonic/gin @ v1.10.0 | Go — mature framework | `75ccf94d60` | 110 | ~0.1 s | 0 | 0 | 0 |
| gorilla/mux @ v1.8.1 | Go — mature router | `b4617d0b96` | 21 | ~35 ms | 0 | 0 | 0 |

## Triage of every high-confidence finding (7 total)

| # | repo | rule | location | verdict |
|--|--|--|--|--|
| 1–3 | NodeGoat | VC-RCE-EVAL | `app/routes/contributions.js:32-34` `eval(req.body.*)` | **TP — real RCE** |
| 4 | NodeGoat | VC-OPEN-REDIRECT | `app/routes/index.js:72` `res.redirect(req.query.url)` | **TP — real open redirect** |
| 5 | **dvpwa** | VC-PY-SQLI | `sqli/views.py:57` `await Student.create(conn, data['name'])` | **TP — real SQLi** (aiohttp `await request.post()` → `data.get()` → cross-file into `Student.create`, which builds `"... '%(name)s'" % {'name': name}` and executes it) |
| 6 | express | VC-OPEN-REDIRECT | `test/res.location.js:194` `res.location(req.query.q)` | correct detection, **in test code** |
| 7 | flask | VC-ENV-COMMITTED | `tests/test_apps/.env` | correct detection, **benign test fixture** |

The dvpwa true positive is what this iteration set out to close: it needed (a) **aiohttp** sources
(`await request.post()`, `request.match_info`), (b) `await`/`Dict` taint (the `% {'name': name}`), and
(c) **class `@staticmethod` cross-file resolution** (`Student.create`). All three landed.

## Results (honest, two lenses)
- **Detector precision: 7/7 = 100%** — every high-confidence finding correctly matches its rule; **0
  spurious findings**.
- **Production-exploitable precision: 5/7 ≈ 71%** — 5 are exploitable production vulnerabilities (NodeGoat
  ×4 + dvpwa ×1); 2 are correct detections in test code / a test fixture (excludable via `allowPaths`).
- **6 mature frameworks/libs (express/fastify/flask/werkzeug/requests/gin/mux): 0 spurious high-confidence
  findings**, even after the fix made all their Python/Go files actually get scanned.

## Prior corpus-driven fixes (still in effect)
- Fixed-prefix relative redirects are not open redirects.
- SSRF requires a server source (not client-side `document.location` → `fetch`).

## Limitations (read this)
- **Small, curated repo set (9).** A transparency exercise, not a statistically representative study.
- **High-confidence only.** `medium`/`review` (excluded from `--ci`) are counted, not triaged.
- A variable literally named `req`/`request`/`ctx`/`event` that is *not* a server request (e.g. a local
  object literal or an HTTP-client response) matches a source pattern by name; an independent audit showed
  this **can reach `high`** in a direct sink (`db.query("…"+req.body.x)`), not only `review`. Real code
  rarely names a non-request `req`, but a sound fix needs scope/shadowing analysis — tracked, not yet done.
- Manual triage by the author — judgement calls (e.g. "test code") are stated, not hidden.
