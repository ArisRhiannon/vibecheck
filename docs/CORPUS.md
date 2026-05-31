# Real-world corpus measurement

Beyond the curated [`METRICS.md`](METRICS.md) benchmark, vibecheck is run against real, widely-used
open-source repositories at pinned commits. This is an **honest, manually-triaged** measurement of the
**high-confidence** findings (exactly what `--ci` and the MCP `scan` tool surface). Reproduce with
`bun scripts/corpus.ts` (clones the repos below, scans, writes `corpus-raw.json`).

## Method
- Shallow-clone each repo at a pinned tag / full SHA; record the exact commit.
- Run `scanProject()` (all detectors, all three languages) and keep the **`confidence:"high"`** findings.
- **Manually triage every high-confidence finding** (no sampling — the high set is small enough to review
  in full). `medium`/`review` findings are excluded from `--ci`/MCP by design and are reported as counts
  only (not triaged here).

## Corpus (9 repos, 833 files)

| repo | kind | commit | files | scan | **high** | med | review |
|--|--|--|--|--|--|--|--|
| expressjs/express @ 4.21.2 | JS — mature framework | `1faf228935` | 191 | ~1.4 s | 1 | 26 | 258 |
| fastify/fastify @ v4.28.1 | JS/TS — mature framework | `94068edf59` | 355 | ~7.8 s | 0 | 41 | 961 |
| OWASP/NodeGoat @ `c5cb68a7` | JS — intentionally vulnerable | `c5cb68a708` | 92 | ~1.0 s | **4** | 16 | 20 |
| pallets/flask @ 3.0.3 | Python — mature framework | `c12a5d874c` | 62 | ~6 ms | 1 | 0 | 0 |
| pallets/werkzeug @ 3.0.3 | Python — mature WSGI toolkit | `f9995e9679` | 71 | ~21 ms | 0 | 2 | 0 |
| psf/requests @ v2.32.3 | Python — mature HTTP lib | `0e322af877` | 29 | ~6 ms | 0 | 0 | 0 |
| anxolerd/dvpwa @ master | Python — intentionally vulnerable | `a1d8f89fac` | 10 | ~1.5 s | 0 | 7 | 0 |
| gin-gonic/gin @ v1.10.0 | Go — mature framework | `75ccf94d60` | 18 | ~8 ms | 0 | 0 | 0 |
| gorilla/mux @ v1.8.1 | Go — mature router | `b4617d0b96` | 5 | ~1 ms | 0 | 0 | 0 |

## Triage of every high-confidence finding (6 total)

| # | repo | rule | location | verdict |
|--|--|--|--|--|
| 1–3 | NodeGoat | VC-RCE-EVAL | `app/routes/contributions.js:32-34` `eval(req.body.*)` | **TP — real RCE** |
| 4 | NodeGoat | VC-OPEN-REDIRECT | `app/routes/index.js:72` `res.redirect(req.query.url)` | **TP — real open redirect** |
| 5 | express | VC-OPEN-REDIRECT | `test/res.location.js:194` `res.location(req.query.q)` | correct detection, **in test code** (not production) |
| 6 | flask | VC-ENV-COMMITTED | `tests/test_apps/.env` | correct detection (committed `.env`), **benign test fixture** |

## Two false-positive classes this corpus found — and fixed
1. **Fixed-prefix relative redirect** (`res.redirect('/user/' + id)`, express examples) — not an open
   redirect. Fixed: the open-redirect rule ignores relative `/x…` targets (still flags `'/'+input` →
   `//evil.com` and host-controlled targets). Regression-tested.
2. **Client-side `document.location` → `fetch`** (werkzeug `debug/shared/debugger.js`) — flagged as SSRF,
   but SSRF is server-side; this is browser code fetching its own URL. Fixed: VC-SSRF now requires a
   **server** source (`req/request/ctx/event.*`, a request call, or a tainted variable), not a DOM
   `location`. Server SSRF (direct and via variable) still fires; regression-tested.

## Results (honest, two lenses)
- **Detector precision: 6/6 = 100%** — every remaining high-confidence finding correctly matches its
  rule; **0 spurious findings** after the two fixes above.
- **Production-exploitable precision: 4/6 ≈ 67%** — 4 are exploitable production vulnerabilities (all
  NodeGoat); 2 are correct detections located in **test code / a test fixture** (excludable via
  `allowPaths: ["**/test/**","**/tests/**"]`).
- **6 mature frameworks/libs (express/fastify/flask/werkzeug/requests/gin/mux): 0 spurious high-confidence
  findings.** The high-confidence gate does not drown real codebases in noise.

## Honest false negatives this corpus exposed
- **dvpwa** (intentionally-vulnerable Python) produced **0 high** (7 medium): it uses **aiohttp** request
  APIs (`request.match_info`, `await request.post()`), which are **not** in our source set (we model
  Flask/Django `request.*`, gin, `net/http`). Its SQLi therefore stays at `medium` (the f-string
  heuristic) instead of `high`. Modeling more framework sources (aiohttp, Django ORM, FastAPI) is future
  work — stated plainly. This is exactly the kind of gap a real corpus reveals that a curated benchmark hides.

## Limitations (read this)
- **Small, curated repo set (9).** A transparency exercise, not a statistically representative study.
- **High-confidence only.** `medium`/`review` (excluded from `--ci`) are counted, not triaged.
- **Manual triage by the author** — judgement calls (e.g., "test code") are stated, not hidden.
