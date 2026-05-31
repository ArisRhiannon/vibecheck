# Real-world corpus measurement

Beyond the curated [`METRICS.md`](METRICS.md) benchmark, vibecheck was run against real, widely-used
open-source repositories at pinned commits. This is an **honest, manually-triaged** measurement of the
**high-confidence** findings (exactly what `--ci` and the MCP `scan` tool surface). Reproduce with
`bun scripts/corpus.ts` (clones the repos below, scans, writes `corpus-raw.json`).

## Method
- Shallow-clone each repo at a pinned tag/branch; record the exact commit SHA.
- Run `scanProject()` (all detectors, all languages) and keep only **`confidence: "high"`** findings.
- **Manually triage every high-confidence finding** and classify it. No sampling — the high-confidence
  set was small enough to review in full.

## Corpus (5 repos, 718 files)

| repo | kind | commit | files | scan time | high-confidence |
|--|--|--|--|--|--|
| expressjs/express @ 4.21.2 | JS — mature framework | `1faf228935` | 191 | ~1.4 s | 1 |
| fastify/fastify @ v4.28.1 | JS/TS — mature framework | `94068edf59` | 355 | ~6.5 s | 0 |
| OWASP/NodeGoat @ `c5cb68a7` | JS — intentionally vulnerable | `c5cb68a708` | 92 | ~1.8 s | 4 |
| pallets/flask @ 3.0.3 | Python — mature framework | `c12a5d874c` | 62 | ~6 ms | 1 |
| gin-gonic/gin @ v1.10.0 | Go — mature framework | `75ccf94d60` | 18 | ~8 ms | 0 |

## Triage of every high-confidence finding

Initial run produced **7** high-confidence findings. One was a **genuine false positive** that this
corpus surfaced and which is now **fixed and regression-tested** (see below). The remaining **6**:

| # | repo | rule | location | verdict |
|--|--|--|--|--|
| 1 | NodeGoat | VC-RCE-EVAL | `app/routes/contributions.js:32` `eval(req.body.preTax)` | **TP — real RCE** |
| 2 | NodeGoat | VC-RCE-EVAL | `app/routes/contributions.js:33` `eval(req.body.afterTax)` | **TP — real RCE** |
| 3 | NodeGoat | VC-RCE-EVAL | `app/routes/contributions.js:34` `eval(req.body.roth)` | **TP — real RCE** |
| 4 | NodeGoat | VC-OPEN-REDIRECT | `app/routes/index.js:72` `res.redirect(req.query.url)` | **TP — real open redirect** |
| 5 | express | VC-OPEN-REDIRECT | `test/res.location.js:194` `res.location(req.query.q)` | correct detection, **in test code** (not production-exploitable) |
| 6 | flask | VC-ENV-COMMITTED | `tests/test_apps/.env` | correct detection (a committed `.env`), **benign test fixture** |

### The false positive we fixed
The initial run also flagged `examples/mvc/.../index.js:21` `res.redirect('/user/' + id)` as VC-OPEN-REDIRECT.
That is a **fixed-prefix relative redirect** (`/user/...`) — it cannot leave the site, so it is **not** an
open redirect. This was a real precision bug. Fix: the open-redirect rule now suppresses targets whose
leading literal is a relative path (`/…` but not `//…`); added unit tests + a benchmark case. The
attacker-controlled NodeGoat case (`req.query.url`, no fixed prefix) still fires. The relative check
requires a `/` followed by a **non-slash**, so a bare `'/' + input` (which could become `//evil.com`,
a protocol-relative redirect) is still flagged — verified by test.

## Results (honest, two lenses)
- **Detector precision (after the fix): 6/6 = 100%** — every remaining high-confidence finding correctly
  matches its rule's pattern; **0 spurious findings**.
- **Production-exploitable precision: 4/6 ≈ 67%** — 4 are exploitable production vulnerabilities (all in
  NodeGoat); 2 are correct detections located in **test code / a test fixture**, not production-exploitable.
- **Mature frameworks (express/fastify/flask/gin): 0 spurious high-confidence findings** — the only hits
  were a test-suite line and a test `.env` fixture. This is the key signal: the high-confidence gate does
  **not** drown real codebases in noise.
- The two non-production detections are real instances of their patterns; users can exclude them with
  `allowPaths` (e.g., `["**/test/**", "**/tests/**"]`) in `.vibecheck.json`.

## Limitations (read this)
- **Small, curated repo set (5).** This is a transparency exercise, not a statistically representative
  study. Numbers will differ on other code.
- **High-confidence only.** `medium`/`review` findings (excluded from `--ci`) were not triaged here.
- **Manual triage by the author** — judgement calls (e.g., "test code") are stated, not hidden.
- Mature frameworks are *expected* to yield ~0 (they are the framework, not an app reading `req.*` into
  sinks); intentionally-vulnerable NodeGoat is what exercises the true positives.
