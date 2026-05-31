# Code Review Report

**Target:** New data-flow features — return-taint summaries (`buildSummaries`, `returnTainted`), cross-file resolution (`crossFileSummaries`), interproc rewrite (param-sink + cross-file)
**Strategy:** medium
**Dimensions:** Security (FP focus), Performance, Architecture, Testing, Reliability
**Confidence threshold:** 75
**Generated:** 2026-05-31T05:47:00Z

## Executive summary

The new data-flow features are well-designed and additive — `isTainted` is unchanged, the optional `summaries` param defaults to no-op, and all 42 tests + 69 benchmark cases pass at 100% precision/recall. One **High** finding: cross-file name collision produces critical/high false positives when two modules export same-named functions with different taint behavior. One **Medium** finding: `String(x).replace(...)` is treated as taint-preserving in summaries (pre-existing engine tradeoff, amplified by summaries). Documentation is stale.

## Findings

### High (P1) — fix before next release (1)

### [FP1] Cross-file name collision causes false positive in `crossFileSummaries` and `interprocFindings`

- **Severity:** High
- **Dimension:** Security (false positive)
- **Confidence:** 95
- **Location:** `src/taint.ts:243` and `src/interproc.ts:82`
- **Reachability:** confirmed
- **Evidence:**
  ```typescript
  // src/taint.ts:243 — first-come-first-served global map:
  for (const [n, sm] of s) if (!global.has(n)) global.set(n, sm);
  // src/taint.ts:249 — import-gating checks name only, not source:
  for (const n of importedNames(ast)) { const g = global.get(n); if (g && !base.has(n)) base.set(n, g); }
  ```
  Test case: `tainted.ts` exports `getData()` returning `req.body.x`; `safe.ts` exports `getData()` returning `42`; `app.ts` imports from `safe` → gets tainted summary → fires critical/high VC-SQLI.
- **Why this is a problem:** Common function names (`getData`, `getUser`, `fetchData`, `validate`, `query`) will collide across modules. The tool produces a `critical`/`high`-confidence false positive that violates the "0 FP" design goal.
- **Recommendation:** 🔴 Resolve import source paths (even approximately — match the `from '...'` specifier against file rel paths) to pick the correct summary. Or: when multiple files define the same name with conflicting taint, skip the name in the global map (prefer FN over FP, consistent with the tool's philosophy).

---

### Medium (P2) — plan for next sprint (2)

### [FP2] `String(x).replace(...)` treated as taint-preserving in return-taint summaries

- **Severity:** Medium
- **Dimension:** Security (false positive)
- **Confidence:** 80
- **Location:** `src/taint.ts:72`
- **Reachability:** confirmed
- **Evidence:**
  ```typescript
  // isTainted catch-all for method calls:
  if (t.isMemberExpression(callee)) return isTainted(callee.object, set);
  ```
  `const sanitize = (x) => String(x).replace(/[^a-z]/g, "")` gets `returnParams: [0]`, causing downstream sinks to fire as critical/high.
- **Why this is a problem:** Pre-existing taint engine tradeoff, but now amplified — one FP in a helper propagates to all call sites via summaries.
- **Recommendation:** 🟡 Not blocking for this PR. Track for future: whitelist `.replace()` with literal restrictive regex as a sanitizer, or recognize the pattern in `buildSummaries`.

---

### [DOC1] README claims cross-file and return-taint are "not tracked"

- **Severity:** Medium
- **Dimension:** Architecture (documentation)
- **Confidence:** 95
- **Location:** `README.md:92`
- **Reachability:** confirmed
- **Evidence:**
  ```
  Cross-**file**/module flow, helper→helper chains, and return-taint are not tracked (false negatives there).
  ```
- **Recommendation:** 🟡 Update to reflect current capabilities and honest limitations (aliased imports, namespace calls, 5+ hop chains not resolved).

---

### Low (P3) — track in backlog (2)

### [PERF1] `crossFileSummaries` calls `buildSummaries` twice per file

- **Severity:** Low
- **Dimension:** Performance
- **Confidence:** 85
- **Location:** `src/taint.ts:240` and `src/taint.ts:250`
- **Evidence:** Measured 538ms for 500 files (1.08ms/file). Second call is necessary for cross-file propagation.
- **Recommendation:** 🟢 Accept. Skip second call for files that don't import any cross-file names as future optimization.

---

### [FN1] 5+ hop call chains exceed the 4-iteration fixpoint limit

- **Severity:** Low
- **Dimension:** Reliability (false negative)
- **Confidence:** 90
- **Location:** `src/taint.ts:207`
- **Evidence:** 5-hop chain `a→b→c→d→e→x`: function `a` gets empty `returnParams` (missed).
- **Recommendation:** 🟢 Accept as documented FN. Increase limit to 6-8 if desired (cheap).

---

## Findings by dimension

| Dimension     | Critical | High | Medium | Low | Total |
|---------------|---------:|-----:|-------:|----:|------:|
| Security      |        0 |    1 |      1 |   0 |     2 |
| Performance   |        0 |    0 |      0 |   1 |     1 |
| Architecture  |        0 |    0 |      1 |   0 |     1 |
| Testing       |        0 |    0 |      0 |   0 |     0 |
| Reliability   |        0 |    0 |      0 |   1 |     1 |
| **Total**     |    **0** |**1** |  **2** |**2**| **5** |

## Recommended action plan

1. 🔴 **[FP1]** Fix cross-file name collision: resolve import source paths or skip conflicting names in the global map. This is the only finding that violates the "0 FP" design goal.
2. 🟡 **[DOC1]** Update README limitations section to reflect new capabilities and honest limitations.
3. 🟡 **[FP2]** Track `String(x).replace(...)` sanitizer recognition for future improvement.
4. 🟢 **[FN1]** Consider bumping fixpoint limit from 4 to 6-8 iterations.
5. 🟢 **[PERF1]** Skip second `buildSummaries` call for files with no cross-file imports.

## Praise

- 🎉 The additive design is excellent — `isTainted` is truly unchanged, the optional `summaries` param defaults to no-op, and `buildTaintSets(file)` without summaries behaves identically to before.
- 🎉 The 4-iteration fixpoint in `buildSummaries` correctly propagates `returnParams` across multi-hop chains (2, 3, 4 levels) and handles mutual recursion without hanging.
- 🎉 `returnsAbsolute` vs `returnParams` distinction is clean: a function that reads a source directly (`return req.body.x`) taints all callers unconditionally, while a pass-through only taints when the argument is tainted.
- 🎉 The `crossFileSummaries` function correctly stores parsed ASTs in a local map, avoiding cache eviction issues for the second pass.
- 🎉 Engine deduplication by `file:line:ruleId` cleanly prevents double-reporting between analyze2 and interproc.
- 🎉 Import-gating works correctly for the common case (no import = no cross-file taint).
- 🎉 Sanitizer respect in summaries is correct: `Number(x)`, `schema.parse(x)`, and reassignment-based sanitization all clear taint properly.

## Out of scope (not reviewed)

- Python analyzer (JS/TS only features)
- MCP server integration
- CLI output formatting
- Secret/env detection (unchanged)

## False positives eliminated

- 7 candidate FP scenarios tested; 5 confirmed as correctly non-firing
- 2 confirmed FPs: [FP1] name collision (High), [FP2] String.replace (Medium, pre-existing)

## Metadata

- Phases completed: 0..4
- Strict mode: no
- Reviewer: kiro code-review skill v1
