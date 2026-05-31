# Code Review Report

**Target:** Cross-file taint upgrade (commits `1476d48`, `f4f06ad`) — real relative-module resolution + aliased + namespace imports + multi-hop fixpoint
**Strategy:** medium
**Dimensions:** Security (FP/FN), Performance, Reliability, Testing
**Confidence threshold:** 75
**Generated:** 2026-05-31T07:07:48Z

## Executive summary

The cross-file taint upgrade is **sound and safe**. Resolution is correctly bounded by `relSet` membership, namespace keys cannot collide with non-namespace member calls in valid code, and the fixpoint always terminates. One Medium documentation finding (stale README/ADR). One Low performance observation (file-order-dependent fixpoint depth). All tests pass (51/51), benchmark is 100/100/0 FP.

## Findings

### Critical (P0) — must fix immediately (0)

None.

### High (P1) — fix before next release (0)

None.

### Medium (P2) — plan for next sprint (1)

### [DOC1] README and ADR-0006 are stale — describe OLD cross-file behavior

- **Severity:** Medium
- **Dimension:** Architecture (documentation)
- **Confidence:** 95
- **Location:** `README.md:92` and `docs/adr/0006-return-taint-cross-file.md`
- **Reachability:** confirmed
- **Evidence:**
  ```
  README.md:92:
  sanitizers respected). Not tracked (false negatives): aliased/namespace/re-exported imports, helper
  chains beyond a few hops, methods, destructured params, and names defined in **multiple** files
  (treated as ambiguous and skipped — to avoid false positives).
  ```
  ADR-0006 describes "By-name, 1-hop" and "ambiguity rule" which no longer exist.
- **Why this is a problem:** Users reading the README will underestimate the tool's capabilities. The ADR describes a design that no longer exists, creating confusion for future contributors.
- **Recommendation:** 🟡 Update README to reflect: real relative-module resolution, aliased imports handled, namespace imports handled, multi-hop fixpoint (up to 5 iterations). Update ADR-0006 status to "Superseded" and add ADR-0008 for the new approach. Remaining FNs to document: re-exports, default exports, dynamic `import()`, CommonJS `require()`, chains >4 hops in worst-case file ordering.
- **Fix snippet:**
  ```markdown
  # README.md — replace the limitation line:
  - **Taint scope:** JS/TS taint is **inter-procedural** — function summaries carry **return-taint** and
    **parameter→sink** reachability, resolved **within a file and across files via real relative-module
    resolution** (named, aliased, and namespace imports; multi-hop fixpoint, sanitizers respected).
    Not tracked (false negatives): re-exported imports (`export { x } from './y'`), default exports,
    dynamic `import()`, CommonJS `require()`, and chains beyond ~4 hops in adversarial file ordering.
    Python and Go are intra-procedural.
  ```

---

### Low (P3) — track in backlog (1)

### [PERF1] Fixpoint convergence is file-order-dependent

- **Severity:** Low
- **Dimension:** Performance / Reliability
- **Confidence:** 85
- **Location:** `src/taint.ts:285-295`
- **Reachability:** confirmed (only in worst-case reverse file ordering)
- **Evidence:**
  ```typescript
  // eff is updated IN-PLACE during iteration:
  for (const [rel, ast] of parsed) {
    // ... builds base from eff (which may already be updated this iteration)
    eff.set(rel, ne);  // later files in this iteration see this update
  }
  ```
  In forward file order (source → consumer), a single iteration propagates all hops. In reverse order, each iteration propagates only 1 hop. With cap=5, worst-case max depth is 4 hops.
- **Why this is a problem:** The effective depth limit is non-deterministic — it depends on `Map` iteration order (insertion order from `collectFiles`). A project reorganization could silently change which chains are detected.
- **Recommendation:** 🟢 Accept as-is. Real-world taint chains rarely exceed 4 hops across files. If desired, bump cap from 5 to 8 (cheap — adds <1s on fastify). Alternatively, sort files topologically by import edges before iterating (would guarantee max depth = cap regardless of input order).

---

## Findings by dimension

| Dimension     | Critical | High | Medium | Low | Total |
|---------------|---------:|-----:|-------:|----:|------:|
| Security      |        0 |    0 |      0 |   0 |     0 |
| Performance   |        0 |    0 |      0 |   1 |     1 |
| Architecture  |        0 |    0 |      1 |   0 |     1 |
| Testing       |        0 |    0 |      0 |   0 |     0 |
| Reliability   |        0 |    0 |      0 |   0 |     0 |
| **Total**     |    **0** |**0** |  **1** |**1**| **2** |

## Recommended action plan

1. 🟡 **[DOC1]** Update README limitations section and ADR-0006 to reflect the new real module resolution. Add a new ADR-0008 documenting the design.
2. 🟢 **[PERF1]** Consider bumping fixpoint cap from 5 to 8, or sorting files topologically before iteration.

## Praise

- 🎉 The `resolveModule` + `normalizePath` design is elegant and safe — resolution is always bounded by `relSet` membership, making it structurally impossible to attach the wrong file's summary unless that file is actually in the scanned set AND matches the import path.
- 🎉 Extension resolution order (`.ts` > `.tsx` > `.js` > `.jsx` > `.mjs` > `.cjs` > `/index.*`) matches real Node/TS/bundler behavior perfectly.
- 🎉 The namespace key scheme (`${local}.${fn}`) is collision-free in valid code because `import * as x` binds `x` in module scope, preventing a same-named local variable.
- 🎉 The test suite (`crossfile.test.ts`) covers all the critical scenarios: named, aliased, namespace, multi-hop, precise resolution, and bare-name non-resolution. Well-designed.
- 🎉 The old FP1 (name collision from the previous QA review) is completely fixed — same-name helpers in different files are now resolved precisely by import path.

## Out of scope (not reviewed)

- Go and Python analyzers (unchanged by this commit)
- Secret/env detection (unchanged)
- CLI/MCP interface (unchanged)
- `isTainted` function (confirmed unchanged via git diff)

## False positives eliminated

- 0 — no candidate findings were raised and then dropped. The code is clean.

## Metadata

- Phases completed: 0..4
- Strict mode: no
- Reviewer: kiro code-review skill v1
