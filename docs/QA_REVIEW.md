# Code Review Report

**Target:** vibecheck v0.2 re-architecture (src/, benchmark/, test/, docs/)
**Strategy:** medium
**Dimensions:** Security, Correctness, Testing, Reliability, Honesty
**Confidence threshold:** 75
**Generated:** 2026-05-31T03:50:35Z

## Executive summary

The v0.2 re-architecture is **genuinely better than v0.1** — it uses a real AST parser, implements actual intra-procedural taint tracking, and the confidence-gating design is sound. However, the taint engine has two concrete soundness gaps (JSON.parse taint loss, monotonic set can't un-taint) and the SQLI rule over-fires on non-SQL `.query()` calls. The 100/100 benchmark is honest but self-serving — adding 3 adversarial cases would break it and drive real improvements.

## Verdict: **NEEDS-FIX**

The tool is a genuine improvement and the honest framing is commendable, but the taint bypass through `JSON.parse()` (the most common Express body-reading pattern) is a significant false-negative gap, and the `.query()` over-firing is a real false-positive risk that undermines the "low-FP" promise.

## Findings

### Critical (P0) — must fix immediately (0)

None.

### High (P1) — fix before next release (0)

None.

### Medium (P2) — plan for next sprint (4)

#### [TAINT1] `JSON.parse(taintedSource)` loses taint — false negative on the #1 body-reading pattern
- **File:** `src/taint.ts:50-55`
- **Impact:** The most common Express pattern (`JSON.parse(req.body)`) produces data the tool considers clean. Any sink consuming the parsed result is a false negative.
- **Fix:** In the MemberExpression-callee branch of CallExpression, also propagate taint if any argument is tainted (excluding sanitizers).

#### [TAINT3] Monotonic taint set produces false positives on sanitize-then-use via reassignment
- **File:** `src/taint.ts:86-98`
- **Impact:** `let id = req.query.id; id = Number(id); sink(id)` fires as tainted even though `id` was sanitized. Undermines the "low-FP" promise.
- **Fix:** Consider flow-sensitive ordering, or remove a variable from the set if its last assignment is a sanitizer.

#### [ANAL1] `.query()` / `.execute()` fires VC-SQLI on non-SQL objects (Redis, HTTP, etc.)
- **File:** `src/analyze2.ts:62-70`
- **Impact:** Any tainted argument to ANY object's `.query()` or `.execute()` method fires a critical/high SQLI finding. Redis, Elasticsearch, and HTTP client usage will produce false positives.
- **Fix:** Constrain the object name to SQL-associated identifiers, or downgrade generic `.query()`/`.execute()` to medium confidence.

#### [BENCH1] Benchmark corpus lacks adversarial cases — 100/100 is fragile
- **File:** `benchmark/corpus.ts`
- **Impact:** Three concrete cases would break the perfect score, revealing TAINT1, TAINT3, and ANAL1. The metric is honest but doesn't stress-test weaknesses.
- **Fix:** Add the three cases documented in the finding. Accept the score drop until the underlying issues are fixed.

### Low (P3) — track in backlog (2)

#### [MCP1] MCP `counts` object is unfiltered while `findings` array is filtered
- **File:** `src/mcp.ts:36-37`
- **Impact:** Agents see inconsistent data (e.g., `counts.critical: 3` but only 1 finding in the array).
- **Fix:** `const counts = countBySeverity(findings);` after filtering.

#### [ANAL3] `document.writeln()` not detected as XSS sink
- **File:** `src/analyze2.ts:79`
- **Impact:** Minor coverage gap; `writeln` is rare but equally dangerous.
- **Fix:** Add `|| cp === "document.writeln"` to the condition.

## Findings by dimension

| Dimension     | Critical | High | Medium | Low | Total |
|---------------|---------:|-----:|-------:|----:|------:|
| Security      |        0 |    0 |      3 |   1 |     4 |
| Testing       |        0 |    0 |      1 |   0 |     1 |
| Reliability   |        0 |    0 |      0 |   1 |     1 |
| **Total**     |    **0** |**0** |  **4** |**2**| **6** |

## Recommended action plan

1. **Fix TAINT1** (JSON.parse taint propagation) — highest impact, most common pattern missed.
2. **Fix ANAL1** (constrain .query()/.execute() to SQL objects) — prevents the most likely real-world FPs.
3. **Add adversarial benchmark cases** (BENCH1) — will validate fixes to #1 and #2, and expose TAINT3.
4. **Fix TAINT3** (flow-sensitive sanitization) — harder; acceptable to document as known limitation if fix is complex.
5. **Fix MCP1** (recompute counts) — one-line fix.
6. **Fix ANAL3** (add writeln) — one-line fix.

## Praise

- 🎉 The confidence-gating architecture is well-designed. The separation of `high`/`medium`/`review` with `--ci` defaulting to high-only is exactly right for agent loops.
- 🎉 The REARCHITECTURE.md is refreshingly honest — it concedes v0.1's weaknesses directly and doesn't over-claim v0.2's capabilities.
- 🎉 The sanitizer recognition (Number/parseInt/schema.parse) is a thoughtful touch that most quick SAST implementations skip.
- 🎉 The ORM `.exec()` exclusion is correctly implemented via the member-expression object-name check — no false positives on Mongoose/RegExp.
- 🎉 The benchmark infrastructure (labeled corpus + precision/recall + CI regression test) is the right approach for a tool that claims measured quality.
- 🎉 The `buildTaintSets` fixpoint with a hard iteration cap (4) is a pragmatic design that guarantees termination while handling realistic taint chains.

## Out of scope (not reviewed)

- Inter-procedural taint (explicitly out of scope for v0.2)
- Performance benchmarking (tool runs in ms, no concern)
- Multi-language support (explicitly roadmap)
- `src/walk.ts` gitignore parsing correctness (tested by existing tests)
- `src/envcheck.ts` logic (straightforward, well-tested)

## False positives eliminated

7 candidate findings eliminated after applying §0–§15 checks:
- TAINT2: documented limitation, not a bug
- ANAL2: common patterns covered, rare gap acceptable
- ANAL4: regex is correctly bounded, advisory-only finding
- REDOS1: no actual ReDoS after analysis
- HONEST1: README is genuinely honest
- GATE1: positive finding (works correctly)
- TAINT4: positive finding (terminates correctly)

## Metadata

- Phases completed: 0, 1, 2, 3, 4
- Strict mode: no
- Reviewer: kiro code-review skill v1
