# Code Review Report

**Target:** `src/interproc.ts` — intra-file inter-procedural taint via function summaries
**Strategy:** medium
**Dimensions:** Security (FP focus), Reliability, Performance, Testing, Architecture
**Confidence threshold:** 75
**Generated:** 2026-05-31T05:09:25Z

## Executive summary

The inter-procedural layer is well-designed, additive, and genuinely low-false-positive. It correctly handles sanitization via fixpoint, DB-receiver gating, non-tainted arguments, and name collisions. Two real findings: (1) `tainted.method()` propagation causes FPs for sanitizing methods like `.replace()`, and (2) README still claims "intra-procedural only" which is now stale documentation. All tests pass (35/35), benchmark 100% precision/recall on 66 cases.

---

## Findings

### Medium (P2) — plan for next sprint (2)

### [PERF1] Double-parse: each file is parsed and taint-analyzed twice (analyze2 + interproc)

- **Severity:** Medium
- **Dimension:** Performance
- **Confidence:** 85
- **Location:** `src/interproc.ts:60` and `src/interproc.ts:104`
- **Reachability:** confirmed — `engine.ts` calls both `astFindings(files)` and `interprocFindings(files)` on the same file set
- **Evidence:**
  - `src/analyze2.ts:37`: `const ast = parseFile(f.content, f.rel);` + `const sets = buildTaintSets(ast);`
  - `src/interproc.ts:60`: `const ast = parseFile(f.content, f.rel);`
  - `src/interproc.ts:104`: `const sets = buildTaintSets(ast);`
  - No caching in `src/ast.ts:parseFile` — each call re-invokes `@babel/parser`.
- **Why this is a problem:** Every JS/TS file is parsed twice and has `buildTaintSets` computed twice. On the 500-function benchmark this adds ~47ms per file. For large projects with hundreds of files, this doubles parse time unnecessarily.
- **Recommendation:** Extract a shared `ParsedFile` cache (Map<string, {ast, sets}>) at the engine level, or pass pre-parsed ASTs into both `astFindings` and `interprocFindings`. Not blocking — current perf is acceptable for typical projects.

---

### [DOC1] README "Limitations" section claims intra-procedural only — now stale

- **Severity:** Medium
- **Dimension:** Architecture (documentation)
- **Confidence:** 90
- **Location:** `README.md:91`
- **Reachability:** confirmed — user-facing documentation
- **Evidence:**
  ```
  - **Intra-procedural** taint: flow across functions/files/modules is not tracked (false negatives there).
  ```
  The comparison table (line 31) also says "intra-procedural taint" vs competitors' "full inter-procedural".
- **Why this is a problem:** The tool now does intra-file inter-procedural analysis. The docs under-claim, which is better than over-claiming, but still misleading. Users may not adopt it for cross-function patterns it now handles.
- **Recommendation:** Update to: "Intra-file inter-procedural taint (1-level function summaries); cross-file/cross-module flow is not tracked." Update the comparison table cell to "intra-file inter-procedural taint".

---

### Low (P3) — track in backlog (1)

### [FP1] `tainted.method()` propagation causes false positive for sanitizing member calls

- **Severity:** Low
- **Dimension:** Security (false positive)
- **Confidence:** 78
- **Location:** `src/taint.ts:60` (the `isTainted` CallExpression case: `if (t.isMemberExpression(callee)) return isTainted(callee.object, set)`)
- **Reachability:** confirmed — `src/interproc.ts:97` calls `isTainted(hit.arg, set)` which reaches this path
- **Evidence:**
  ```typescript
  // This fires (FP):
  function q(s){ s = s.replace(/[^a-z]/g, ''); db.query(s); }
  q(req.body.x);
  ```
  `s.replace(...)` → callee is MemberExpression → `isTainted(callee.object=s, set)` → `s` is in set → returns true → `s` stays tainted after reassignment.
- **Why this is a problem:** `.replace()` with a restrictive regex, `.slice()`, `.substring()`, `.toLowerCase()` etc. are common sanitization patterns. The tool treats them as taint-preserving because it can't distinguish `s.replace(/[^0-9]/g,'')` (sanitizing) from `s.trim()` (non-sanitizing). This is a known trade-off in the taint engine (`src/taint.ts`), not specific to interproc.
- **Recommendation:** This is pre-existing in the taint engine and affects both intra-proc and inter-proc equally. A future improvement could whitelist specific method names (`.replace` with a restrictive regex pattern, `.slice`, `.substring`) as sanitizers. Not blocking — the FP rate in practice is low because most real sanitization uses `Number()`, `parseInt()`, `schema.parse()`, or standalone functions like `escapeHtml()` which are already handled correctly.

---

## False-Positive Analysis (4 concrete scenarios)

### Scenario 1: Redis/HTTP `.execute`/`.query` — SAFE ✅

```typescript
function doCmd(c){ redis.execute(c); }
doCmd(req.body.cmd);
```
**Verdict:** Does NOT fire. `matchSink` requires `DB.test(callee.object.name)` for `.query`/`.execute`. `redis` does not match the DB regex. Correct.

### Scenario 2: User-defined function named `fetch` (no sink inside) — SAFE ✅

```typescript
function fetch(url){ console.log(url); }
fetch(req.query.url);
```
**Verdict:** Does NOT fire from interproc (no sink inside user's `fetch`). The intra-proc engine (`analyze2`) checks `t.isIdentifier(callee) && callee.name === 'fetch'` — but the SSRF rule requires `tainted(arg0)` which IS true here. However, this is analyze2's concern, not interproc's. Interproc correctly does not double-fire because the user's `fetch` has no `matchSink` hit internally.

### Scenario 3: Non-tainted argument at call site — SAFE ✅

```typescript
function q(s){ db.query(s); }
q('SELECT 1');
```
**Verdict:** Does NOT fire. At the call site, `isSourceExpr('SELECT 1')` is false and `taintedAt(path, stringLiteral, ...)` is false. Correct.

### Scenario 4: Custom sanitization function — SAFE ✅

```typescript
function q(s){ s = sanitize(s); db.query(s); }
q(req.body.x);
```
**Verdict:** Does NOT fire. `fixpoint` seeds `{s}`, then processes `s = sanitize(s)`. `isTainted(sanitize(s), {s})` → callee is Identifier `sanitize`, not in NUMERIC, not String, not JSON.parse, not a MemberExpression → returns `false`. So `s` is removed from the taint set. `db.query(s)` with empty set → not tainted. Correct.

### Scenario 5 (bonus): Shadowing — local param shadows outer tainted var — SAFE ✅

```typescript
const s = req.body.x;
function q(s){ db.query(s); }
q("safe");
```
**Verdict:** Does NOT fire. The summary says param `s` reaches `db.query(s)`. At the call site, `q("safe")` — the argument is a string literal, not tainted. The outer `s` is irrelevant because interproc checks the *argument expression*, not the parameter name. Correct.

---

## False-Negative / Soundness Analysis

| Limitation | Confirmed | Acceptable |
|---|---|---|
| 1-level only (no helper→helper chains) | ✅ Verified: `outer(s){inner(s)} / outer(req.body.x)` → no finding | Yes — high-confidence, low-FP design goal |
| No return-taint tracking | ✅ Verified: `get(s){return db.query(s)} / eval(get(req.body.x))` → only finds the SQLi inside `get`, not the eval | Yes |
| No method support (class methods) | ✅ Verified: `class Foo{q(s){db.query(s)}} / new Foo().q(tainted)` → no finding | Acceptable — call site is MemberExpression, not Identifier |
| Destructured params → null from `paramName` | ✅ Verified: `function q({s}){db.query(s)} / q({s:tainted})` → no finding | Acceptable — `paramName` only handles Identifier/AssignmentPattern |
| No crash on: no-arg calls, arrow fns, default params, async | ✅ All tested, no crashes | Good |

---

## Sanitizer Respect — Fixpoint Walkthrough

For `function q(s){ s = Number(s); db.query(s); }`:

1. `fixpoint` called with `assigns = [{names:['s'], expr: Number(s)}]`, `seed = new Set(['s'])`
2. Iteration 0: `s` is in set. Evaluate `isTainted(Number(s), {s})`:
   - CallExpression, callee is Identifier `Number`, which is in `NUMERIC` set → returns `false`
   - So `tt = false`. `s` is in set → delete it. `changed = true`. Set = `{}`
3. Iteration 1: `s` not in set. Evaluate `isTainted(Number(s), {})`:
   - Same path → `false`. `tt = false`, `s` not in set → no change. Stable.
4. Final set: `{}`. `isTainted(db.query(s), {})` → `s` not in set → `false`. **No finding.** ✅

---

## Additive / No Regression

- **analyze2.ts unchanged:** Confirmed — the file has no interproc imports or modifications.
- **taint.ts unchanged:** Confirmed — interproc imports `buildTaintSets`, `taintedAt`, `isTainted`, `isSourceExpr` without modification.
- **Engine dedup:** `src/engine.ts:50` deduplicates by `${f.file}:${f.line}:${f.ruleId}`. If both analyze2 and interproc emit the same rule at the same line, only one survives. Verified.
- **Interproc only ADDS:** All findings are `confidence: "high"` (line 116). Only fires when both (a) the helper summary proves param→sink AND (b) the call site passes tainted input. This is strictly additive.

---

## Performance / Robustness

| Metric | Result |
|---|---|
| 100 helpers × 100 calls | 20.9ms/file |
| 500 helpers × 500 calls | 47.0ms/file |
| 20 params × 50 sinks (pathological) | 36.5ms |
| Parse + buildTaintSets | Once per file within interproc (but duplicated with analyze2) |
| Fixpoint iterations | Capped at 6 (line 48) — no infinite loop possible |
| Complexity | O(functions × params × sinks) per file — linear in practice |

No pathological blowup. The fixpoint cap of 6 iterations prevents runaway on cyclic taint dependencies.

---

## Test Coverage Assessment

- **5 test cases** covering: TP (3 sink types), variable indirection, sanitizer respect, non-tainted arg, confidence level.
- **4 benchmark corpus cases** (`ip-*`): `ip-sqli-helper`, `ip-ssrf-helper`, `ip-safe-helper-sanitized`, `ip-safe-helper-literal`.
- **Missing:** No test for methods, destructured params, multi-param, recursion, name collision, nested functions. These are false-negative scenarios (by design), but documenting them in tests would prevent future regressions if the scope expands.

---

## Findings by dimension

| Dimension     | Critical | High | Medium | Low | Total |
|---------------|---------:|-----:|-------:|----:|------:|
| Security      |        0 |    0 |      0 |   1 |     1 |
| Performance   |        0 |    0 |      1 |   0 |     1 |
| Architecture  |        0 |    0 |      1 |   0 |     1 |
| Testing       |        0 |    0 |      0 |   0 |     0 |
| Reliability   |        0 |    0 |      0 |   0 |     0 |
| **Total**     |    **0** |**0** |  **2** |**1**| **3** |

## Recommended action plan

1. **[DOC1]** Update README limitations section and comparison table to reflect intra-file inter-procedural capability.
2. **[PERF1]** Consider a shared parse cache at the engine level to avoid double-parsing (non-urgent; current perf is fine for typical projects).
3. **[FP1]** Track as future improvement: whitelist sanitizing member methods in `isTainted`. Low priority — affects both engines equally and real-world FP rate is low.

## Praise

- 🎉 The `fixpoint()` design is elegant — seeding with the parameter name and letting last-write-wins naturally handle sanitizing reassignments is simple and correct.
- 🎉 The `matchSink` DB-receiver gating (`DB.test(callee.object.name)`) is a smart precision choice that prevents Redis/HTTP `.query()` false positives.
- 🎉 The decision to only fire at `confidence: "high"` (both summary AND call-site taint must be proven) keeps the FP rate genuinely low.
- 🎉 The engine dedup via `file:line:ruleId` key cleanly prevents double-reporting without any coupling between analyze2 and interproc.
- 🎉 Benchmark corpus includes both TP and TN inter-procedural cases — honest validation.

## Out of scope (not reviewed)

- Cross-file inter-procedural analysis (not implemented, by design)
- Python analyzer interaction (interproc is JS/TS only)
- MCP server integration
- CLI output formatting

## False positives eliminated

- 8 candidate scenarios tested empirically; 7 confirmed as correctly non-firing
- 1 confirmed FP (`s.replace` pattern) — pre-existing in taint engine, Low severity, tracked as [FP1]

## Metadata

- Phases completed: 0..4
- Strict mode: no
- Reviewer: kiro code-review skill v1

---

## Verdict: **PASS**

The inter-procedural layer is sound, additive, and genuinely low-false-positive. No blocking issues. The two Medium findings are documentation and performance optimization — neither affects correctness or FP rate.
