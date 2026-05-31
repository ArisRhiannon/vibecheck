# Code Review Report

**Target:** New Python support in vibecheck SAST tool (src/python.py, src/python.ts, benchmark py-* cases, test/python.test.ts, engine integration)
**Strategy:** medium
**Dimensions:** Security, Reliability, Testing
**Confidence threshold:** 75
**Generated:** 2026-05-31T04:29Z

## Executive summary

The Python taint engine is well-designed and honest — real AST parsing, real taint propagation, no theater. The bridge is robust and injection-safe. However, three taint propagation gaps create **real bypasses** that an attacker (or an AI agent) could inadvertently trigger: tuple unpacking, plain function calls, and closures all silently lose taint. The highest-priority fix (tuple unpack) is 2 lines.

## Findings

### High (P1) — fix before next release (1)

#### [SEC1] Tuple/list unpacking does not propagate taint — real bypass

- **Severity:** High
- **Dimension:** Security
- **Confidence:** 90
- **Location:** `src/python.py:62-64`
- **CWE:** CWE-1321 (incomplete data flow tracking)

Tuple unpacking (`a, b = request.form['a'], request.form['b']`) produces an `ast.Tuple` RHS node. `is_tainted()` has no handler for `ast.Tuple`/`ast.List` and returns `False`, so ALL unpacked variables are marked clean regardless of their actual source.

**Concrete input that escapes detection:**
```python
def handler():
    name, age = request.form['name'], request.form['age']
    cursor.execute(f"SELECT * FROM users WHERE name='{name}'")  # SQLi — NOT detected
```

**Fix (2 lines in `is_tainted`):**
```python
if isinstance(node, (ast.Tuple, ast.List)):
    return any(is_tainted(e, tset) for e in node.elts)
```

---

### Medium (P2) — plan for next sprint (2)

#### [SEC2] Plain function calls (non-method) do not propagate taint

- **Severity:** Medium
- **Dimension:** Security
- **Confidence:** 78
- **Location:** `src/python.py:48-53`

`result = func(tainted)` where `func` is a plain Name (not `obj.method`) returns `False` from `is_tainted`. Method calls (`obj.method(tainted)`) correctly propagate. This inconsistency means helper functions silently break taint chains.

**Concrete input:**
```python
def handler():
    data = request.args['x']
    q = build_query(data)  # plain call — taint lost
    cursor.execute(q)       # NOT detected
```

**Fix:** Add before the final `return False` in the `ast.Call` branch:
```python
if isinstance(node.func, ast.Name) and d not in NUMERIC:
    return any(is_tainted(a, tset) for a in node.args)
```

#### [SEC3] Closure/nested function variables not in child scope taint set

- **Severity:** Medium
- **Dimension:** Security
- **Confidence:** 75
- **Location:** `src/python.py:66-86`

Variables tainted in an outer function are invisible to nested functions because `taint_sets` computes independent per-scope sets with no inheritance.

**Concrete input:**
```python
def handler():
    payload = request.data
    def process():
        pickle.loads(payload)  # NOT detected
    process()
```

**Fix:** Seed each child scope's taint set with its parent scope's final set.

---

### Low (P3) — track in backlog (1)

#### [TEST1] Benchmark does not exercise identified bypasses

- **Severity:** Low
- **Dimension:** Testing
- **Confidence:** 80
- **Location:** `benchmark/corpus.ts` (py-* section)

The 13 Python benchmark cases only test direct source→sink flows. No tuple unpack, closure, or plain-call cases exist. The "100% recall" claim is honest against the corpus but doesn't reflect real-world FN rate.

**Fix:** Add failing cases for each bypass, then fix the engine to pass them.

---

## Findings by dimension

| Dimension     | Critical | High | Medium | Low | Total |
|---------------|---------:|-----:|-------:|----:|------:|
| Security      |        0 |    1 |      2 |   0 |     3 |
| Performance   |        0 |    0 |      0 |   0 |     0 |
| Architecture  |        0 |    0 |      0 |   0 |     0 |
| Testing       |        0 |    0 |      0 |   1 |     1 |
| Reliability   |        0 |    0 |      0 |   0 |     0 |
| **Total**     |    **0** |**1** |  **2** |**1**| **4** |

## Recommended action plan

1. **[SEC1] Fix tuple/list taint propagation** — 2-line fix, highest impact, no FP risk.
2. **[SEC2] Fix plain-call taint propagation** — consistent with existing method-call behavior.
3. **[SEC3] Implement closure taint inheritance** — seed child scopes from parent.
4. **[TEST1] Add bypass cases to benchmark** — will honestly surface FN rate and validate fixes.
5. 💡 (below threshold) Consider checking `yaml.load` Loader value against a safelist rather than just checking presence.

## Praise

- 🎉 The bridge design (`src/python.ts`) is excellent — stdin JSON, graceful degradation on missing python3, guarded JSON.parse, no shell injection surface. Textbook subprocess integration.
- 🎉 The confidence model (high=taint-backed, medium=non-literal) is honest and well-calibrated. `eval(x)` at medium vs `eval(request.form['x'])` at high is exactly right.
- 🎉 The `NUMERIC` sanitizer set correctly handles `int()`/`float()`/`bool()` — the reassignment test proves last-write-wins works.
- 🎉 The f-string and %-format propagation is correct and handles the common SQLi patterns well.
- 🎉 README limitations section is genuinely honest — no over-claims, fair comparison table, "curated benchmark" disclaimer.

## Out of scope (not reviewed)

- JS/TS taint engine (`src/analyze2.ts`, `src/taint.ts`) — validated separately, not part of this review
- Secret/env detectors — orthogonal to Python support
- MCP server integration — not changed by this PR
- Performance benchmarking of the Python subprocess spawn

## False positives eliminated

- 4 candidates eliminated:
  1. subprocess kwarg bypass — not standard API usage (confidence 50)
  2. yaml.load FullLoader — edge case, below threshold (confidence 65)
  3. eval/exec medium-confidence on non-literal — working as designed
  4. Bridge malformed field handling — graceful, not a crash

## Metadata

- Phases completed: 0, 1, 2, 3, 4
- Strict mode: no
- Reviewer: kiro code-review skill v1

---

## Verdict: **NEEDS-FIX**

[SEC1] is a High-severity taint bypass with a trivial fix. The tool's core value proposition is "low false positives with real taint" — a 2-line gap that silently drops taint on tuple unpacking (an idiomatic Python pattern) should be fixed before claiming production-ready Python support.
