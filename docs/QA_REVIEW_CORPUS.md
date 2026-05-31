# Code Review Report

**Target:** Corpus-driven precision fix (`isRelativeRedirect`/`leadingLiteral` in `src/analyze2.ts`), corpus harness (`scripts/corpus.ts`), documentation (`docs/CORPUS.md`)  
**Strategy:** small  
**Dimensions:** Security, Reliability, Testing, Documentation  
**Confidence threshold:** 75  
**Generated:** 2026-05-31T06:35:11Z

## Executive summary

The precision fix correctly eliminates false positives for multi-character relative paths (`/user/…`, `/dashboard/…`) but introduces a **P1 false-negative bypass**: `res.redirect('/' + req.query.x)` where `req.query.x = '/evil.com'` produces `'//evil.com'` (protocol-relative open redirect) and is now silently suppressed. The corpus harness and documentation are generally honest and well-structured, with one reproducibility gap (unpinned `master` ref).

## Findings

### High (P1) — fix before next release (1)

#### 🟠 [SEC1] Protocol-relative open redirect bypass via `'/' + userInput`

**`src/analyze2.ts:19-23`** — `isRelativeRedirect` suppresses the finding when the leading literal is `'/'`, but at runtime `'/' + '/evil.com'` = `'//evil.com'` which is a protocol-relative redirect to an attacker-controlled host.

**Attack scenario:**
```javascript
// Developer writes:
res.redirect('/' + req.query.next);
// Attacker visits: ?next=/evil.com
// Runtime: res.redirect('//evil.com') → browser navigates to evil.com
```

**Fix:** Change `isRelativeRedirect` to require the leading literal matches `/[^/]` (slash followed by a non-slash character):
```typescript
function isRelativeRedirect(node: t.Node): boolean {
  const p = leadingLiteral(node);
  return p !== null && /^\/[^/]/.test(p);
}
```

---

### Medium (P2) — plan for next sprint (2)

#### 🟡 [REL1] Unpinned `master` ref for OWASP/NodeGoat in corpus harness

**`scripts/corpus.ts:12`** — Using `ref: "master"` makes corpus results non-reproducible over time. Pin to a commit SHA.

#### 🟡 [TEST1] Test suite missing the bare-slash bypass case

**`test/openredirect.test.ts:8-10`** — Tests only cover `/user/` and `/dashboard/` prefixes. The dangerous `'/' + tainted` case is untested, giving false confidence in the fix.

---

### Low (P3) — track in backlog (2)

#### 🟢 [REL2] Clone failure produces no marker in corpus output

**`scripts/corpus.ts:22-23`** — Skipped repos leave no trace in `corpus-raw.json`.

#### 🟢 [DOC1] CORPUS.md fix description doesn't acknowledge single-slash limitation

**`docs/CORPUS.md:42-44`** — The fix description is technically accurate but incomplete regarding the `'/' + userInput` edge case.

---

## Findings by dimension

| Dimension     | Critical | High | Medium | Low | Total |
|---------------|----------|------|--------|-----|-------|
| Security      | 0        | 1    | 0      | 0   | 1     |
| Reliability   | 0        | 0    | 1      | 1   | 2     |
| Testing       | 0        | 0    | 1      | 0   | 1     |
| Documentation | 0        | 0    | 0      | 1   | 1     |
| **Total**     | **0**    | **1**| **2**  | **2**| **5** |

## Recommended action plan

1. **[SEC1] Fix `isRelativeRedirect`** — change the regex to `/^\/[^/]/` so that a bare `'/'` prefix is NOT considered safe. This is the only blocking issue.
2. **[TEST1] Add test case** for `'/' + req.query.x` — should expect `true` (flagged).
3. **[REL1] Pin NodeGoat** to a specific commit SHA in `scripts/corpus.ts`.
4. **[DOC1] + [REL2]** — minor doc/robustness improvements, non-blocking.

## Praise

- 🎉 The `leadingLiteral` recursive descent through `BinaryExpression.left` is elegant and handles template literals + concatenation uniformly.
- 🎉 The corpus documentation (`docs/CORPUS.md`) is refreshingly honest — it separates "detector precision" from "production-exploitable precision", explicitly lists limitations, and acknowledges the small sample size. This is better transparency than most tools provide.
- 🎉 The corpus harness records the exact SHA at clone time, which is good practice for auditability even though the input ref isn't fully pinned.
- 🎉 The benchmark suite (78 cases, 100/100) is comprehensive and includes adversarial/tricky-safe cases. All tests pass.

## Out of scope (not reviewed)

- Other detectors (SQLI, SSRF, XSS, etc.) — not part of this change
- Python/Go analyzers — not touched by this fix
- MCP server / CLI — not relevant

## False positives eliminated

- 2 candidates dropped:
  - [SEC2] `'//evil.com'` literal: not a bypass because `tainted()` gates the rule first (no user input in a literal)
  - [SEC3] Backslash trick: correctly handled — `'\\'` doesn't start with `/` so `isRelativeRedirect` returns false and the taint check flags it

## Verification

- `bun test`: **48/48 pass** ✅
- `bun benchmark/run.ts`: **78 cases, Precision 100%, Recall 100%** ✅
- The bypass [SEC1] is NOT caught by existing tests because no test case covers `'/' + tainted`.

## Metadata

- Phases completed: 0..4
- Strict mode: no
- Reviewer: kiro code-review skill v1
