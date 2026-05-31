# Code Review Report

**Target:** vibecheck — offline TypeScript security scanner (full codebase)  
**Strategy:** medium  
**Dimensions:** Detection correctness, False positives, ReDoS/Termination, MCP correctness, CLI/exit codes, Honesty  
**Confidence threshold:** 75  
**Generated:** 2026-05-31T03:00:00Z  

## Executive summary

The tool is **well-built, honest, and functional**. All 24 advertised rules have real detector implementations that fire on realistic vulnerable code and stay quiet on safe code. The README's threat model section accurately describes the heuristic limitations. No ReDoS vulnerabilities found. MCP and CLI work correctly. The main actionable issue is false positives from `exec()` matching ORM/regex method calls (DET3), and `service_role` matching comments (DET5).

## Verdict: **PASS** (with minor issues to track)

No critical or high-severity findings in the tool itself. The issues found are medium/low false-positive risks that don't undermine the tool's core value proposition.

---

## Findings

### Medium (P2) — plan for next sprint (2)

#### [DET3] `exec(` regex matches ORM `.exec()` and `RegExp.exec()` — false positives

- **Severity:** Medium
- **Confidence:** 92
- **Location:** `src/codescan.ts:36`
- **Evidence:**
  ```typescript
  /\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(/g
  ```
  Fires on `User.find().exec()`, `/pattern/.exec(str)`, `knex(...).exec()` because `\b` matches
  after `.` (non-word char). `firstArgIsLiteral` returns false for these (arg is not a plain string
  literal), so the finding is emitted.
- **Failing input:** `const users = await User.find({ active: true }).exec();`
- **Fix:** Add negative lookbehind for `.`: use `/(?<!\.\s*)(?:exec|execSync|...)\s*\(/g` or check
  that the character before the match is not `.`. Alternatively, require `exec`/`spawn` to be
  preceded by `require("child_process")` or imported from `child_process` in the file.

#### [DET5] `service_role` fires on comments and documentation

- **Severity:** Medium
- **Confidence:** 88
- **Location:** `src/routes.ts:58-62`
- **Evidence:**
  ```typescript
  const idx = c.search(/service_role/i);
  ```
  Fires on `// Never expose the service_role key to clients` — a comment warning AGAINST the
  practice triggers a high-severity finding.
- **Failing input:** `// WARNING: do not use service_role key here`
- **Fix:** Check that the match is not on a comment-only line. Simple heuristic: skip if the line
  containing the match starts with `//` or `*` (inside block comment). Or require `service_role`
  to appear in a string literal or assignment context.

---

### Low (P3) — track in backlog (4)

#### [DET1] Shannon entropy threshold (3.5) differs from PLAN.md (~4.0)

- **Severity:** Low
- **Confidence:** 85
- **Location:** `src/secrets.ts:30` vs `docs/PLAN.md` AC2.2
- **Fix:** Update PLAN.md to reflect the actual implementation values (3.5 bits, 12+ chars).

#### [DET2] SQLI-CONCAT misses parenthesized expressions after `+`

- **Severity:** Low
- **Confidence:** 90
- **Location:** `src/codescan.ts:52-54`
- **Failing input:** `"SELECT * FROM users WHERE id=" + (req.params.id)`
- **Fix:** Broaden trailing char class to `[A-Za-z_$(]`.

#### [DET4] JWT-UNPINNED 250-char lookahead may miss algorithms in formatted code

- **Severity:** Low
- **Confidence:** 78
- **Location:** `src/codescan.ts:68-69`
- **Failing input:** `jwt.verify(token, secret, { issuer: "x", audience: "y", /* ...200+ chars... */ algorithms: ["RS256"] })`
- **Fix:** Increase window to 500 or use `spanTo` to find the closing `)`.

#### [DET8] Nested template literals can confuse `spanTo` scope detection

- **Severity:** Low
- **Confidence:** 76
- **Location:** `src/routes.ts:17-27`
- **Failing input:** `` app.get("/x", (req, res) => { const x = `${`inner`}`; res.json(x); }) ``
- **Fix:** Document as known limitation. Nested templates in route handlers are extremely rare.

#### [PERF1] `locate()` is O(n) per call — quadratic on files with many findings

- **Severity:** Low
- **Confidence:** 80
- **Location:** `src/walk.ts:72-81`
- **Fix:** Pre-compute line-start array, binary-search. Low priority given 1.5MB cap.

---

## Findings by dimension

| Dimension              | Critical | High | Medium | Low | Total |
|------------------------|----------|------|--------|-----|-------|
| Detection correctness  | 0        | 0    | 1      | 3   | 4     |
| False positives        | 0        | 0    | 1      | 0   | 1     |
| ReDoS / Termination    | 0        | 0    | 0      | 1   | 1     |
| MCP correctness        | 0        | 0    | 0      | 0   | 0     |
| CLI / exit codes       | 0        | 0    | 0      | 0   | 0     |
| Honesty                | 0        | 0    | 0      | 1   | 1     |
| Performance            | 0        | 0    | 0      | 1   | 1     |
| **Total**              | **0**    | **0**| **2**  | **5**| **7** |

---

## Bypass analysis summary

| Bypass technique | Caught? | Expected? |
|-----------------|---------|-----------|
| RCE via bracket notation (`global["eval"](x)`) | ❌ No | Yes — acknowledged limitation |
| SQLi via multi-statement building (`q += x`) | ❌ No | Yes — acknowledged limitation |
| Secret split across variables | ❌ No | Yes — acknowledged limitation |
| Base64-encoded secret | ❌ No | Yes — acknowledged limitation |
| SQLi via parenthesized expr (`"SQL" + (x)`) | ❌ No | Minor gap, fixable |
| ORM `.exec()` false positive | ⚠️ FP | Fixable with lookbehind |

All missed bypasses are within the tool's stated threat model ("heuristic, not a full taint engine").

---

## Recommended action plan

1. **[DET3]** Fix `.exec()` false positives — add negative lookbehind or context check for child_process import. This is the highest-impact improvement.
2. **[DET5]** Skip `service_role` matches on comment-only lines to reduce false positives.
3. **[DET2]** Broaden SQLI-CONCAT trailing pattern to include `(`.
4. **[DET4]** Increase JWT lookahead window to 500 chars.
5. **[DET1]** Update PLAN.md to match actual thresholds.

---

## Praise

- 🎉 **Honest threat model.** The README explicitly states limitations and doesn't over-claim. The "review" severity for route-auth findings is exactly right — it flags for human review without blocking CI.
- 🎉 **Clean false-positive suppression.** The PLACEHOLDER regex, env-ref detection, and publishable-key exclusions show careful thought about what NOT to flag.
- 🎉 **`spanTo` is well-designed.** It handles string escaping, multiple quote types, and always terminates. The scope-based auth checking (only within the handler's own call span) is a smart approach that reduces noise.
- 🎉 **MCP implementation is correct and minimal.** Handles notifications properly, stays alive on stdin, flushes synchronously. The test actually spawns the process and validates JSON-RPC — real integration testing.
- 🎉 **Zero dependencies achieved.** No runtime deps, only type-checking devDeps. The tool does what it claims.
- 🎉 **`--ci` default threshold is "high"** — review/medium findings don't block, which is the right default for a heuristic tool.
- 🎉 **Every regex is ReDoS-safe.** No catastrophic backtracking patterns found. Character-class negations (`[^"'\n]*`) are bounded by line/quote terminators.

---

## Out of scope (not reviewed)

- Runtime performance benchmarking (no execution environment for timing)
- Actual CI pipeline behavior (`.github/workflows/ci.yml` not deeply reviewed)
- License compliance (MIT)
- Cross-platform path handling (Windows `\` separators — `walk.ts` normalizes to `/`)

## False positives eliminated

- 5 candidate findings dropped during verification:
  1. "MCP id:0 handling" — verified correct on re-read
  2. "eval('') is safe" — by design, literal strings are not RCE
  3. "SQLI regex backtracking" — bounded by `[^"'\n]*`, no nested quantifiers
  4. "spanTo template literal issue" — backtick-quoted content correctly skipped in common cases
  5. "NEXT_PUBLIC false positive on anon keys" — explicitly excluded by `/PUBLISHABLE|ANON|PUBLIC_KEY/`

## Metadata

- Phases completed: 0, 1, 2, 3, 4
- Strict mode: no
- Reviewer: kiro code-review skill v1
