# VALIDATION — vibecheck v0.2

**Date:** 2026-05-31T03:59Z  
**Validator:** Independent automated validator (Kiro)  
**Commit:** HEAD on main branch

---

## Build & Test Results

### `bun run typecheck`
```
$ tsc --noEmit
(exit 0 — no errors)
```

### `bun test`
```
26 pass, 0 fail, 87 expect() calls
Ran 26 tests across 7 files. [1.89s]
```

### `bun benchmark/run.ts`
```
Corpus: 47 labeled cases (vulnerable + safe + tricky-safe)
- Precision: 100.0% (TP 26 / FP 0)
- Recall: 100.0% (TP 26 / FN 0)
- F1: 100.0%

Per-rule breakdown:
| rule                    | TP | FP | FN |
|-------------------------|----|----|----|
| VC-COOKIE-INSECURE      | 1  | 0  | 0  |
| VC-CORS-WILDCARD        | 2  | 0  | 0  |
| VC-JWT-NONE             | 1  | 0  | 0  |
| VC-JWT-UNPINNED         | 1  | 0  | 0  |
| VC-NEXT-PUBLIC-SECRET   | 1  | 0  | 0  |
| VC-OPEN-REDIRECT        | 1  | 0  | 0  |
| VC-PATH-TRAVERSAL       | 1  | 0  | 0  |
| VC-RCE-CHILD-PROCESS    | 2  | 0  | 0  |
| VC-RCE-EVAL             | 3  | 0  | 0  |
| VC-SQLI                 | 5  | 0  | 0  |
| VC-SSRF                 | 2  | 0  | 0  |
| VC-STACK-EXPOSURE       | 1  | 0  | 0  |
| VC-SUPABASE-SERVICE-ROLE| 1  | 0  | 0  |
| VC-XSS-DOM              | 3  | 0  | 0  |
| VC-XSS-REACT            | 1  | 0  | 0  |

All cases match their labels.
```

### Dependencies
```
[ '@babel/parser', '@babel/traverse', '@babel/types' ]
```
Confirmed: real @babel/* dependencies (by design for AST-based analysis).

### License
- `package.json` → `"license": "MIT"`
- `LICENSE` file → standard MIT text, © 2026 Aris Rhiannon ✓

---

## Claims Verification

| # | Claim | PASS/FAIL | Evidence |
|---|-------|-----------|----------|
| 1 | **Real AST**: src/ast.ts uses @babel/parser; TSX+decorators+dynamic-import+tagged-template+JSX parses successfully | **PASS** | `src/ast.ts` imports `parse` from `@babel/parser`, uses `decorators-legacy` plugin. `test/ast.test.ts` passes: parses TSX snippet with all four constructs, traverses to find `dangerouslySetInnerHTML` JSXAttribute. Test suite confirms (6ms). |
| 2 | **Taint is real**: `knex.raw(q)` with tainted `q` → VC-SQLI high; `Number(req.query.id)` sanitized → no high/medium SQLI; parameterized `$1` → no SQLI | **PASS** | CLI `--json` on temp dirs: (a) `const q = req.query.q; knex.raw(q)` → `VC-SQLI` severity=critical confidence=high. (b) `const id = Number(req.query.id); db.query(...)` → only `VC-SQLI` at confidence=review (not high/medium). (c) `db.query('SELECT * FROM u WHERE id = $1',[x])` → zero findings. |
| 3 | **Confidence gating**: `--ci` exits 0 on review-only; exits 1 on high-confidence taint. MCP returns high-confidence only by default. | **PASS** | (a) Route-only file (`app.get('/admin',...)`) → `--ci` exit 0 (only VC-ROUTE-NO-AUTH at review confidence). (b) Tainted SQLI file → `--ci` exit 1. (c) `src/mcp.ts` line: `r.findings.filter((f) => f.confidence === "high")` when `includeAll` is not set. |
| 4 | **Benchmark integrity**: corpus contains genuine safe negatives; run.ts computes TP/FP/FN correctly | **PASS** | `benchmark/corpus.ts` contains 47 cases including tricky-safe: parameterized SQL (`$1`), tagged template (`sql\`...\``), numeric sanitization (`Number()`), schema validation (`.parse()`), ORM `.exec()`, RegExp `.exec()`, anon/publishable keys (`NEXT_PUBLIC_SUPABASE_ANON_KEY`), hardened cookies (`secure:true, sameSite:'lax'`), allowlisted CORS, pinned JWT. `run.ts` correctly: iterates corpus, computes emitted rule IDs per case, counts TP (expected∩emitted), FP (emitted−expected), FN (expected−emitted), derives precision/recall/F1. |
| 5 | **Honesty**: README says NOT a Semgrep/CodeQL replacement; states JS/TS-only + intra-procedural limits; benchmark described as curated | **PASS** | README § "What it is — and what it is not": "vibecheck is **not** a replacement for Semgrep or CodeQL". Limitations section: "JS/TS/JSX/TSX only in v0.2", "Intra-procedural taint: flow across functions/files/modules is not tracked". Benchmark section: "This benchmark is curated (not 'scanned N real repos')". No "beats industry standard" claim found. |

---

## Rule List (implemented & benchmarked)

**Taint-backed (high confidence when source→sink proven):**
- VC-RCE-EVAL
- VC-RCE-CHILD-PROCESS
- VC-SQLI
- VC-XSS-REACT
- VC-XSS-DOM
- VC-SSRF
- VC-PATH-TRAVERSAL
- VC-OPEN-REDIRECT

**AST config analysis:**
- VC-CORS-WILDCARD
- VC-JWT-NONE
- VC-JWT-UNPINNED
- VC-COOKIE-INSECURE
- VC-STACK-EXPOSURE

**Provenance / secrets:**
- VC-SECRET-* (8 patterns)
- VC-ENV-COMMITTED / VC-ENV-DRIFT / VC-ENV-MISSING
- VC-NEXT-PUBLIC-SECRET
- VC-SUPABASE-SERVICE-ROLE

**Advisory (review confidence, excluded from --ci by default):**
- VC-ROUTE-NO-AUTH
- VC-INPUT-NO-VALIDATION

---

## Limitations Acknowledged

1. JS/TS/JSX/TSX only (v0.2)
2. Intra-procedural taint only — no cross-function/file/module tracking
3. Secret/config rules are pattern-based where AST adds no value
4. Benchmark is curated (47 cases), not a real-world corpus scan
5. Not a proof of security — complement with Semgrep/CodeQL

---

## Over-claims Assessment

**None identified.** The README is appropriately modest:
- Explicitly disclaims being a replacement for deeper tools
- States the benchmark is curated, not "scanned N real repos"
- Acknowledges intra-procedural limitation (false negatives for cross-function flows)
- No "beats industry standard" language

**Minor note:** The README states "43 cases" but the benchmark now reports **47 cases** — this is a stale number in the README (the corpus grew). Not an over-claim, just a documentation lag.

---

## VALIDATION: PASS


## v0.2.1 — Python multi-language increment (independent validation: PASS)

An independent validator re-ran the tool and confirmed, with its own adversarial snippets:
- **Real parser:** `src/python.py` uses the stdlib `ast` (`ast.parse`/`ast.walk`, 0 regex); `src/python.ts` shells to `python3` over stdin.
- **Taint-backed true positives:** 10/10 self-written vulnerable Python snippets flagged with the correct `VC-PY-*` id at **high** confidence (CMDI, SQLi, RCE eval/exec, deserialize, yaml, SSTI, open-redirect, path).
- **True negatives:** parameterized `execute`, `subprocess.run([list])`, `yaml.safe_load`, positional tuple-unpack → **zero high/medium** findings (medium-on-non-literal is by design, excluded from `--ci`).
- **Benchmark:** `bun benchmark/run.ts` → **62 cases, precision/recall/F1 = 100%, 0 FP**, Python rows present.
- **No JS regression:** `bun test` → 30 pass / 0 fail. **Graceful without python3:** `pythonFindings` returns `[]` (no throw); JS scanning unaffected.
- **No over-claims:** intra-procedural limit, curated benchmark, python3 requirement, and "not a Semgrep/CodeQL replacement" all stated.

QA (code-reviewer) before this: NEEDS-FIX with 0 P0, 1 P1 (tuple-unpack taint loss) — fixed and regression-tested. Verdict: **VALIDATION: PASS**.
