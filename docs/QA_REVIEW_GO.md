# Code Review Report — Go Support in vibecheck

**Target:** `src/go.go`, `src/go.ts`, `test/go.test.ts`, `benchmark/corpus.ts`, engine wiring  
**Strategy:** medium (focused additive feature)  
**Dimensions:** Security (false positives), Reliability, Testing, Architecture  
**Confidence threshold:** 75  
**Generated:** 2026-05-31T06:13Z

---

## Executive summary

The Go analyzer is a well-engineered addition: real `go/parser` + `go/ast`, intra-procedural taint, graceful degradation when `go` is absent, source-hash-keyed binary cache, and JSON-over-stdin (no command injection). **One significant false-positive bug** exists: parameterized SQL queries (`db.Query("... $1", taintedArg)`) fire VC-GO-SQLI because `anyTainted` checks ALL args including bind parameters. A secondary FP exists with `.Do` suffix matching non-HTTP clients. Both are fixable with targeted changes.

---

## Findings

### 🔴 Critical (P0) — must fix immediately (0)

None.

### 🟠 High (P1) — fix before next release (1)

#### [PERF1] Parameterized SQL queries flagged as SQL injection (FALSE POSITIVE)

- **Severity:** High
- **Dimension:** Security (false positive)
- **Confidence:** 100
- **Location:** `src/go.go:140-143`
- **Reachability:** confirmed — any Go file with `db.Query("SELECT ... $1", userInput)` triggers this
- **Evidence:**
  - Test snippet:
    ```go
    package main
    import "net/http"
    func h(r *http.Request) {
        name := r.FormValue("name")
        db.Query("SELECT * FROM users WHERE name = $1", name)
    }
    ```
  - Result: `VC-GO-SQLI` fires at line 5 — **incorrect**, this is a safe parameterized query.
  - Root cause in `src/go.go`:
    ```go
    if x, ok3 := sel.X.(*ast.Ident); ok3 && dbRecv[strings.ToLower(x.Name)] && anyTainted(c.Args, set) {
    ```
    `anyTainted(c.Args, set)` checks ALL arguments. For parameterized queries, the SQL string (arg[0]) is a literal, but bind parameters (arg[1:]) are tainted. The check should only fire when **arg[0] (the SQL string) is tainted**.
- **Why this is a problem:** Parameterized queries are the *recommended fix* for SQL injection. Flagging them as vulnerable is a high-impact false positive that erodes user trust and makes the tool's own remediation advice contradictory.
- **Recommendation:**
  ```go
  // Replace anyTainted(c.Args, set) with isTainted(c.Args[0], set) for SQL sinks:
  if x, ok3 := sel.X.(*ast.Ident); ok3 && dbRecv[strings.ToLower(x.Name)] && len(c.Args) > 0 && isTainted(c.Args[0], set) {
  ```
- **Note:** The existing benchmark test `go-safe-param` passes only because `strconv.Atoi` sanitizes the value before it's passed as a bind param. Without that sanitizer, the FP manifests.

---

### 🟡 Medium (P2) — plan for next sprint (1)

#### [SEC2] `.Do` suffix matches non-HTTP clients (FALSE POSITIVE)

- **Severity:** Medium
- **Dimension:** Security (false positive)
- **Confidence:** 90
- **Location:** `src/go.go:149`
- **Reachability:** confirmed — any `*.Do(tainted)` call fires VC-GO-SSRF
- **Evidence:**
  - Test snippet:
    ```go
    package main
    import "net/http"
    func h(r *http.Request) {
        val := r.FormValue("key")
        redisClient.Do("GET", val)
    }
    ```
  - Result: `VC-GO-SSRF` fires — **incorrect**, this is a Redis command, not an HTTP request.
  - Code: `strings.HasSuffix(s, ".Do")` matches any receiver's `.Do` method.
- **Why this is a problem:** Redis, gRPC, and other clients use `.Do()` methods. Flagging them as SSRF is a false positive.
- **Recommendation:** Gate `.Do` on the receiver name matching HTTP-related identifiers (e.g., `client`, `http`, `httpClient`, `transport`) or require the receiver to be of a known HTTP type pattern:
  ```go
  if strings.HasSuffix(s, ".Do") {
      if sel2, ok := c.Fun.(*ast.SelectorExpr); ok {
          if x, ok2 := sel2.X.(*ast.Ident); ok2 {
              recv := strings.ToLower(x.Name)
              if strings.Contains(recv, "http") || recv == "client" || recv == "transport" {
                  // fire
              }
          }
      }
  }
  ```

---

### 🟢 Low (P3) — track in backlog (1)

#### [REL3] Multi-return assignments not tracked (known FN, undocumented for Go)

- **Severity:** Low
- **Dimension:** Reliability (false negative)
- **Confidence:** 85
- **Location:** `src/go.go:100-107`
- **Reachability:** confirmed — `result, _ := someFunc(tainted)` does not propagate taint to `result`
- **Evidence:**
  - `taintSet` only processes assignments where `len(as.Lhs) == len(as.Rhs)`.
  - Go's multi-return (`id, err := someFunc(x)`) has 2 LHS, 1 RHS → skipped.
  - This is acceptable for `strconv.Atoi` (sanitizer), but causes FN for `result, _ := unsafeTransform(tainted)`.
- **Why this is a problem:** It's a known limitation of intra-procedural analysis, but it's not documented in the Go-specific context. The VALIDATION.md and README mention "intra-procedural" limits for JS/TS but not specifically for Go's multi-return idiom.
- **Recommendation:** Add a note to README/docs acknowledging this Go-specific FN: "Multi-return assignments (`x, err := f(tainted)`) do not propagate taint through the called function."

---

## Findings by dimension

| Dimension     | Critical | High | Medium | Low | Total |
|---------------|---------:|-----:|-------:|----:|------:|
| Security (FP) |        0 |    1 |      1 |   0 |     2 |
| Reliability   |        0 |    0 |      0 |   1 |     1 |
| **Total**     |        0 |    1 |      1 |   1 |     3 |

---

## Test Results

- `bun test`: **46/46 pass** (includes 3 Go-specific tests)
- `bun benchmark/run.ts`: **75 cases, Precision 100%, Recall 100%, F1 100%, 0 FP**
- Go analyzer adds findings additively — no regression to JS/TS/Python rules

---

## False-Positive Probes (7 scenarios, all verified)

| # | Scenario | Expected | Actual | Verdict |
|---|----------|----------|--------|---------|
| FP1 | `redisClient.Query(tainted)` / `httpThing.Exec(tainted)` / `foo.Query(tainted)` | No fire | `[]` | ✅ PASS |
| FP2 | `db.Query("...$1", sanitized_id)` (strconv.Atoi) | No fire | `[]` | ✅ PASS |
| FP3 | `strconv.Atoi` → `fmt.Sprintf` → `db.Query` | No fire | `[]` | ✅ PASS |
| FP4 | `exec.Command("ls","-la")` / `exec.Command(constName)` | No fire | `[]` | ✅ PASS |
| FP5 | `c.Query("k")` (gin source, no sink) | No fire | `[]` | ✅ PASS |
| FP6 | `http.Redirect(w,r,"/dashboard")` / `http.Get("https://...")` | No fire | `[]` | ✅ PASS |
| FP7 | `db.Query("...$1", rawTaintedName)` (no sanitizer) | No fire | **FIRES** | ❌ **FP BUG** |

---

## True-Positive Verification (5 vuln classes)

| Rule | Snippet | Line | Confidence | Verdict |
|------|---------|------|------------|---------|
| VC-GO-CMDI | `exec.Command("sh","-c",r.FormValue("c"))` | 12 | high | ✅ |
| VC-GO-SQLI | `db.Query("SELECT "+tainted)` | 16 | high | ✅ |
| VC-GO-PATH | `os.Open(r.FormValue("f"))` | 19 | high | ✅ |
| VC-GO-SSRF | `http.Get(r.FormValue("u"))` | 22 | high | ✅ |
| VC-GO-OPEN-REDIRECT | `http.Redirect(w,r,tainted)` | 25 | high | ✅ |

---

## Taint Soundness

| Feature | Status | Notes |
|---------|--------|-------|
| Intra-procedural taint propagation | ✅ Works | Fixed-point iteration (6 rounds max) |
| `strconv.Atoi`/`ParseInt`/`ParseFloat`/`ParseBool` sanitizers | ✅ Works | Returns `false` from `isTainted` |
| `fmt.Sprintf` propagation | ✅ Works | Checks all args |
| `mux.Vars(r)["id"]` index expr | ✅ Works | `isSource` handles IndexExpr on mux.Vars |
| Gin sources (`c.Query`, `c.Param`, etc.) | ✅ Works | Receiver-gated by common names |
| Reassignment kills taint | ✅ Works | `x = tainted; x = "safe"` → untainted |
| Multi-return `id, _ := f(x)` | ⚠️ FN | Not tracked (len(Lhs)≠len(Rhs) skipped) |
| Cross-function taint | ⚠️ FN | Intra-procedural only (documented) |
| Method on tainted receiver | ✅ Works | `isTainted` on SelectorExpr checks `v.X` |

---

## Bridge Robustness (`src/go.ts`)

| Check | Status | Evidence |
|-------|--------|----------|
| Graceful when `go` absent | ✅ | Returns `[]`, no throw. `goAvailable()` → `false`. |
| Compile failure handled | ✅ | `r.status !== 0 || !existsSync(out)` → `resolved = null` → returns `[]` |
| Bad/empty stdout JSON | ✅ | `try { raw = JSON.parse(r.stdout); } catch { return []; }` |
| maxBuffer | ✅ | Set to 32 MB (`32 * 1024 * 1024`) |
| Binary cache keyed by source hash | ✅ | SHA-256 of `src/go.go` → first 16 hex chars in binary filename |
| No command injection via stdin | ✅ | Content passed as `input` to `spawnSync`, not argv. No shell. |
| Invalid Go files handled | ✅ | `parser.ParseFile` error → `continue` (skipped) |

---

## Recommended action plan

1. **[P1] Fix parameterized SQL FP** — Change `anyTainted(c.Args, set)` to `len(c.Args) > 0 && isTainted(c.Args[0], set)` for SQL sink detection. Add benchmark cases: `go-safe-param-raw` (tainted bind param, no sanitizer).
2. **[P2] Fix `.Do` SSRF FP** — Gate `.Do` on receiver name containing "http"/"client"/"transport" or similar heuristic.
3. **[P3] Document multi-return FN** — Add a note to README/docs about Go multi-return taint limitation.

---

## Praise

- 🎉 The binary-cache-by-hash design is elegant — avoids recompilation on every scan while ensuring staleness is impossible.
- 🎉 The `dbRecv` allowlist for SQL sinks is a smart approach to avoid FPs on non-DB `.Query()` calls (Redis, HTTP, etc.).
- 🎉 Gin source detection with receiver-name gating (`c`, `ctx`, `g`, `gc`, `gctx`) is practical and avoids the `c.Query` vs `db.Query` collision cleanly.
- 🎉 The fixed-point taint iteration with kill (reassignment removes taint) is more sophisticated than a simple union — it correctly handles sanitization-by-reassignment.
- 🎉 JSON-over-stdin architecture eliminates any command-injection surface in the bridge.

---

## Out of scope (not reviewed)

- Cross-file Go analysis (not implemented, not claimed)
- Go module resolution / type information
- Performance benchmarking of the Go binary itself

---

## False positives eliminated

- 0 (all 3 findings are real issues confirmed with concrete code paths)

---

## Metadata

- Phases completed: 0, 1, 2, 3, 4
- Strict mode: no
- Reviewer: kiro code-review skill v1
