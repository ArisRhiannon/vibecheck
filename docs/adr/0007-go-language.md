# ADR-0007: Go support via go/parser (compiled-once bridge)

**Status**: Accepted · **Date**: 2026-05-31 · **Decider**: Aris Rhiannon · **Follows** ADR-0004

## Context
After Python, Go is the next high-volume target for AI-generated backend code. Per ADR-0004 we reuse the
language's own real parser rather than hand-rolling one.

## Decision
- **`src/go.go`**: a real analyzer using **`go/parser` + `go/ast`** with intra-procedural taint. Sources:
  `net/http` (`r.FormValue`, `r.URL.Query().Get`, `r.Header.Get`, `mux.Vars`), gin (`c.Query/Param/...`),
  `os.Args`. Sinks: `exec.Command` (cmdi), `db.Query/Exec/...` on a DB-looking receiver (SQLi — only the
  **query-string** arg, so parameterized bind args are safe), `os.Open/ReadFile` (path), `http.Redirect`
  (open redirect), `http.Get/Post/Head/NewRequest` (SSRF). Sanitizers: `strconv.Atoi/ParseInt/...`.
- **`src/go.ts`**: resolves a `go` toolchain, **compiles the analyzer once** to a cached binary (keyed by
  source SHA-256) and runs it, passing `{path,content}` as **JSON over stdin** (no arg injection). If `go`
  is absent or the build fails, `.go` files are silently skipped (graceful) — JS/TS/Python unaffected.

## Consequences
- **+** Real Go parsing/taint (not regex); benchmark **75 cases, 100/100, 0 FP**; 46/46 tests. Additive.
- **+** Compiled-once ⇒ fast repeat scans; CI pins Go via `actions/setup-go`.
- **−** Go scanning needs a `go` toolchain on PATH (stated plainly).
- **−** **Intra-procedural** only; multi-return assignments (`x, _ := f(src)`) are not tracked; the `.Do`
  HTTP-client sink was dropped to avoid Redis/gRPC `.Do` false positives (a chosen FN over a FP).
