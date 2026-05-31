# ADR-0012: Go cross-package call resolution

**Status**: Accepted · **Date**: 2026-05-31 · **Decider**: Aris Rhiannon · **Refines** ADR-0010

## Context
ADR-0010 made Go inter-procedural **within a package** (bare-name calls). Real Go services split helpers
across packages (`util.Sanitize(...)`, `store.Run(...)`), so cross-package flows were a documented FN.

## Decision
Resolve `pkg.Func()` selector calls in `src/go.go` (both `retTainted` and the call-site param→sink
matcher): a `SelectorExpr` callee `x.Func` maps to summary key `{x, Func}`. Summaries are keyed by the
file's actual `package` declaration name, and Go binds an **unaliased** import to the package's name, so
the selector base equals the package name in the common case — no import-path bookkeeping needed.

## Consequences
- **+** Cross-package return-taint (`q := util.GetInput(r); db.Query(q)`) and param→sink
  (`store.Run(req.FormValue(...))`) now resolve. 57/57 tests; 91-case benchmark 100/100; self-QA: a
  non-package `logger.Run(taint)` does not resolve (no false positive), parameterized cross-package
  helper stays silent.
- **−** **Aliased** package imports (`import u "x/util"; u.Func`) and packages whose declared name differs
  from the selector base are not resolved (false negatives). A scanned package coincidentally named like a
  receiver variable could in principle mis-resolve, but only if it also defines a matching function — rare.
  Multi-return assignments remain untracked.
