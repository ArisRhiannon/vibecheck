# ADR-0010: Go inter-procedural (intra-package) taint

**Status**: Accepted · **Date**: 2026-05-31 · **Decider**: Aris Rhiannon · **Follows** ADR-0007

## Context
The Go analyzer was intra-procedural; real Go services route request data through same-package helper
functions before a sink. That was the remaining inter-procedural gap (after JS/TS and Python).

## Decision
Rewrite `src/go.go` to build **per-(package, function) summaries** (`returnsAbsolute`, `returnParams`,
`param→sink`) to a fixpoint across all provided files, then analyze with them:
- `retTainted` resolves **same-package bare-name calls** to their summary; it feeds the assignment
  fixpoint (`computeSet`) so a variable from a return-tainting helper becomes tainted and trips the sinks.
- `param→sink` summaries are computed by seeding each parameter and diffing the sink hits against the
  empty-seed **base** (so a sink driven by an *internal* absolute source is not mis-attributed to a
  parameter); they fire at the **call site** when the caller passes attacker input.
- `sinkHits` factors the sink set (cmdi, SQLi on a DB receiver checking only the query-string arg, path,
  open-redirect, SSRF). Sanitizers (`strconv.*`) clear taint.

## Consequences
- **+** Catches same-package helper flows; 84-case benchmark 100/100; 54/54 tests; adversarial self-QA
  (7 cases) clean: parameterized helper, **cross-package `pkg.Func`** (unresolved → silent), unrelated
  method `obj.Run`, **recursion** (no hang), and **same name in a different package** (no contamination,
  keyed by package) all silent; intra return-taint + param→sink fire.
- **−** **Intra-package only**: cross-package `pkg.Func` calls are not resolved (we don't load the imported
  package's files); multi-return assignments (`x, _ := f(src)`) still untracked. Stated plainly.
- Summaries keyed by `(package, name)`, so same-named functions in different packages don't collide.
