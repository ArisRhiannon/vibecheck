# ADR-0009: Python inter-procedural taint

**Status**: Accepted · **Date**: 2026-05-31 · **Decider**: Aris Rhiannon · **Follows** ADR-0004

## Context
The Python analyzer was intra-procedural — useless for the dominant Flask/Django pattern where request
data flows through helper functions (`x = get_input(); cursor.execute(x)` or `run(request.args['x'])`),
often across modules. That was the biggest gap for real Python apps.

## Decision
Rewrite `src/python.py` to be **inter-procedural**, mirroring the JS engine:
- **Per-function summaries** (`build_summaries`): `returnsAbsolute`, `returnParams`, and `param→sink`,
  computed to a fixpoint across **all** provided files (so multi-hop chains resolve).
- **Return-taint** feeds the per-scope taint fixpoint (`ret_tainted`), so a variable assigned from a
  return-tainting call becomes tainted and trips the existing sinks; sanitizers (`int()`, …) clear it.
- **Param→sink** is flagged at the **call site** when the caller passes attacker input into a parameter
  that provably reaches a sink (only `high`-confidence, taint-driven sinks become summaries).
- **Cross-file** via real import resolution (`resolve_module_py` + `imports_of`): `from .mod import name
  [as alias]` and `import mod [as alias]`, resolved to the actual scanned file (relative levels, dotted
  path, unique-basename fallback). `make_resolver` maps a call's callee → the defining function's summary.

## Consequences
- **+** Catches Flask/Django helper flows (intra-file + cross-file, multi-hop); 81-case benchmark 100/100;
  53/53 tests; adversarial self-QA (10 cases) clean (sanitizing/constant helpers, constant-arg calls,
  same-name-from-safe-module, non-imported, recursion all silent; intra/cross-file/2-hop fire).
- **−** Not resolved (false negatives, documented): `import a.b` dotted-unaliased, `*`/re-export imports,
  decorator-mediated flow, methods on instances. Intra-procedural scoping is function-name-keyed
  (nested-function name collisions are rare and accepted).
