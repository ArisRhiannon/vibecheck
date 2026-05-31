# ADR-0006: Return-taint + cross-file (by-import) summaries

**Status**: Accepted · **Date**: 2026-05-31 · **Decider**: Aris Rhiannon · **Refines** ADR-0005

## Context
ADR-0005 added param→sink summaries (helper-wrapped sinks). Two gaps remained, both common in AI code:
`const id = getUserInput(); db.query(id)` (**return-taint**) and helpers/sources imported from another
file (**cross-file**). Both were documented false negatives.

## Decision
- **Return-taint** (`src/taint.ts`): `buildSummaries` computes, per function, `returnsAbsolute` (returns a
  source) and `returnParams` (which params flow to the return), via a fixpoint so multi-hop intra-file
  chains resolve. `buildTaintSets` gains an optional `summaries` arg and uses `returnTainted` so a variable
  assigned from a return-tainting call becomes tainted — making **every existing sink** fire on it.
  `isTainted` is **unchanged** (the new arg defaults to no-op ⇒ zero regression).
- **Cross-file** (`crossFileSummaries` + interproc): build a global name→summary map across all scanned
  files, then resolve a call only when the file **imports that name** (1-hop, by name). Sanitizers are
  respected end-to-end.
- **Ambiguity rule (anti-FP):** a name defined in **more than one file** is skipped from cross-file
  resolution (we do no real module resolution, so picking one would risk a false positive).

## Consequences
- **+** Catches return-taint and imported-helper/source flows; benchmark **69 cases, 100/100, 0 FP**;
  **42/42** tests. Additive: `analyze2.ts` logic and `isTainted` unchanged.
- **−** **By-name, 1-hop**: aliased imports (`import {a as b}`), namespace calls (`ns.fn()`), re-export
  chains, and >~4-hop return chains are not resolved (false negatives). Stated plainly in the README.
- **−** Ambiguous (multi-file) names are intentionally **not** resolved cross-file (a chosen FN over a FP).
- **−** `crossFileSummaries` runs `buildSummaries` twice per file; parse is cached, cost is small.
