# ADR-0008: Real cross-file module resolution (supersedes ADR-0006's by-name resolution)

**Status**: Accepted · **Date**: 2026-05-31 · **Decider**: Aris Rhiannon · **Supersedes** the cross-file part of ADR-0006

## Context
ADR-0006 resolved cross-file summaries **by bare name** and dropped any name defined in >1 file
(ambiguous) to avoid false positives. That left real false negatives: aliased imports (`a as b`),
namespace imports (`* as ns`), helper chains across >1 file boundary, and any import of a name that
happened to exist elsewhere. This is the biggest gap for layered/enterprise codebases.

## Decision
Resolve imports **for real**:
- `resolveImports` parses each file's relative `import` statements and **resolves the source to the actual
  scanned file** (`resolveModule`: `./`,`../` normalization + extension/`/index` resolution), producing
  edges `{ local, orig, fromRel, ns }` for **named**, **aliased** (`orig` = the exported name), and
  **namespace** (`ns`) imports. Bare/package imports stay unresolved (a false negative, not a guess).
- `crossFileSummaries` seeds each file's summary base from the **resolved defining file** (precise — same
  names in different files no longer collide, so the ambiguity-drop is gone), and runs a **multi-hop
  fixpoint** (cap 8 + change-detection) so chains across several files propagate.
- Namespace calls `ns.fn()` resolve via dotted summary keys; `returnTainted` and the interproc call-site
  matcher handle member callees. The same edges drive cross-file **param→sink** in `interproc.ts`.

## Consequences
- **+** Aliased + namespace imports and multi-hop cross-file chains now resolve (removed FNs); precise
  per-file resolution removes the ambiguity-drop. 51/51 tests; 78-case benchmark 100/100/0; corpus
  unchanged (no new FP); fastify (355 files) cross-file pass ≈ 3 s.
- **−** Still **ESM-relative only**: re-exports (`export { x } from …`), default exports, CommonJS
  `require`, and dynamic `import()` are not resolved; chains deeper than ~7 hops in worst-case file
  ordering may need another pass. Stated plainly in the README. `isTainted` remains unchanged.
