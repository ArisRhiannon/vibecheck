# ADR-0005: Intra-file inter-procedural taint via function summaries

**Status**: Accepted · **Date**: 2026-05-31 · **Decider**: Aris Rhiannon · **Refines** ADR-0003

## Context
ADR-0003 shipped intra-procedural taint and stated "not inter-procedural" as an honest limitation.
But AI-generated code constantly hides sinks behind helpers — `function runRaw(sql){ db.query(sql) }`
called with `runRaw(req.body.x)` — which the intra-procedural pass cannot see (a clear false negative).

## Decision
Add an **additive** layer (`src/interproc.ts`) that does **intra-file inter-procedural** taint via
**function summaries**, without touching the validated `taint.ts`/`analyze2.ts`:
- For each named function/arrow, compute which **parameter index provably reaches a dangerous sink**
  (eval, child_process, raw/`.query`/`.execute` SQL on a DB-looking receiver, fetch/axios SSRF, fs path),
  seeding the parameter as tainted and running the same `isTainted` fixpoint (so a sanitizing
  reassignment inside the helper — `s = Number(s)` — correctly clears it).
- At each **call site** to such a helper, if the argument at that index is attacker-controlled
  (source or tainted in the caller's scope), emit the finding at the call site as **high** confidence.
- The engine merges these with the intra-procedural findings and de-dupes by `file:line:rule`.

## Consequences
- **+** Catches the helper-wrapped vuln class that was a documented false negative; +2 true positives,
  still **0 false positives** on the (now 66-case) benchmark; **35/35** tests green.
- **+** Zero regression risk: the validated engine is unchanged; this only **adds** high-confidence findings.
- **+** A shared parse cache (`src/ast.ts`) keeps the second analyzer from re-parsing.
- **−** **1-level only**: helper→helper chains, return-taint, methods, and destructured params are not
  followed; **cross-file/module** flow is still out of scope. Stated plainly in the README.
- **−** Sanitizers are recognized structurally (numeric coercion, schema `.parse`); an unknown
  sanitizing helper would not clear taint (possible false positive) — same tradeoff as the core engine.
