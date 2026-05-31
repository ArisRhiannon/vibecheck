# ADR-0003: Real AST + intra-procedural taint (supersedes ADR-0001)

**Status**: Accepted · **Date**: 2026-05-31 · **Decider**: Aris Rhiannon

## Context
A reviewer correctly argued that regex-over-source (ADR-0001's "zero-dependency" stance) is not real
SAST: it misses abstracted sinks (`knex.raw(x)`, `prisma.$queryRawUnsafe(x)`), can't follow data flow,
and produces false positives that — if fed to an agent via MCP — generate phantom work. "Zero-dep" was
a precision handicap, not a virtue.

## Decision
- Parse JS/TS/JSX/TSX with **`@babel/parser`** (handles decorators, dynamic import, tagged templates,
  TS, JSX). Accept the dependency.
- Add **intra-procedural taint**: sources (`req.*`, `location`, `process.argv`, `searchParams`) propagate
  through assignments into sinks; numeric coercion / schema `.parse()` sanitize.
- **Confidence** on every finding: `high` (taint-backed / deterministic) gates `--ci` and is what the
  MCP `scan` tool returns by default; `review` is excluded from the agent loop.
- **Measure**: a labeled benchmark computes precision/recall/F1 (`METRICS.md`) and guards regressions in CI.
- **Position honestly**: complements Semgrep/CodeQL; not a replacement; JS/TS only in v0.2.

## Consequences
- **+** Catches the abstracted sinks and cuts false positives (measured 100/100 on the v0.2 corpus, 0 FP
  on tricky-safe cases). Agent-safe via confidence gating.
- **+** Real AST tolerates the edge cases that break hand-rolled parsers.
- **−** New dependencies (Babel); larger install than v0.1. Acceptable for correctness.
- **−** Intra-procedural only; multi-language is roadmap (tree-sitter, not hand-rolled). Stated plainly.
