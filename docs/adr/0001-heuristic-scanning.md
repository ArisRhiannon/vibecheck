# ADR-0001: Heuristic, zero-dependency, no-AI source scanning

**Status**: Superseded by ADR-0003 (v0.2) · **Date**: 2026-05-31 · **Decider**: Aris Rhiannon

## Context
vibecheck must catch the security mistakes AI-generated apps make, run anywhere (incl. CI and agent
loops), be trivially auditable, and add no supply-chain risk of its own. A full multi-language taint
engine (or pulling a heavy parser) would be large, slow, and ironic for a tool that warns about
dependencies.

## Decision
Detect issues with **targeted heuristics over source text**: regexes plus small structural helpers (a
balanced-delimiter scanner for argument/handler spans, an entropy check for secrets). **Zero runtime
dependencies** (Node/Bun stdlib only). **No AI, no network, no code execution.** Findings carry a
severity, `file:line`, and remediation; a `review` tier marks *possible* issues (e.g. routes with no
visible auth) so they inform without breaking CI by default.

## Consequences
- **+** Tiny, fast, auditable; safe to run in CI and inside agents; no DB to update.
- **+** Each rule is provable on fixtures (vulnerable fires, safe stays quiet) — the test suite enforces this.
- **−** Heuristics yield false positives/negatives vs a real taint analyzer; mitigated by severity tiers,
  argument/handler-scoped checks, placeholder filtering, and `.vibecheck.json` allowlists.
- **−** JS/TS-first; other languages and deeper analysis are roadmap. We say so plainly (no over-claiming).
