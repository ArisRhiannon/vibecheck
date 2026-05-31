# ADR-0002: Agent-first interface and severity / CI model

**Status**: Accepted · **Date**: 2026-05-31 · **Decider**: Aris Rhiannon

## Context
The biggest gap vibecheck fills is that AI coding agents ship insecure apps and have no deterministic
"definition of done" check. To be used by agents (not just humans), the tool must be *discoverable* and
*machine-consumable*, matching how agents work in 2026 (ripgrep-style local tools, `--json`, MCP,
`llms.txt`/`AGENTS.md` routing surfaces).

## Decision
- Ship four agent surfaces: a CLI with `--json` + stable exit codes, a real **MCP stdio server** exposing
  a `scan` tool, an **`AGENTS.md`** ("run `vibecheck . --ci` before done"), and an **`llms.txt`**.
- Severity tiers `critical|high|medium|review|low` with a configurable `failSeverity` (default `high`):
  `--ci` exits non-zero only at/above it, so `review`/`low` advisories inform without blocking pipelines.
- Findings are deterministic and sorted; output schema is stable so agents can parse → fix → re-run.

## Consequences
- **+** The tool plugs directly into agent loops and CI; agents can self-verify and remediate.
- **+** Stable JSON + exit codes make it scriptable and testable end-to-end (spawned CLI + MCP tests).
- **−** Maintaining four surfaces is slightly more work; mitigated by sharing one `scanProject()` core.
- **−** `review` findings can be noisy; kept below the default CI threshold and explained via `explain`.
