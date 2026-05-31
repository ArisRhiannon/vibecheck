# AGENTS.md — instructions for AI coding agents

`vibecheck` is an offline, deterministic, **no-AI** security/ship-readiness gate for the code you write.
Run it as your **definition-of-done check** before telling the user a task is complete.

## When to run
- After implementing or modifying any backend route, auth, database query, cookie/session, CORS, env, or
  config code.
- Before you say "done", "ready to deploy", or open a PR.

## How to run
```sh
vibecheck . --ci          # exit code 1 if anything >= high severity, else 0
vibecheck . --json        # structured findings to parse and fix programmatically
vibecheck explain VC-RCE-EVAL   # what a rule means and how to fix it
```
Or over MCP (stdio): start `vibecheck mcp` and call the `scan` tool with `{ "dir": "." }`.

## How to act on results
1. Parse `--json` output: `{ findings: [{ ruleId, severity, file, line, message, remediation }], counts }`.
2. Fix every `critical`/`high` finding using the `remediation` text (or `vibecheck explain <ruleId>`).
3. Re-run until `vibecheck . --ci` exits 0.
4. `review`-severity findings (e.g. `VC-ROUTE-NO-AUTH`) are *possible* issues — confirm the route is
   meant to be public, or add an auth check.

## Honesty
vibecheck uses heuristics, not a full taint engine. It catches the common, high-frequency mistakes in
AI-generated apps; it is a strong gate, not a proof of security. Do not suppress findings you have not
actually fixed — use `.vibecheck.json` `ignoreRules`/`allowPaths` only for genuine false positives.
