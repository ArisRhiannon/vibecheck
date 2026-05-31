# Re-architecture (v0.2) — decision record

Author: Aris Rhiannon. Status: in progress. Honest response to a hard, mostly-correct critique of v0.1.

## What was wrong with v0.1 (conceded)
- **Regex over source text is not SAST.** Real detection needs a real parser. v0.1's "zero-dependency"
  forced regex/heuristics — a precision handicap, not a virtue.
- **"Light structural matching" = grep with a fancy name.** No data-flow. It missed abstracted sinks
  (`knex.raw(x)`, `prisma.$queryRawUnsafe(x)`), and route-auth needs middleware-chain understanding,
  not "is there a word `auth` nearby".
- **"The exact mistakes AI agents make" was an overclaim.** v0.1 was JS/TS-only and missed whole
  classes: XSS (`dangerouslySetInnerHTML`, `innerHTML`, `document.write`), SSRF, path traversal,
  prototype pollution, open redirect.
- **MCP + noisy heuristics = automating phantom work for agents.** False positives in an agent loop burn
  tokens "fixing" non-issues.
- **"offline" / "no AI" framed as headline virtues.** They aren't differentiators against Semgrep
  (MIT-ish, real parsers, taint, 2000+ rules) or CodeQL (free for OSS, real data-flow).

## Decisions
1. **Real AST.** Parse JS/TS/JSX/TSX with `@babel/parser` (handles decorators, dynamic import, tagged
   templates, TS, JSX). No hand-rolled parser.
2. **Intra-procedural taint.** Track sources (`req.body/query/params/headers`, route-handler params,
   `location`/`document`, `process.argv`) through assignments into sinks. Findings are **confidence-graded**:
   `tainted` (a source provably reaches the sink) vs `unsanitized` (non-literal at a dangerous sink) vs
   `review` (structural smell).
3. **Broadened, real rule classes** (AST + taint): RCE/command-injection, SQLi incl. raw-query APIs,
   XSS, SSRF, path traversal, prototype pollution, open redirect, CORS/JWT/cookie misconfig, plus
   secrets and committed-.env (regex is industry-standard for secrets).
4. **Confidence gating for agents.** `--ci` and the MCP `scan` tool default to **high-confidence
   (taint-backed)** findings only, so an agent loop never chases phantom issues. Full set behind a flag.
5. **Measured, not claimed.** A labeled benchmark (vulnerable + safe) computes precision/recall/F1 per
   rule; the numbers ship in `METRICS.md` and are re-checked in CI.
6. **Honest positioning.** vibecheck is a fast, low-false-positive, **agent-native ship-gate** for the
   AI-vibe-coding failure classes — it **complements** Semgrep/CodeQL, it does not replace them.
7. **MIT.** (Done.)

## Non-goals (explicit, no over-claiming)
- NOT a general SAST platform; NOT broader/deeper than Semgrep or CodeQL.
- NOT inter-procedural / cross-file taint in v0.2 (intra-procedural only; stated plainly).
- Multi-language beyond JS/TS is roadmap; we will not hand-roll parsers.

## Where we can honestly be "above standard"
One narrow, measurable axis: **false-positive-safe, taint-backed gating of the AI-failure classes inside
agent/CI loops, with transparent precision/recall.** Not breadth. We prove it with numbers or we don't
claim it.
