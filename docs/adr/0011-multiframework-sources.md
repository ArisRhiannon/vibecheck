# ADR-0011: Multi-framework Python sources + the `collectFiles` language-coverage fix

**Status**: Accepted · **Date**: 2026-05-31 · **Decider**: Aris Rhiannon · **Follows** ADR-0009

## Context
The real-world corpus exposed two gaps. (1) **A critical bug**: `collectFiles` (used by `scanProject` →
CLI/MCP/corpus) had a text-extension allowlist that omitted `.py` and `.go`, so the Python and Go
analyzers **never ran in real scans** — only in unit tests/benchmark, which call them directly. (2) Even
once scanned, the only Python sources modeled were Flask/Django `request.*`, so layered **aiohttp** apps
like `dvpwa` produced no high-confidence finding (its SQLi flows through `await request.post()` → a
helper `data.get()` → a cross-file `@staticmethod` that builds `"… '%(name)s'" % {'name': name}`).

## Decision
- **Fix `collectFiles`**: add `.py` and `.go` to `TEXT_EXT` (+ regression test). Binary/size guards still
  apply. This is the highest-impact change here — it makes Python/Go support actually function in production.
- **Broaden Python sources** (`src/python.py`): match a `request.`/`req.`/`self.request.` chain via regex
  over the union of framework request attributes (`match_info`, `query`, `query_params`, `path_params`,
  `matchdict`, `rel_url`, `GET/POST/COOKIES/META/FILES`, `forms`, …) plus call-form sources
  (`await request.post()/json()/form()/body()/text()`, `.get_argument`, …). Add `await` and `Dict` to
  `is_tainted` (so `% {'k': tainted}` propagates).
- **Class-method cross-file resolution**: `ImportedClass.method` → (the class's module, method);
  `LocalClass.method` → (this module, method). Instance/`self` calls are deliberately **not** resolved.

## Consequences
- **+** Python/Go now scanned for real; dvpwa's layered aiohttp SQLi is caught at **high** (corpus TP).
  91-case benchmark 100/100; corpus precision 7/7 detector-correct, 0 high-confidence FPs across 6 mature
  repos even after their `.py`/`.go` get scanned.
- **−** A variable literally named `req`/`request` that is not a server request (e.g. an HTTP-client
  response) can match a source pattern; in concat-SQL this surfaces only at `review` confidence, outside
  the gate. Instance-method flows (`obj.method(taint)`), `import a.b` dotted-unaliased, `*`/re-exports,
  and decorator-mediated flow remain false negatives. Stated plainly.
