# ADR-0004: Polyglot via each language's native parser

**Status**: Accepted · **Date**: 2026-05-31 · **Decider**: Aris Rhiannon

## Context
v0.2 shipped JS/TS only — a fair criticism, since AI agents generate Python/Go/Ruby/etc. We must broaden
coverage without hand-rolling parsers (years of work, full of edge cases — the very thing that made the
original regex approach unreliable).

## Decision
Add languages by reusing **each language's own real parser**, not a custom one:
- **Python**: shell out to `python3` and parse with the **stdlib `ast`** (`src/python.py`), running the
  same model as the JS engine — intra-procedural taint, confidence levels, the AI-failure sink set
  (eval/exec, os.system/subprocess shell=True, cursor.execute SQLi, pickle.loads, yaml.load, SSTI,
  open redirect, path traversal). Python is **optional**: if `python3` is absent, `.py` files are
  skipped (graceful), and JS/TS needs nothing extra.
- The bridge (`src/python.ts`) passes file contents over stdin (no disk re-read; testable), and findings
  are normalized into the same `Finding` shape + confidence model + benchmark.

## Consequences
- **+** Real Python parsing/taint (not regex), benchmarked alongside JS (60-case corpus, 100/100).
- **+** No hand-rolled parsers; each language uses its battle-tested AST.
- **+** Additive — the validated JS engine is untouched (no regression risk).
- **−** Python scanning adds a runtime requirement (`python3`), stated plainly; absent ⇒ skip.
- **−** Per-language analyzers must be maintained in parallel; future languages (Go via `go/parser`,
  Ruby via `ripper`, or tree-sitter) follow the same "native parser, optional dependency" pattern.
