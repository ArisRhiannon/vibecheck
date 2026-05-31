# Benchmark metrics

Corpus: **43** labeled cases (vulnerable + safe + tricky-safe). Advisory rules
(`VC-ROUTE-NO-AUTH`, `VC-INPUT-NO-VALIDATION`) and `review`-confidence findings are excluded
from these core numbers by design (they are advisory, not assertions). Re-run: `bun benchmark/run.ts`.

- **Precision: 100.0%** (TP 24 / FP 0)
- **Recall: 100.0%** (TP 24 / FN 0)
- **F1: 100.0%**

| rule | TP | FP | FN |
|------|----|----|----|
| VC-COOKIE-INSECURE | 1 | 0 | 0 |
| VC-CORS-WILDCARD | 2 | 0 | 0 |
| VC-JWT-NONE | 1 | 0 | 0 |
| VC-JWT-UNPINNED | 1 | 0 | 0 |
| VC-NEXT-PUBLIC-SECRET | 1 | 0 | 0 |
| VC-OPEN-REDIRECT | 1 | 0 | 0 |
| VC-PATH-TRAVERSAL | 1 | 0 | 0 |
| VC-RCE-CHILD-PROCESS | 2 | 0 | 0 |
| VC-RCE-EVAL | 3 | 0 | 0 |
| VC-SQLI | 4 | 0 | 0 |
| VC-SSRF | 2 | 0 | 0 |
| VC-STACK-EXPOSURE | 1 | 0 | 0 |
| VC-SUPABASE-SERVICE-ROLE | 1 | 0 | 0 |
| VC-XSS-DOM | 2 | 0 | 0 |
| VC-XSS-REACT | 1 | 0 | 0 |

All cases match their labels.
