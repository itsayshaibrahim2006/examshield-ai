# Architecture

```
 untrusted text ─► Scanner (advisory) ─┐
                                       ├─► audit log
 user's request ─► trusted grant ─► Protection Engine ─► allowed simulated actions ─► result
 (trusted)                           ▲
                    allowlist + policy rules
```

## Components (backend/examshield)
| Module | Role |
|---|---|
| `scanner.py` | Detection. Rule signals (regex rules), structural signals (HTML comments, zero-width characters, fake role markers) and contextual signals (quote/educational detection, narrative vs. command, compound escalation). Output: findings with offsets, severity, confidence, and risk Low/Medium/High/Critical. **Advisory only.** |
| `policy.py` | **Protection Engine.** Imports nothing from the scanner. Derives a *grant* from the user's own request, then checks each proposed action: well-formed → allowlisted → not from untrusted content → covered by grant → known resource in scope → protected resources need explicit authorization → no external destination or protected data in output. Any error or ambiguity = deny (fail closed). |
| `simulator.py` | A deliberately gullible *simulated* assistant (not a language model). Uses its own patterns, independent of the scanner, so attacks the scanner misses can still reach the policy. |
| `pipeline.py` | Runs one scenario in `unprotected` (allow-all, simulation) or `protected` mode. |
| `benchmark.py`, `benchmark_data.py` | Deterministic synthetic dataset and metric calculation. |
| `db.py`, `service.py` | SQLite with parameterised queries; validation, persistence, audit events. |
| `llm.py` | Optional LLM adapter. Implemented but **not exercised** in the build sandbox. Output is shown separately and never alters decisions. |
| `server.py` | JSON API plus static files on the standard library. |

## Detection vs enforcement
The scanner tells you *something looks wrong*. The policy decides what is *allowed*. The test `test_every_case_blocked_even_with_null_scanner` replaces the scanner with one that detects nothing and shows no unauthorised action ever executes.

## Database tables
`scenarios`, `scans`, `scanner_findings`, `simulation_runs`, `security_decisions`, `simulated_actions`, `benchmark_runs`, `benchmark_results`, `audit_events`. Timestamps are UTC ISO-8601 with a trailing `Z`.

## Mapping to the requested stack
React/Vite/Tailwind/Recharts → plain JS modules, CSS and hand-written SVG charts. FastAPI/Pydantic → `http.server` plus explicit validation in `service.py`. SQLAlchemy → `sqlite3` with parameterised statements. Pytest → `unittest` (tests are also collected by pytest if installed).
