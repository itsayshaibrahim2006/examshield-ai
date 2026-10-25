# ExamShield AI

**Detect. Block. Protect.** A prompt-injection security platform that finds malicious instructions hidden in untrusted documents, then *independently enforces* an authorization policy so an AI assistant cannot be tricked into unauthorised actions. Everything runs locally on simulated, synthetic resources.

> **Honest build note.** The brief asked for React/Vite/FastAPI/SQLAlchemy. The build sandbox had **no network, so none of those packages could be installed or run**. Rather than ship code that was never executed, this project uses the **Python standard library** (http.server, sqlite3, unittest) and a **no-build JavaScript front end**. Every claim in `docs/VERIFICATION.md` was actually executed. The architecture maps one-to-one onto the requested stack, see `docs/ARCHITECTURE.md`.

## Quick start (no installs needed)
Requires Python 3.10+ only.
```bash
python run.py                 # http://127.0.0.1:8000
python -m unittest discover -s tests -v    # 51 automated tests
```
Optional: copy `.env.example` to `.env` to change host/port or add an LLM key. Local mode needs no key.

On first launch the dashboard is empty (every number comes from stored records). Press **Run benchmark now** on the Overview page, then open **Before and After**.

## What is inside
| Page | Purpose |
|---|---|
| Overview | Counts, benchmark metrics, recent events, latest runs (all from the database) |
| Attack Lab | 12 synthetic scenarios + custom scenarios; shows request, document, scanner findings, policy decision, attempted action, outcome |
| AI Security Scanner | Paste text or upload a text file; highlighted findings, risk level, explanations, limitations |
| Protection Engine | The policy, allowlist, simulated resources and an interactive action tester |
| Security Benchmark | 57 labelled synthetic cases; confusion matrix, precision/recall/F1, blocking and completion rates, per-case inspection |
| Before and After | Same scenario with and without protection, side by side |
| Logs and Investigation | Filterable audit trail, detail drawer, JSON export |
| Settings and System | Mode, limits, dataset, limitations, clear history |

## Layout
```
backend/examshield/   scanner, policy (Protection Engine), simulator, pipeline, benchmark, db, service, server
frontend/             index.html, styles.css, js/ (no build step)
tests/                test_examshield.py (51 tests)
docs/                 ARCHITECTURE, API, JUDGE_DEMO, VERIFICATION
deliverables/poster/  A1 poster PDF + editable SVG + generator script + README
```

## Safety
All files, secrets and "protected" resources are synthetic and held in memory. No real file is read, no command is executed, nothing is transmitted. Uploaded files are decoded as plain text only.
