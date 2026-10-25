# Feature verification report

Everything marked **Tested** was executed in the build environment (Python 3.12, Chromium via Playwright). Commands: `python -m unittest discover -s tests` → **51 tests, OK**. A scripted browser pass visited all 8 pages, clicked the main buttons and recorded **0 console errors**.

| Area | Status | Evidence / notes |
|---|---|---|
| Scanner: rules, structural, contextual signals, risk levels, explanations | **Implemented, tested** | TestDetection (10 tests) |
| Quoted / educational text handling | **Implemented, tested (heuristic)** | Quoted cases stay unflagged; quote + real attack and "lure" cases flagged. Heuristic, can be fooled |
| Optional LLM-assisted analysis | **Partially implemented** | `llm.py` exists; **never run** (no network/key). Never changes decisions |
| Safe file upload (type, size, binary, encoding, path stripping) | **Implemented, tested** | test_unsafe_uploads_rejected |
| Protection Engine: allowlist, grant, provenance, protected resources, disclosure, fail-closed | **Implemented, tested** | TestPolicy (9 tests) |
| Protection when scanner fails | **Implemented, tested** | null-scanner test over every benchmark case |
| Attack Lab (12 scenarios, custom scenarios, inspect results) | **Implemented, tested** | API tests + browser pass |
| Benchmark: dataset, metrics, zero-denominator handling, repeatability, timestamped storage | **Implemented, tested** | TestMetrics (8 tests); stored rows recompute to stored metrics |
| Before/after demo, consistent pairing | **Implemented, tested** | test_before_after_consistency_via_service; browser pass |
| Audit log, investigation drawer, JSON export | **Implemented, tested** | API tests; export button exercised only via code path (download not asserted) |
| Dashboard numbers from records | **Implemented, tested** | test_zz_stats_come_from_records |
| Input validation and API errors | **Implemented, tested** | 400/404/405/413/415/422 covered |
| SQL injection resistance (parameterised) | **Implemented, tested** | hostile title stored as plain text |
| UI on laptop widths | **Implemented, visually checked** | screenshots at 1440 px; narrow (390 px) layout checked only via one screenshot of the Overview page |
| A1 poster PDF (594 x 841 mm), SVG source, bleed variant | **Implemented, verified** | PDF page box measured 594.0 x 841.0 mm; bleed file 600 x 847; layout inspected visually, nothing clipped |
| Poster QR code | **Unavailable (placeholder)** | No verified demo URL exists |
| React / TypeScript / Vite / Tailwind / Recharts | **Unavailable** | Not installable offline; replaced by JS modules, CSS, SVG charts |
| FastAPI / Pydantic / SQLAlchemy / Pytest | **Unavailable** | Replaced by stdlib server, explicit validation, sqlite3, unittest |
| Frontend "production build" | **Not applicable** | No build step exists; the browser loads source files directly |
| Real-world detection performance | **Not claimed** | Dataset is synthetic and written by us |

## Benchmark result of the build run (synthetic, 57 cases)
TP 21, FN 4, FP 0, TN 22. Precision 100%, recall 84.0%, F1 91.3%. Simulated attacks blocked by the engine 27/27; scanner alone would have stopped 22/27. Legitimate tasks completed 22/22. Ambiguous: 8 unflagged, 2 flagged.

## Bugs found by testing and fixed during the build
Trailing period in a file path broke authorised reads; the simulator's first read-verb could hide a later one (hidden HTML comment case); bodyless DELETE requests were rejected with 411; a shared DOM node hid half of the before/after left column.

## Known limitations
English-only rules; heuristic quote handling; scripted simulator rather than a real model; the policy infers the user's grant from keywords in the request; no authentication (server binds to 127.0.0.1 for local demos only).
