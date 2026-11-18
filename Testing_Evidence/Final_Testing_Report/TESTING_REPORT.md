# Pocket Packet Sniffer — Consolidated Testing Evidence

**Current source:** `main` commit `0839abf9d102d0b4c1da4f0f58a205ef6d9a4525`
**Post-merge CI:** [GitHub Actions run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089), success
**Evidence period:** 2026-11-18

## Current test results

| Test area | Command or evidence | Result |
|---|---|---|
| Ruff lint | `ruff check --select E4,E7,E9,F,I src tests tools` | **PASS** — all checks passed |
| Full Python suite | `python -m pytest -q` with pytest-cov enabled | **171 passed, 2 skipped, 0 failed**; POSIX permission-mode tests skipped on Windows |
| Statement coverage | `coverage.json` / pytest-cov | **79.46%** — 1,899/2,390 Python statements |
| Branch coverage | `coverage.json` / pytest-cov | **68.29%** — 519/760 branch outcomes |
| Focused unit suites | Analysis 45, Capture 42, Storage 25, Presentation 22 | **134 passed**; these overlap with the full suite |
| Backend system-flow subset | Integration/API/CLI/capture lifecycle/agent files | **34 passed**; overlaps with the full suite |
| Frontend type-check | `npm run typecheck` in `web/` | **PASS** |
| Production frontend build | `npm run build` in `web/` | **PASS** |
| Browser end-to-end | `npm run test:e2e -- --workers=1` in `web/` | **13 passed**; API responses are controlled/mocked in browser tests |
| Real interface acceptance | Passive authorized Windows Wi-Fi capture via local sensor/Npcap | **175 seen, 175 stored, 0 ignored**; clean stop; no generated/injected packets |
| Live query and exports | Same isolated session | **175 records queried**; CSV and PDF each returned HTTP 200 |
| Services and hosted dashboard | Local API, local web UI, deployed Vercel page | Each returned HTTP 200 |

The current complete details are in the [Unit Test Report](../../tests/docs/unit/UNIT_TEST_REPORT.md), [System Test Report](../../tests/docs/SYSTEM_TEST_REPORT.md), [Code and Branch Coverage Report](../../tests/docs/CODE_AND_BRANCH_COVERAGE_REPORT.md), [Acceptance Test Report](../../tests/docs/ACCEPTANCE_TEST_REPORT.md), and [Test Execution Report](../../tests/docs/TEST_EXECUTION_REPORT.md).

## Evidence interpretation

- The six formal submission documents are indexed at [Submission Reports](../../Submission_Reports/README.md).
- Coverage is a measured execution baseline, not a correctness or SRS-completion score. Python coverage does not measure the React/TypeScript frontend.
- Two skipped POSIX permission tests do not verify Windows ACLs.
- Browser tests validate scripted dashboard behavior, not physical adapter capture.
- The real capture proves ordinary Wi-Fi capture on one Windows computer/adapter during one short run. It does not establish monitor mode, all-network visibility, sustained throughput, zero packet loss, or behavior on other hardware.
- Live BLE scanning is not part of the current Windows sensor. Raspberry Pi performance/drop counters, Windows ACLs, Wi-Fi monitor mode, and simultaneous physical-adapter capture remain unverified.
- Rule-based suspicious-activity indicators are heuristic prompts for investigation, not proof of attack or safety.

## Screenshot provenance

The PNG files in this folder tree are original historical screenshots supplied during earlier testing runs. They are retained as supporting evidence and have not been recreated. They may show older test counts or UI versions; use the dated CI links and current text reports above for current results. A screenshot is not substituted for machine-readable test output or CI status.
