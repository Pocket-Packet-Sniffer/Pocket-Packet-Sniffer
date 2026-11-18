# Regression Test Report

**Current source:** `main` commit `0839abf`
**CI result:** [GitHub Actions run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) — success
**Current full-suite result:** Python 171 passed / 2 skipped; dashboard 13 passed.

## Purpose

Regression tests preserve behavior associated with previously fixed defects and acceptance requirements. They are part of the normal Python/browser CI rather than a separate standalone CI workflow.

## Defect-to-regression map

| Regression area | Canonical test/evidence | Protection provided |
|---|---|---|
| Relative Windows storage path | `tests/test_storage_query.py::test_relative_storage_directory_is_normalized_and_usable` | Changes to a temporary working directory, creates the relative repository folder, saves/queries a packet, and confirms metadata DB and PCAP placement |
| SQLite read/write guard | `tests/test_storage_query.py` repository connection tests | Requires an existing metadata DB for `mode=rw`; prevents accidental recreation on read/write access |
| Capture stop/liveness | `tests/test_capture_control.py::test_active_capture_session_exits_after_external_stop_request` and API lifecycle tests | Ensures an external stop request ends the active capture process/session cleanly |
| Parser malformed/unsupported input | `tests/test_analysis_parser_edge_cases.py` | Exercises empty/malformed frames and unsupported link types without misclassifying unsupported data as decoded packets |
| API query/pagination and origin boundary | `tests/test_api.py::test_packet_search_time_filter_pagination_and_safe_transport_metadata`, `test_browser_write_rejects_unapproved_website_origin` | Protects query limits/metadata behavior and rejects unapproved browser write origins |
| Dashboard filtering and data refresh | `web/tests/e2e/dashboard.spec.ts` | Protects address navigation, search/filter controls, capture state updates, local PCAP selection, report downloads, and mobile layout |
| Packaged Windows agent startup | `.github/workflows/release-windows-agent.yml`, historical workflow run [#44140452688](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44140452688) | Builds the Windows executable, starts it, polls the API health endpoint, then stops it |

## Current execution evidence

- Python suite: **171 passed, 2 skipped, 0 failed**. POSIX permission-mode skips on Windows do not exercise ACLs.
- Browser suite: **13 passed** in the verification run; merged CI #731 passed.
- The Windows relative-path regression is part of the full Python suite and Windows CI job.
- A real capture on 2026-11-18 separately stored 175/175 observed Wi-Fi packets. That is system acceptance evidence, not a synthetic regression fixture.

## Reproduction

```powershell
python -m pytest -q tests/test_storage_query.py
python -m pytest -q tests/test_capture_control.py tests/test_api.py
python -m pytest -q tests/test_analysis_parser_edge_cases.py
```

Run browser regressions from `web/` with `npm run test:e2e -- --workers=1`. The exact complete run outcomes and limits are in the [Test Execution Report](TEST_EXECUTION_REPORT.md).

## Limits

Passing regression tests show that covered scenarios continue to pass; they do not certify every code path or hardware combination. Wi-Fi monitor mode, live BLE radio capture, Windows ACLs, Raspberry Pi performance/drop counters, and simultaneous physical adapters remain unverified.
