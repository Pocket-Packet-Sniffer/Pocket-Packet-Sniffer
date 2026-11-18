# Unit Test Report

**Project:** Pocket Packet Sniffer
**Evidence date:** 2026-11-18
**Verified source:** PR #60 source commit `0f07b0fc9db3050df97ada39cdb28950525df384`, merged to `main` as `0839abf9d102d0b4c1da4f0f58a205ef6d9a4525`
**Environment:** Windows 11, Python 3.13.1, pytest; CI independently passed on Windows and Ubuntu in [run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089).

## Objective and scope

Unit tests check focused behavior at the smallest practical boundary: packet parsing and analysis, capture source contracts, repository persistence/query, and presentation/report generation. Tests use deterministic packet objects or PCAP fixtures, temporary directories, and mocks where isolation is required. These tests do not transmit packets and do not substitute for physical adapter acceptance.

## Execution summary

The four canonical layer groups were run independently on the evidence date. All passed; counts below are collected test executions, not estimates.

| Unit group | Test modules | Collected | Passed | Failed / skipped |
|---|---|---:|---:|---:|
| Analysis | `test_analysis_layer.py`, `test_analysis_parser_edge_cases.py`, `test_analysis_pipeline.py`, `test_analysis_statistics.py`, `test_analysis_alerts.py` | 45 | 45 | 0 / 0 |
| Capture | `test_capture_layer.py`, `test_concurrent_capture.py` | 42 | 42 | 0 / 0 |
| Storage | `test_storage_query.py` | 25 | 25 | 0 / 0 |
| Presentation | `test_presentation_dashboard.py`, `test_presentation_report_export.py`, `test_report_pdf.py` | 22 | 22 | 0 / 0 |
| **Layer-group total** | 11 modules | **134** | **134** | **0 / 0** |

The full repository suite on the same source tree reports **171 passed, 2 skipped**. The 134 focused cases are a subset of that full suite and must not be added to its total. The two skips are POSIX permission-mode tests that do not execute on Windows; they are not Windows ACL evidence.

## Test design and coverage by layer

| Layer | Behaviors verified | Representative failure / boundary cases |
|---|---|---|
| Analysis | Ethernet/IP/TCP/UDP/ARP/ICMP/DNS metadata parsing; IPv4/IPv6; protocol classification; pipeline ordering/fallback; rate/protocol/talker summaries; heuristic alert matching | Empty, malformed, unsupported link type, missing fields, alert match vs. non-match, and boundary input handling |
| Capture | File replay and callback lifecycle; packet metadata propagation; live backend contract/error mapping; concurrent source aggregation, stop/cancel, and error propagation | Invalid or unavailable source, startup/stream failure, clean cancellation, and no packet-injection behavior |
| Storage | PCAP plus SQLite persistence; metadata migration; session-scoped lookup; protocol/address/time filters; summary and path handling | Missing metadata database remains an error; relative Windows directory round-trip; invalid filters; safe output/no-overwrite paths |
| Presentation | Dashboard/statistics formatting; CSV and PDF report content; session scoping and destination validation | Empty results, invalid destination, overwrite refusal, and metadata-only report assertions |

The canonical executable tests are the modules listed above. `tests/docs/evidence/unit/` contains supporting historical screenshots for selected analysis, capture, storage, and presentation runs. Automated command output and the linked CI run are the authoritative pass/fail evidence; screenshots are supplementary.

## Reproduction

From the repository root on PowerShell:

```powershell
python -m pytest -q tests/test_analysis_layer.py tests/test_analysis_parser_edge_cases.py tests/test_analysis_pipeline.py tests/test_analysis_statistics.py tests/test_analysis_alerts.py
python -m pytest -q tests/test_capture_layer.py tests/test_concurrent_capture.py
python -m pytest -q tests/test_storage_query.py
python -m pytest -q tests/test_presentation_dashboard.py tests/test_presentation_report_export.py tests/test_report_pdf.py
```

Observed results were respectively **45, 42, 25, and 22 passed**. The full-suite command and cross-platform CI result are indexed in the [Test Execution Report](../TEST_EXECUTION_REPORT.md).

## Interpretation and limits

- Unit results establish behavior for the tested inputs and collaborators; they do not establish that all statements or branches are exercised. See the [combined code and branch coverage report](../CODE_AND_BRANCH_COVERAGE_REPORT.md).
- Mocks and replay fixtures cannot establish Wi-Fi monitor mode, live BLE capture, physical multi-adapter behavior, Raspberry Pi throughput, or live packet-loss rates.
- Windows tests do not validate POSIX file modes, and the skipped POSIX tests do not validate Windows ACLs.
- Heuristic alerts are investigative signals, not a malware verdict or proof of compromise.
- The complete SRS disposition is in the [acceptance report](../ACCEPTANCE_TEST_REPORT.md); the documented live capture there is separate system-level evidence, not a unit test.
