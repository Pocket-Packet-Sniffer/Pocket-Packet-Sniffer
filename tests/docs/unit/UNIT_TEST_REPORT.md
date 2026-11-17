# Unit Test Report

**Purpose:** verify individual functions and classes in isolation using controlled packets, temporary storage, and mocked capture interfaces.

## Canonical unit-test files

- **Analysis:** `tests/test_analysis_layer.py`, `tests/test_analysis_parser_edge_cases.py`, `tests/test_analysis_pipeline.py`, `tests/test_analysis_statistics.py`, and `tests/test_analysis_alerts.py`.
- **Capture:** `tests/test_capture_layer.py` and `tests/test_concurrent_capture.py`.
- **Storage:** `tests/test_storage_query.py`.
- **Presentation:** `tests/test_presentation_dashboard.py`, `tests/test_presentation_report_export.py`, and `tests/test_report_pdf.py`.

Focused tests in `tests/test_cli.py`, `tests/test_api.py`, and `tests/test_agent.py` provide additional command, API, and configuration coverage; they are not included in the four-layer unit-test subtotal below.

## Selected layer execution summary

| Layer | Selected test executions | Passed | Failed |
|---|---:|---:|---:|
| Analysis | 42 | 42 | 0 |
| Capture | 42 | 42 | 0 |
| Storage | 25 | 25 | 0 |
| Presentation | 22 | 22 | 0 |
| **Total** | **131** | **131** | **0** |

The Analysis and Capture counts are the selected executions recorded in their existing layer reports. Storage and Presentation were executed individually on Windows with Python 3.13.15 and pytest 8.3.4. See the dedicated reports in this directory.

## Full-suite verification

The full command `pytest tests/ -v` collected **173 items** and completed with **171 passed, 2 skipped, 0 failed in 9.21 seconds** on Windows, Python 3.13.15, pytest 8.3.4. The two skips are POSIX file-mode checks that do not apply to Windows ACLs. One Starlette deprecation warning was emitted by the FastAPI TestClient import; it did not cause a test failure.

The full-suite result includes the unit tests and additional API, CLI, integration, security, architecture, agent, and benchmark tests. It must not be added to the 131 selected layer executions because it includes those same tests.

See the [Test Execution Report](../TEST_EXECUTION_REPORT.md) for historical CI, coverage, dashboard, and hardware-verification context.

## Limitations

The tests use deterministic PCAP fixtures, temporary storage, and mocked capture interfaces where applicable. Passing automated tests does not establish actual Wi-Fi monitor-mode or BLE adapter operation, simultaneous physical-adapter capture, Raspberry Pi throughput, live packet-drop rates, or Windows ACL behavior. Those require separate target-hardware/manual verification.
