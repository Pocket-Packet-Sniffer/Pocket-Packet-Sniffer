# Unit Test Report

**Purpose:** verify small functions and classes in isolation using controlled packets, temporary storage, and mocked capture interfaces.

**Canonical files:** `tests/test_analysis_layer.py`, `test_analysis_parser_edge_cases.py`, `test_analysis_pipeline.py`, `test_analysis_statistics.py`, `test_analysis_alerts.py`, `test_capture_layer.py`, `test_capture_control.py`, `test_capture_runner.py`, `test_storage_query.py`, `test_presentation_dashboard.py`, `test_presentation_report_export.py`, `test_report_pdf.py`, `test_agent.py`, and focused tests in `test_cli.py` / `test_api.py`.

**Historical component evidence:** the Analysis layer report recorded 42 passing selected executions; the Capture layer report recorded 42 selected executions. See the original write-ups and screenshots under this folder and `../evidence/unit/`. These are dated selections, not the current whole-suite count.

**Current suite result:** see [test execution report](../TEST_EXECUTION_REPORT.md). Unit cases are also included in the full CI suite. The suite uses deterministic PCAP fixtures and mocks; actual NIC/radio operation is not unit-tested.
