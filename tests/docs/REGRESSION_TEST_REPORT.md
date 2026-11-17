# Regression Test Report

**Purpose:** protect previously fixed behavior from returning.

**Representative regression coverage:** relative Windows storage paths (`tests/test_storage_query.py`); capture stop/liveness and transient connection behavior (`tests/test_capture_control.py`, API and dashboard tests); parser edge cases (`tests/test_analysis_parser_edge_cases.py`); metadata/query/API pagination and dashboard updating (`tests/test_api.py`, `web/tests/e2e/dashboard.spec.ts`); and packaged-agent startup (`.github/workflows/release-windows-agent.yml`).

**Result:** regressions run as part of the full Python/browser CI. The tagged v0.2.2 workflow additionally passed its Windows-specific capture-agent and relative-path regression steps. See [CI evidence](TEST_EXECUTION_REPORT.md).
