# Component Test Report

**Purpose:** verify a layer or service component at its public boundary, including validation, error handling, and its interaction with collaborators.

**Canonical files:** `tests/test_capture_layer.py`, `test_capture_runner.py`, `test_storage_query.py`, `test_analysis_pipeline.py`, `test_api.py`, `test_architecture_boundaries.py`, and `test_security_contracts.py`.

**Coverage:** capture backend contracts and lifecycle; analysis/parser pipeline behavior; PCAP/SQLite persistence and query; API request/response behavior; origin validation; and layer dependency rules. API tests use FastAPI’s in-process client and temporary repositories.

**Result:** included in the passing Python suite recorded in [test execution report](TEST_EXECUTION_REPORT.md). Component tests using synthetic inputs do not establish live adapter or OS permission behavior.
