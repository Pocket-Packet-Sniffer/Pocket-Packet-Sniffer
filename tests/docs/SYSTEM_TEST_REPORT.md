# System and Integration Test Report

**Purpose:** verify complete connected flows across project boundaries.

**Backend flow:** `tests/test_session_integration.py` exercises Capture → Analysis → Storage → statistics/query → CSV export using generated packet records; `tests/test_cli.py` verifies command workflows; `tests/test_api.py` verifies API capture/replay and retrieval routes.

**Dashboard flow:** `web/tests/e2e/dashboard.spec.ts` exercises onboarding, capture controls, real API-backed data presentation, packet filters/details, local PCAP replay, reports, and responsive layout. The browser tests stub API responses where documented; they do not perform a physical capture.

**Result:** the Python suite and dashboard browser suite passed in the latest recorded CI/release verification. Exact counts and workflow links are in [test execution report](TEST_EXECUTION_REPORT.md).

**Limit:** the complete software flow is verified with fixtures and controlled API responses; physical network equipment is outside this system-test evidence.
