# Sanity Test Report

**Purpose:** run a small, high-value check after a focused change to see whether its main path still works.

**Repeatable commands:**

```powershell
python -m pytest -q tests/test_storage_query.py
python -m pytest -q tests/test_api.py
cd web; npm run typecheck
```

These are focused developer checks, not a separately named CI job. The release workflow's targeted Windows regression subset and executable health smoke check are recorded in [smoke test report](SMOKE_TEST_REPORT.md).

**Current disposition:** the focused relative-path regression is part of the full passing suite. No separate sanity-only result is claimed unless a run is recorded in the execution report.
