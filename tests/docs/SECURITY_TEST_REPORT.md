# Security Test Report

**Automated checks:** passive-only contract tests (`tests/test_security_contracts.py`), API origin/write protections and payload minimization (`tests/test_api.py`), storage permission behavior where supported (`tests/test_storage_query.py`), plus capture authorization/error handling tests.

**Result:** included in the passing Python CI suite. POSIX permission tests are platform-conditional and may be skipped on Windows. Windows ACL verification is **NOT RUN**.

**Manual/security limits:** no live hostile traffic, Wi-Fi monitor-mode, BLE radio, or Windows ACL security assessment is claimed. Captured traffic can be sensitive; local storage and export guidance is documented in `SECURITY.md` and `Docs/SECURITY_VALIDATION.md`.
