# Presentation Layer Unit Test Report

**Evidence revision:** source merged to `main` as `0839abf`
**Focused result:** **22 passed, 0 failed**
**CI:** [run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) passed.

## Objective

Verify presentation-layer formatting, statistics refresh/stop behavior, and local CSV/PDF report generation from stored packet metadata.

## Test modules and cases

| Test module | Test focus |
|---|---|
| `tests/test_presentation_dashboard.py` | Statistics rendering, empty/invalid data, refresh and stop events, interval validation |
| `tests/test_presentation_report_export.py` | Session-scoped CSV summaries and packet metadata, empty sessions, no-overwrite handling, consistency and invalid destinations |
| `tests/test_report_pdf.py` | PDF structure/metadata, payload exclusion, no-overwrite handling, mismatched session validation |

These are backend/CLI presentation unit tests. Dashboard browser behavior is separately covered by 13 Playwright tests in the [system test report](../SYSTEM_TEST_REPORT.md).

## Execution

```powershell
python -m pytest -q tests/test_presentation_dashboard.py tests/test_presentation_report_export.py tests/test_report_pdf.py
```

**Observed:** 22 passed in 1.01 seconds; 0 failed. These tests are a subset of the full Python result.

## Evidence

Historical supporting screenshots are in `tests/docs/evidence/unit/presentation/screenshots/`: dashboard renderer, report export, and PDF report. The current exact command result and CI #731 provide current pass/fail evidence.

## Interpretation and limits

Passing unit tests establish tested formatting/export behavior, not whether reports are complete for every possible protocol or safe to share without review. Exports are metadata-oriented, but capture files themselves may contain sensitive packet bytes. This unit report does not measure frontend accessibility or human usability; see the [Usability Test Report](../USABILITY_TEST_REPORT.md).
