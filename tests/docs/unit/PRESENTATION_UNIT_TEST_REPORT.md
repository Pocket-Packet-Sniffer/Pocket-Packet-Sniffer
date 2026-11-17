# Presentation Layer - Unit Testing

## 1. Objective

Unit testing was performed to verify dashboard rendering and refresh behavior, CSV report export, and PDF report generation.

## 2. Test Files

### 2.1 Dashboard

**File:** `tests/test_presentation_dashboard.py`

Tests dashboard statistics rendering, empty capture handling, invalid statistics, refresh/stop events, and refresh-interval validation.

Result: 13 test executions passed.

### 2.2 Report Export

**File:** `tests/test_presentation_report_export.py`

Tests CSV export of stored session summaries and packet metadata, empty-session export, no-overwrite behavior, session consistency, summary counts, and invalid output paths.

Result: 6 test executions passed.

### 2.3 PDF Report

**File:** `tests/test_report_pdf.py`

Tests PDF structure and metadata, exclusion of packet payloads, no-overwrite behavior, and rejection of mismatched session records.

Result: 3 test executions passed.

## 3. Execution Summary

Each selected test file was executed individually using pytest.

- Total test executions: 22
- Passed: 22
- Failed: 0
- Execution times: dashboard 0.63 seconds; CSV export 0.65 seconds; PDF report 0.56 seconds
- Environment: Windows, Python 3.13.15, pytest 8.3.4

## 4. Screenshot Evidence

Expected evidence location: `tests/docs/evidence/unit/presentation/`

- `02_presentation_dashboard.png`
- `03_presentation_report_export.png`
- `04_presentation_pdf_report.png`

## 5. Conclusion

All 22 selected Presentation Layer test executions passed. The results verify the tested dashboard behavior and CSV/PDF report-export functionality.
