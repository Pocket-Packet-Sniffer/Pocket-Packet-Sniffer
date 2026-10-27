# Presentation Layer: capture-session report export

This module implements CSV and PDF portions of PPS-07 (SRS REQ-8, STP TC-PRE-02) on branch `feat/PPS-28-srs-compliance`. It consumes a stored `SessionSummary` and `PacketRecord` values supplied by the caller, so exporting does not require a running capture.

## Usage

```python
from pocket_packet_sniffer.presentation.report_export import export_session_report_csv

path = export_session_report_csv(summary, stored_records, "reports/session-123.csv")
print(f"Report saved to {path}")

from pocket_packet_sniffer.presentation.report_pdf import export_session_report_pdf
pdf_path = export_session_report_pdf(summary, stored_records, "reports/session-123.pdf")
print(f"Report saved to {pdf_path}")
```

The destination must not already exist. A `ReportExportError` describes invalid data, a mismatched session, an existing destination, or a write failure. The exporter does not silently overwrite files.

## Data and safety

Both formats contain session summary and packet metadata only; captured payload bytes are never written into the report. Both use exclusive file creation and refuse to overwrite an existing destination. The CLI obtains records through `Repository.query_session(session_id)`, avoiding report code that reaches into private SQLite tables.

## Validation

Automated export tests verify format markers/content, session matching, count validation, payload exclusion for PDF, and no-overwrite behavior. Actual CI status for the compliance branch must be checked before this code is merged to `main`.
