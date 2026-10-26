# Presentation Layer: capture-session report export

This module implements the CSV portion of PPS-07 (SRS REQ-8, STP TC-PRE-02).
It consumes a stored `SessionSummary` and `PacketRecord` values supplied by the caller, so exporting does not require a running capture.

## Usage

```python
from pocket_packet_sniffer.presentation.report_export import export_session_report_csv

path = export_session_report_csv(summary, stored_records, "reports/session-123.csv")
print(f"Report saved to {path}")
```

The destination must not already exist. A `ReportExportError` describes invalid data, a mismatched session, an existing destination, or a write failure. The exporter does not silently overwrite files.

## Integration note

The caller should obtain the summary and records from the storage/query layer before calling the exporter. The current repository API exposes `get_session_summary` and filtered `query`, but `query` does not yet accept a session ID filter. Full integration therefore requires the storage layer to expose a session-scoped record retrieval method (or another agreed query contract). This module intentionally does not invent or modify that storage API.
