from __future__ import annotations

import csv
from datetime import datetime, timezone

import pytest

from pocket_packet_sniffer.presentation.report_export import (
    ReportExportError,
    export_session_report_csv,
)
from pocket_packet_sniffer.storage.models import PacketRecord, SessionSummary


def fixture_data():
    first = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    second = datetime(2026, 1, 1, 10, 0, 1, tzinfo=timezone.utc)
    summary = SessionSummary("session-1", 2, first, second)
    records = [
        PacketRecord("session-1", "TCP", "192.0.2.1", "192.0.2.2", first, b"\x00\x01"),
        PacketRecord("session-1", "UDP", "192.0.2.3", "192.0.2.4", second, b"\x02\x03\x04"),
    ]
    return summary, records


def test_exports_stored_session_summary_and_packet_metadata_to_csv(tmp_path):
    summary, records = fixture_data()
    destination = tmp_path / "session.csv"

    result = export_session_report_csv(summary, records, destination)

    assert result == destination
    with destination.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    assert rows[0]["session_id"] == "session-1"
    assert rows[0]["packet_count"] == "2"
    assert rows[0]["protocol"] == "TCP"
    assert rows[0]["source_address"] == "192.0.2.1"
    assert rows[1]["protocol"] == "UDP"
    assert rows[1]["captured_length"] == "3"


def test_empty_session_still_exports_summary_row(tmp_path):
    summary = SessionSummary("empty-session", 0, None, None)
    destination = tmp_path / "empty.csv"

    export_session_report_csv(summary, [], destination)

    with destination.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["session_id"] == "empty-session"
    assert rows[0]["packet_count"] == "0"
    assert rows[0]["record_id"] == ""


def test_does_not_overwrite_existing_report(tmp_path):
    summary, records = fixture_data()
    destination = tmp_path / "existing.csv"
    destination.write_text("keep this content", encoding="utf-8")

    with pytest.raises(ReportExportError, match="already exists"):
        export_session_report_csv(summary, records, destination)

    assert destination.read_text(encoding="utf-8") == "keep this content"


def test_rejects_records_from_another_session(tmp_path):
    summary, records = fixture_data()
    records[0] = PacketRecord(
        "other-session", "TCP", "192.0.2.1", "192.0.2.2",
        records[0].timestamp, b"\x00\x01"
    )

    with pytest.raises(ReportExportError, match="belong to the requested session"):
        export_session_report_csv(summary, records, tmp_path / "bad.csv")


def test_rejects_mismatched_summary_count(tmp_path):
    summary, records = fixture_data()
    summary = SessionSummary("session-1", 4, summary.first_packet_at, summary.last_packet_at)

    with pytest.raises(ReportExportError, match="reports 4 packets"):
        export_session_report_csv(summary, records, tmp_path / "bad.csv")


def test_reports_invalid_output_path(tmp_path):
    summary, records = fixture_data()
    with pytest.raises(ReportExportError, match="could not write report"):
        export_session_report_csv(summary, records, tmp_path)
