from __future__ import annotations

from datetime import datetime, timezone

import pytest

from pocket_packet_sniffer.presentation.report_export import ReportExportError
from pocket_packet_sniffer.presentation.report_pdf import export_session_report_pdf
from pocket_packet_sniffer.storage.models import PacketRecord, SessionSummary


def data():
    timestamp = datetime(2026, 10, 27, tzinfo=timezone.utc)
    summary = SessionSummary("pdf-session", 1, timestamp, timestamp)
    record = PacketRecord(
        "pdf-session",
        "TCP",
        "192.0.2.1",
        "198.51.100.2",
        timestamp,
        b"never-include-this-payload",
        interface="eth-demo",
        capture_backend="scapy-live",
    )
    return summary, [record]


def test_exports_valid_pdf_structure_and_metadata_without_payload(tmp_path):
    summary, records = data()
    destination = tmp_path / "session.pdf"

    result = export_session_report_pdf(summary, records, destination)
    content = destination.read_bytes()

    assert result == destination
    assert content.startswith(b"%PDF-1.4")
    assert b"/Type /Catalog" in content
    assert b"xref" in content
    assert content.rstrip().endswith(b"%%EOF")
    assert b"pdf-session" in content
    assert b"scapy-live" in content
    assert b"never-include-this-payload" not in content


def test_pdf_export_does_not_overwrite_existing_destination(tmp_path):
    summary, records = data()
    destination = tmp_path / "existing.pdf"
    destination.write_bytes(b"preserve me")

    with pytest.raises(ReportExportError, match="already exists"):
        export_session_report_pdf(summary, records, destination)

    assert destination.read_bytes() == b"preserve me"


def test_pdf_export_rejects_mismatched_session_records(tmp_path):
    summary, records = data()
    other = PacketRecord(
        "different-session",
        "TCP",
        "192.0.2.1",
        "198.51.100.2",
        records[0].timestamp,
        b"packet",
    )
    with pytest.raises(ReportExportError, match="belong to the requested session"):
        export_session_report_pdf(summary, [other], tmp_path / "bad.pdf")
