from __future__ import annotations

import csv
from datetime import UTC, datetime, timedelta
from threading import Event

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from pocket_packet_sniffer.analysis.parser import PacketParser
from pocket_packet_sniffer.analysis.pipeline import AnalyzerPipeline
from pocket_packet_sniffer.application.session import CaptureSession
from pocket_packet_sniffer.capture import CapturedPacket, Capturer
from pocket_packet_sniffer.presentation import export_session_report_csv, render_stats
from pocket_packet_sniffer.storage import PcapSqliteRepository


class FixtureCapturer(Capturer):
    name = "synthetic-pcap"

    def __init__(self, records):
        self.records = records

    def capture(self, on_packet, stop_event, count=None):
        delivered = 0
        for record in self.records:
            if stop_event.is_set():
                return
            if count is not None and delivered >= count:
                return
            on_packet(record)
            delivered += 1


def captured(packet_bytes, *, timestamp, link_type=1):
    return CapturedPacket(
        timestamp=timestamp,
        packet_data=packet_bytes,
        interface="synthetic0.pcap",
        link_type=link_type,
        original_length=len(packet_bytes),
    )


def test_capture_analysis_storage_statistics_query_and_csv_export_end_to_end(tmp_path):
    """Exercise the PCAP-fixture path across Analysis, Storage, Query and CSV export.

    Covers the controlled-fixture portions of STP TC-ANA-01, TC-STO-01,
    TC-STO-02, TC-PRE-01 and TC-PRE-02. It does not replace live-interface
    verification for TC-CAP-01.
    """
    start = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
    frames = [
        captured(
            bytes(Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP()),
            timestamp=start,
        ),
        captured(
            bytes(Ether() / IP(src="192.0.2.10", dst="198.51.100.30") / UDP()),
            timestamp=start + timedelta(seconds=1),
        ),
        captured(b"unsupported-link", timestamp=start + timedelta(seconds=2), link_type=99999),
    ]
    repository = PcapSqliteRepository(tmp_path / "captures")
    session = CaptureSession(
        FixtureCapturer(frames),
        repository,
        session_id="integration-session",
        analyzer=AnalyzerPipeline([PacketParser()]),
    )

    result = session.run(Event(), count=3)

    assert result.exit_code == 0
    assert result.packets_seen == 3
    assert result.packets_stored == 2
    assert result.packets_ignored == 1

    stored = repository.query()
    assert [record.protocol for record in stored] == ["TCP", "UDP"]
    assert stored[0].packet_data == frames[0].packet_data
    assert stored[0].source_address == "192.0.2.10"
    assert stored[0].destination_address == "198.51.100.20"
    assert stored[0].session_id == "integration-session"

    filtered = repository.query(protocol="TCP", address="192.0.2.10")
    assert len(filtered) == 1
    assert filtered[0].record_id == stored[0].record_id

    summary = repository.get_session_summary("integration-session")
    assert summary.packet_count == 2

    snapshot = session.statistics_snapshot()
    assert snapshot["total_packets"] == 2
    assert snapshot["total_bytes"] == sum(frame.original_length for frame in frames[:2])
    assert dict(snapshot["protocols"]) == {"TCP": 1, "UDP": 1}
    assert dict(snapshot["top_talkers"])["192.0.2.10"] == 2
    display = render_stats(snapshot)
    assert "Packets: 2" in display
    assert "TCP" in display
    assert "192.0.2.10" in display

    report_path = tmp_path / "session.csv"
    export_session_report_csv(summary, stored, report_path)
    with report_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    assert rows[0]["session_id"] == "integration-session"
    assert rows[0]["packet_count"] == "2"
