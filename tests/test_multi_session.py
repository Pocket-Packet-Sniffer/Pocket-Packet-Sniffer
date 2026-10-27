from __future__ import annotations

from datetime import UTC, datetime
from threading import Event
from time import sleep

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from pocket_packet_sniffer.application.multi_session import MultiCaptureSession
from pocket_packet_sniffer.capture import CapturedPacket, Capturer
from pocket_packet_sniffer.storage import PcapSqliteRepository


class FixtureCapturer(Capturer):
    def __init__(self, interface, link_type=1):
        self.interface = interface
        self.name = f"fixture-{interface}"
        self.link_type = link_type

    def capture(self, on_packet, stop_event, count=None):
        raw = bytes((Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / TCP()) if self.link_type == 1 else (IP(src="192.0.2.1", dst="198.51.100.2") / TCP()))
        packet = CapturedPacket(
            timestamp=datetime.now(UTC),
            packet_data=raw,
            interface=self.interface,
            link_type=self.link_type,
            original_length=len(raw),
        )
        if not stop_event.is_set():
            on_packet(packet)


def test_multi_capture_session_uses_separate_sessions_for_distinct_link_types(tmp_path):
    repository = PcapSqliteRepository(tmp_path / "captures")
    multi = MultiCaptureSession(
        [FixtureCapturer("eth0", link_type=1), FixtureCapturer("raw0", link_type=101)],
        repository,
        session_id="multi-demo",
    )

    result = multi.run(Event())

    assert result.exit_code == 0
    assert result.packets_seen == 2
    assert result.packets_stored == 2
    assert len(result.sessions) == 2
    records = repository.query()
    assert {record.interface for record in records} == {"eth0", "raw0"}
    assert len({record.session_id for record in records}) == 2
    assert multi.statistics_snapshot()["total_packets"] == 2
