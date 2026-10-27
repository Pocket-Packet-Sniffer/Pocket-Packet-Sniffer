from __future__ import annotations

from datetime import UTC, datetime
from threading import Event

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from pocket_packet_sniffer.application.multi_session import MultiCaptureSession
from pocket_packet_sniffer.capture import CapturedPacket, Capturer
from pocket_packet_sniffer.storage import PcapSqliteRepository


class OnePacketThenWaitCapturer(Capturer):
    def __init__(self, interface, source, entered):
        self.interface = interface
        self.source = source
        self.entered = entered

    def capture(self, on_packet, stop_event, count=None):
        frame = bytes(
            Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20")
            / IP(src=self.source, dst="198.51.100.20")
            / TCP()
        )
        on_packet(
            CapturedPacket(
                timestamp=datetime.now(UTC),
                packet_data=frame,
                interface=self.interface,
                link_type=1,
                original_length=len(frame),
            )
        )
        self.entered.set()
        stop_event.wait(2.0)


def test_multi_capture_runs_children_concurrently_and_combines_statistics(tmp_path):
    first_entered = Event()
    second_entered = Event()
    repository = PcapSqliteRepository(tmp_path / "captures")
    session = MultiCaptureSession(
        {
            "ethA": OnePacketThenWaitCapturer("ethA", "192.0.2.10", first_entered),
            "ethB": OnePacketThenWaitCapturer("ethB", "192.0.2.11", second_entered),
        },
        repository,
        session_id="multi-demo",
    )
    session.start()
    try:
        assert first_entered.wait(1.0)
        assert second_entered.wait(1.0)
        snapshot = session.statistics_snapshot()
        assert snapshot["total_packets"] == 2
        assert dict(snapshot["protocols"]) == {"TCP": 2}
        assert dict(snapshot["top_talkers"]) == {"192.0.2.10": 1, "192.0.2.11": 1}
    finally:
        session.stop()
        assert session.wait(timeout=2.0)
    result = session.result()
    assert result.exit_code == 0
    assert set(result.results) == {"ethA", "ethB"}
    stored = repository.query()
    assert len(stored) == 2
    assert {record.interface for record in stored} == {"ethA", "ethB"}
    assert {record.session_id for record in stored} == {
        result.results["ethA"].session_id,
        result.results["ethB"].session_id,
    }


def test_multi_capture_requires_two_named_backends(tmp_path):
    repository = PcapSqliteRepository(tmp_path / "captures")
    with pytest.raises(ValueError, match="at least two"):
        MultiCaptureSession({"one": OnePacketThenWaitCapturer("one", "192.0.2.1", Event())}, repository)
