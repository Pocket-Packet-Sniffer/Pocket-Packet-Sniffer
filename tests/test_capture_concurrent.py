from datetime import UTC, datetime
from threading import Event

import pytest

from pocket_packet_sniffer.capture.base import Capturer
from pocket_packet_sniffer.capture.concurrent import (
    ConcurrentCaptureError,
    ConcurrentCaptureRunner,
)
from pocket_packet_sniffer.capture.models import CapturedPacket


def packet(interface: str) -> CapturedPacket:
    return CapturedPacket(
        timestamp=datetime.now(UTC),
        packet_data=b"\x00",
        interface=interface,
        link_type=1,
        original_length=1,
    )


class FixtureCapturer(Capturer):
    def __init__(self, name, packets=(), error=None):
        self.name = name
        self.packets = packets
        self.error = error

    def capture(self, on_packet, stop_event: Event, count=None):
        for index, item in enumerate(self.packets):
            if stop_event.is_set() or (count is not None and index >= count):
                break
            on_packet(item)
        if self.error:
            raise self.error


def test_concurrent_runner_delivers_packets_with_backend_context():
    runner = ConcurrentCaptureRunner([
        FixtureCapturer("eth", [packet("eth0")]),
        FixtureCapturer("fixture", [packet("fixture0")]),
    ])
    received = []
    results = runner.run(lambda backend, item: received.append((backend, item.interface)))
    assert sorted(received) == [("eth", "eth0"), ("fixture", "fixture0")]
    assert [result.backend for result in results] == ["eth", "fixture"]


def test_concurrent_runner_requires_two_unique_backends():
    with pytest.raises(ValueError, match="at least two"):
        ConcurrentCaptureRunner([FixtureCapturer("only")])
    with pytest.raises(ValueError, match="unique"):
        ConcurrentCaptureRunner([FixtureCapturer("same"), FixtureCapturer("same")])


def test_concurrent_runner_propagates_backend_errors_and_stops_peers():
    runner = ConcurrentCaptureRunner([
        FixtureCapturer("broken", error=RuntimeError("capture failed")),
        FixtureCapturer("peer", [packet("peer0")]),
    ])
    with pytest.raises(ConcurrentCaptureError) as exc:
        runner.run(lambda backend, item: None)
    assert "broken" in str(exc.value)
    assert runner.stop_event.is_set()


def test_concurrent_runner_validates_packet_count():
    runner = ConcurrentCaptureRunner([FixtureCapturer("a"), FixtureCapturer("b")])
    with pytest.raises(ValueError, match="positive integer"):
        runner.run(lambda backend, item: None, count_per_backend=0)
