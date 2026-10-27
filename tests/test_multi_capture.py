from __future__ import annotations

from datetime import UTC, datetime
from time import sleep
from threading import Event

import pytest

from pocket_packet_sniffer.capture import Capturer, CapturedPacket
from pocket_packet_sniffer.capture.errors import CaptureStartupError
from pocket_packet_sniffer.capture.multi import MultiCapturer


def packet(interface: str) -> CapturedPacket:
    return CapturedPacket(
        timestamp=datetime.now(UTC),
        packet_data=b"frame",
        interface=interface,
        link_type=1,
        original_length=5,
    )


class FiniteCapturer(Capturer):
    def __init__(self, name: str, amount: int = 3, delay: float = 0.001):
        self.name = name
        self.amount = amount
        self.delay = delay

    def capture(self, on_packet, stop_event, count=None):
        for _ in range(self.amount):
            if stop_event.is_set():
                return
            on_packet(packet(self.name))
            sleep(self.delay)


def test_multi_capturer_combines_distinct_backend_streams():
    received = []
    MultiCapturer([FiniteCapturer("eth0"), FiniteCapturer("ble0")]).capture(
        received.append, Event()
    )

    assert len(received) == 6
    assert {item.interface for item in received} == {"eth0", "ble0"}


def test_multi_capturer_combined_count_is_a_global_limit():
    received = []
    MultiCapturer([FiniteCapturer("eth0", 100), FiniteCapturer("wlan0", 100)]).capture(
        received.append, Event(), count=5
    )

    assert len(received) == 5


def test_multi_capturer_requires_two_distinct_backends():
    backend = FiniteCapturer("eth0")
    with pytest.raises(ValueError, match="at least two"):
        MultiCapturer([backend])
    with pytest.raises(ValueError, match="distinct"):
        MultiCapturer([backend, backend])


def test_multi_capturer_stops_peers_and_reports_backend_error():
    class BrokenCapturer(Capturer):
        name = "broken"

        def capture(self, on_packet, stop_event, count=None):
            raise CaptureStartupError("fixture backend failed")

    received = []
    with pytest.raises(CaptureStartupError, match="fixture backend failed"):
        MultiCapturer([BrokenCapturer(), FiniteCapturer("eth0", 1000)]).capture(
            received.append, Event()
        )
