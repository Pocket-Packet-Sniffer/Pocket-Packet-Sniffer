from __future__ import annotations

from datetime import datetime, timezone
from threading import Event

import pytest

from pocket_packet_sniffer.capture.base import Capturer
from pocket_packet_sniffer.capture.concurrent import ConcurrentCapturer
from pocket_packet_sniffer.capture.errors import CaptureStartupError
from pocket_packet_sniffer.capture.models import CapturedPacket


def packet(interface: str, link_type: int) -> CapturedPacket:
    return CapturedPacket(
        timestamp=datetime(2026, 10, 27, tzinfo=timezone.utc),
        packet_data=b"fixture-frame",
        interface=interface,
        link_type=link_type,
        original_length=13,
    )


class FiniteCapturer(Capturer):
    def __init__(self, name: str, interface: str, link_type: int, total: int = 3):
        self.name = name
        self.interface = interface
        self.link_type = link_type
        self.total = total

    def capture(self, on_packet, stop_event, count=None):
        for _ in range(self.total):
            if stop_event.is_set():
                return
            on_packet(packet(self.interface, self.link_type))


class WaitingCapturer(Capturer):
    name = "waiting"

    def capture(self, on_packet, stop_event, count=None):
        stop_event.wait(2)


class FailingCapturer(Capturer):
    name = "broken"

    def capture(self, on_packet, stop_event, count=None):
        raise CaptureStartupError("synthetic backend failure")


def test_concurrent_capture_preserves_interface_backend_and_link_type():
    capturers = [
        FiniteCapturer("ethernet", "eth-demo", 1),
        FiniteCapturer("bluetooth", "ble-demo", 251),
    ]
    received: list[CapturedPacket] = []

    ConcurrentCapturer(capturers).capture(received.append, Event())

    assert len(received) == 6
    assert {item.interface for item in received} == {"eth-demo", "ble-demo"}
    assert {item.capture_backend for item in received} == {"ethernet", "bluetooth"}
    assert {item.link_type for item in received} == {1, 251}


def test_aggregate_count_stops_all_backends_at_requested_total():
    capturers = [
        FiniteCapturer("first", "fixture-a", 1, total=10),
        FiniteCapturer("second", "fixture-b", 1, total=10),
    ]
    received: list[CapturedPacket] = []

    ConcurrentCapturer(capturers).capture(received.append, Event(), count=4)

    assert len(received) == 4


def test_backend_failure_stops_other_backend_and_propagates():
    capturer = ConcurrentCapturer([FailingCapturer(), WaitingCapturer()])

    with pytest.raises(CaptureStartupError, match="synthetic backend failure"):
        capturer.capture(lambda _packet: None, Event())


def test_concurrent_capture_requires_two_unique_backends():
    single = FiniteCapturer("only", "eth-demo", 1)
    with pytest.raises(ValueError, match="at least two"):
        ConcurrentCapturer([single])
    with pytest.raises(ValueError, match="more than once"):
        ConcurrentCapturer([single, single])


def test_keyboard_interrupt_stops_and_joins_all_concurrent_backends(monkeypatch):
    import threading

    import pocket_packet_sniffer.capture.concurrent as concurrent_module

    real_event = threading.Event
    finished_wait_calls = 0
    stopped: list[str] = []

    class InterruptingFinishedEvent:
        def __init__(self):
            self._event = real_event()

        def set(self):
            self._event.set()

        def is_set(self):
            return self._event.is_set()

        def wait(self, timeout=None):
            nonlocal finished_wait_calls
            finished_wait_calls += 1
            if finished_wait_calls == 1:
                raise KeyboardInterrupt
            return self._event.wait(timeout)

    event_calls = 0

    def event_factory():
        nonlocal event_calls
        event_calls += 1
        if event_calls == 1:
            return real_event()
        if event_calls == 2:
            return InterruptingFinishedEvent()
        return real_event()

    class WaitingForStopCapturer(Capturer):
        def __init__(self, name):
            self.name = name

        def capture(self, on_packet, stop_event, count=None):
            stop_event.wait()
            stopped.append(self.name)

    monkeypatch.setattr(concurrent_module, "Event", event_factory)
    external_stop = real_event()

    with pytest.raises(KeyboardInterrupt):
        ConcurrentCapturer(
            [WaitingForStopCapturer("first"), WaitingForStopCapturer("second")]
        ).capture(lambda _packet: None, external_stop)

    assert external_stop.is_set()
    assert sorted(stopped) == ["first", "second"]
