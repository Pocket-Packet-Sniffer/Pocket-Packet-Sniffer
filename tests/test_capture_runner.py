from __future__ import annotations

import io
from datetime import datetime, timezone
from threading import Event

import pytest

from pocket_packet_sniffer.capture import (
    CaptureInterfaceError,
    CapturePermissionError,
    CapturedPacket,
    Capturer,
)
from pocket_packet_sniffer.presentation.capture_runner import (
    EXIT_CAPTURE_ERROR,
    EXIT_INTERRUPTED,
    EXIT_SUCCESS,
    run_capture_with_error_handling,
)


class StubCapturer(Capturer):
    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error

    def capture(self, on_packet, stop_event, count=None) -> None:
        if self.error is not None:
            raise self.error
        on_packet(
            CapturedPacket(
                timestamp=datetime.now(timezone.utc),
                packet_data=b"test-frame",
                interface="fixture.pcap",
                link_type=1,
                original_length=len(b"test-frame"),
            )
        )


@pytest.mark.parametrize(
    "error",
    [
        CaptureInterfaceError("interface 'missing0' is unavailable"),
        CapturePermissionError("permission denied while capturing"),
    ],
)
def test_capture_domain_errors_return_stable_nonzero_status_without_traceback(error):
    stderr = io.StringIO()

    status = run_capture_with_error_handling(StubCapturer(error), lambda _packet: None, Event(), stderr=stderr)

    assert status == EXIT_CAPTURE_ERROR
    assert str(error) in stderr.getvalue()
    assert "Traceback" not in stderr.getvalue()


def test_successful_capture_returns_zero_and_keeps_packet_callback():
    stderr = io.StringIO()
    received = []

    status = run_capture_with_error_handling(StubCapturer(), received.append, Event(), count=1, stderr=stderr)

    assert status == EXIT_SUCCESS
    assert len(received) == 1
    assert received[0].packet_data == b"test-frame"
    assert stderr.getvalue() == ""


def test_keyboard_interrupt_requests_stop_and_returns_interrupted_status():
    stop_event = Event()
    stderr = io.StringIO()

    status = run_capture_with_error_handling(
        StubCapturer(KeyboardInterrupt()),
        lambda _packet: None,
        stop_event,
        stderr=stderr,
    )

    assert status == EXIT_INTERRUPTED
    assert stop_event.is_set()
    assert "capture interrupted" in stderr.getvalue()


def test_unexpected_programming_errors_are_not_hidden():
    class BuggyCapturer(Capturer):
        def capture(self, on_packet, stop_event, count=None) -> None:
            raise RuntimeError("unexpected programmer error")

    with pytest.raises(RuntimeError, match="unexpected programmer error"):
        run_capture_with_error_handling(BuggyCapturer(), lambda _packet: None, Event(), stderr=io.StringIO())
