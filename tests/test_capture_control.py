from __future__ import annotations

from threading import Event
from time import monotonic, sleep

import pytest

from pocket_packet_sniffer.presentation.capture_control import (
    CaptureControl,
    CaptureControlError,
)


def test_stop_request_from_another_cli_context_sets_stop_event(tmp_path):
    control = CaptureControl(tmp_path, "session-one", "pcap-file", poll_interval=0.01)
    stop_event = Event()
    control.activate()
    control.start_watcher(stop_event)
    try:
        assert CaptureControl.request_stop(tmp_path, "session-one") is True
        deadline = monotonic() + 1
        while not stop_event.is_set() and monotonic() < deadline:
            sleep(0.01)
        assert stop_event.is_set()
    finally:
        control.close()
    assert not control.active_path.exists()
    assert not control.stop_path.exists()


def test_request_for_inactive_session_returns_false(tmp_path):
    tmp_path.mkdir(exist_ok=True)
    assert CaptureControl.request_stop(tmp_path, "missing-session") is False


def test_control_refuses_second_active_owner_for_same_session(tmp_path):
    first = CaptureControl(tmp_path, "same-session", "pcap-file")
    second = CaptureControl(tmp_path, "same-session", "scapy-live")
    first.activate()
    try:
        with pytest.raises(CaptureControlError, match="already has an active process"):
            second.activate()
    finally:
        first.close()


def test_unreadable_active_marker_fails_closed(tmp_path):
    first = CaptureControl(tmp_path, "broken-marker", "pcap-file")
    first.activate()
    first.active_path.write_text("not-json", encoding="utf-8")
    second = CaptureControl(tmp_path, "broken-marker", "pcap-file")
    try:
        with pytest.raises(CaptureControlError, match="unreadable"):
            second.activate()
    finally:
        first.close()



def test_private_file_publishes_complete_marker_atomically(tmp_path, monkeypatch):
    target = tmp_path / ".stop.request"
    expected = '{"session_id":"session-one","requested_unix":1}'
    original_link = __import__("os").link
    observed = []

    def checked_link(source, destination, *args, **kwargs):
        source_path = Path(source)
        destination_path = Path(destination)
        assert not destination_path.exists()
        assert source_path.read_text(encoding="utf-8") == expected
        observed.append(True)
        return original_link(source, destination, *args, **kwargs)

    monkeypatch.setattr("os.link", checked_link)
    CaptureControl._private_file(target, expected)

    assert observed == [True]
    assert target.read_text(encoding="utf-8") == expected
    assert not list(tmp_path.glob("*.tmp"))
    assert not list(tmp_path.glob(".*.tmp"))
