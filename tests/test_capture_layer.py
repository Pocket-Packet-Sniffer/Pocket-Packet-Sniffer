from __future__ import annotations

import struct
import types
from datetime import datetime, timezone
from pathlib import Path
from threading import Event

import pytest

from pocket_packet_sniffer.capture import (
    CaptureBackendUnavailableError,
    CaptureCallbackError,
    CapturedPacket,
    CaptureFileError,
    CaptureInterfaceError,
    CapturePermissionError,
    CaptureStartupError,
    PcapFileCapturer,
    ScapyCapturer,
)


def make_pcap(
    path: Path,
    packets: list[bytes] | None = None,
    *,
    endian: str = "<",
    nanoseconds: bool = False,
    link_type: int = 1,
) -> Path:
    packets = packets if packets is not None else [b"\x00\x01\x02\x03", b"\x10\x11"]
    magic = {
        ("<", False): b"\xd4\xc3\xb2\xa1",
        (">", False): b"\xa1\xb2\xc3\xd4",
        ("<", True): b"\x4d\x3c\xb2\xa1",
        (">", True): b"\xa1\xb2\x3c\x4d",
    }[(endian, nanoseconds)]
    with path.open("wb") as stream:
        stream.write(magic)
        stream.write(struct.pack(f"{endian}HHIIII", 2, 4, 0, 0, 65535, link_type))
        for index, packet in enumerate(packets):
            fraction = (123_456_000 if nanoseconds else 123_456) + index
            stream.write(struct.pack(f"{endian}IIII", 1_700_000_000 + index, fraction, len(packet), len(packet)))
            stream.write(packet)
    return path


def test_pcap_replay_emits_backend_neutral_records_with_metadata(tmp_path):
    pcap = make_pcap(tmp_path / "sample.pcap", [b"ethernet-frame", b"second-frame"])
    records = []
    PcapFileCapturer(pcap).capture(records.append, Event())

    assert len(records) == 2
    assert all(isinstance(record, CapturedPacket) for record in records)
    assert records[0].packet_data == b"ethernet-frame"
    assert records[0].interface == "sample.pcap"
    assert records[0].link_type == 1
    assert records[0].original_length == len(b"ethernet-frame")
    assert records[0].timestamp == datetime.fromtimestamp(1_700_000_000, timezone.utc).replace(microsecond=123456)
    assert records[1].packet_data == b"second-frame"


def test_pcap_replay_supports_big_endian_nanosecond_files(tmp_path):
    pcap = make_pcap(tmp_path / "nano.pcap", [b"frame"], endian=">", nanoseconds=True, link_type=101)
    records = []
    PcapFileCapturer(pcap).capture(records.append, Event())
    assert records[0].link_type == 101
    assert records[0].timestamp.microsecond == 123456


def test_count_limits_number_of_replayed_packets(tmp_path):
    pcap = make_pcap(tmp_path / "many.pcap", [b"a", b"b", b"c"])
    records = []
    PcapFileCapturer(pcap).capture(records.append, Event(), count=2)
    assert [record.packet_data for record in records] == [b"a", b"b"]


def test_stop_event_stops_replay(tmp_path):
    pcap = make_pcap(tmp_path / "stop.pcap", [b"a", b"b", b"c"])
    stop = Event()
    records = []
    PcapFileCapturer(pcap, delay=0.01).capture(lambda record: (records.append(record), stop.set()), stop)
    assert len(records) == 1


def test_missing_pcap_reports_clear_error(tmp_path):
    with pytest.raises(CaptureFileError, match="does not exist"):
        PcapFileCapturer(tmp_path / "missing.pcap").capture(lambda _record: None, Event())


@pytest.mark.parametrize(
    "content",
    [
        b"not a pcap",
        b"\xd4\xc3\xb2\xa1short",
        b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 1, 1, 0, 0, 65535, 1),
    ],
)
def test_malformed_pcap_reports_clear_error(tmp_path, content):
    pcap = tmp_path / "bad.pcap"
    pcap.write_bytes(content)
    with pytest.raises(CaptureFileError):
        PcapFileCapturer(pcap).capture(lambda _record: None, Event())


def test_truncated_pcap_payload_reports_clear_error(tmp_path):
    pcap = tmp_path / "truncated.pcap"
    pcap.write_bytes(
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 0, 5, 5)
        + b"xy"
    )
    with pytest.raises(CaptureFileError, match="truncated packet payload"):
        PcapFileCapturer(pcap).capture(lambda _record: None, Event())


def test_callback_failure_is_reported_as_capture_error(tmp_path):
    pcap = make_pcap(tmp_path / "callback.pcap", [b"frame"])

    def broken(_record):
        raise RuntimeError("analysis failed")

    with pytest.raises(CaptureCallbackError, match="callback failed") as error:
        PcapFileCapturer(pcap).capture(broken, Event())

    assert "RuntimeError: analysis failed" in str(error.value)
    assert error.value.__cause__ is not None
    assert "frame" not in str(error.value)


def test_invalid_count_is_rejected(tmp_path):
    pcap = make_pcap(tmp_path / "count.pcap", [b"frame"])
    with pytest.raises(ValueError, match="positive integer"):
        PcapFileCapturer(pcap).capture(lambda _record: None, Event(), count=0)


class FakePacket:
    time = 1_700_000_000.123456
    sniffed_on = "eth-test"
    wirelen = 4

    def __bytes__(self):
        return b"\x01\x02\x03\x04"


class FakeSniffer:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.running = False
        self.thread = None
        self.exception = None

    def start(self):
        self.running = True
        self.kwargs["prn"](FakePacket())
        self.kwargs["started_callback"]()

    def stop(self, join=True):
        self.running = False

    def join(self, *args, **kwargs):
        self.running = False


def install_fake_scapy(monkeypatch, *, interfaces=None, sniffer_factory=FakeSniffer, layer_map=None):
    fake_all = types.ModuleType("scapy.all")
    fake_all.AsyncSniffer = sniffer_factory
    fake_all.get_if_list = lambda: interfaces if interfaces is not None else ["eth-test"]
    fake_all.conf = types.SimpleNamespace(l2types=types.SimpleNamespace(layer2num=layer_map or {FakePacket: 1}))
    fake_scapy = types.ModuleType("scapy")
    fake_scapy.__path__ = []
    fake_all.__package__ = "scapy"
    monkeypatch.setitem(__import__("sys").modules, "scapy", fake_scapy)
    monkeypatch.setitem(__import__("sys").modules, "scapy.all", fake_all)


def test_scapy_backend_delivers_raw_packet_without_dependency_leak(monkeypatch):
    install_fake_scapy(monkeypatch)
    records = []
    ScapyCapturer("eth-test").capture(records.append, Event(), count=1)
    assert len(records) == 1
    assert records[0].packet_data == b"\x01\x02\x03\x04"
    assert records[0].interface == "eth-test"
    assert records[0].timestamp.tzinfo is not None


def test_unavailable_interface_lists_detected_interfaces(monkeypatch):
    install_fake_scapy(monkeypatch, interfaces=["eth-test", "lo"])
    with pytest.raises(CaptureInterfaceError) as error:
        ScapyCapturer("wlan-missing").capture(lambda _record: None, Event())
    assert "wlan-missing" in str(error.value)
    assert "eth-test" in str(error.value)


def test_permission_failure_is_actionable(monkeypatch):
    class PermissionSniffer(FakeSniffer):
        def start(self):
            raise PermissionError("Operation not permitted")

    install_fake_scapy(monkeypatch, sniffer_factory=PermissionSniffer)
    with pytest.raises(CapturePermissionError, match="required permissions"):
        ScapyCapturer("eth-test").capture(lambda _record: None, Event())


def test_backend_startup_failure_is_reported(monkeypatch):
    class BrokenSniffer(FakeSniffer):
        def start(self):
            raise OSError("adapter is down")

    install_fake_scapy(monkeypatch, sniffer_factory=BrokenSniffer)
    with pytest.raises(CaptureStartupError, match="adapter is down"):
        ScapyCapturer("eth-test").capture(lambda _record: None, Event())


def test_missing_scapy_dependency_is_clear(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "scapy", None)
    monkeypatch.setitem(sys.modules, "scapy.all", None)
    with pytest.raises(CaptureBackendUnavailableError, match="requires Scapy"):
        ScapyCapturer("eth-test").capture(lambda _record: None, Event())


def test_keyboard_interrupt_stops_background_live_sniffer(monkeypatch):
    class InterruptingEvent(Event):
        def wait(self, timeout=None):
            raise KeyboardInterrupt()

    instances = []

    class TrackingSniffer(FakeSniffer):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.stopped = False
            instances.append(self)

        def stop(self, join=True):
            self.stopped = True
            super().stop(join)

    install_fake_scapy(monkeypatch, sniffer_factory=TrackingSniffer)
    stop_event = InterruptingEvent()

    with pytest.raises(KeyboardInterrupt):
        ScapyCapturer("eth-test").capture(lambda _record: None, stop_event)

    assert stop_event.is_set()
    assert len(instances) == 1
    assert instances[0].stopped
    assert instances[0].running is False
