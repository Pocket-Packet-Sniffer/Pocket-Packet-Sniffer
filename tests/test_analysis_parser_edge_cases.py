"""Regression tests for packet parser edge cases and metadata preservation."""

from datetime import UTC, datetime

import pytest
from scapy.layers.inet import TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import Ether

from pocket_packet_sniffer.analysis.parser import PacketParser
from pocket_packet_sniffer.capture.models import CapturedPacket


@pytest.fixture
def parser():
    return PacketParser()


def make_capture(packet, *, timestamp=None, interface="fixture1", link_type=1):
    raw = bytes(packet)
    return CapturedPacket(
        timestamp=timestamp or datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        packet_data=raw,
        interface=interface,
        link_type=link_type,
        original_length=len(raw),
    )


@pytest.mark.parametrize(
    ("transport", "expected_protocol"),
    [(TCP(), "TCP"), (UDP(), "UDP")],
)
def test_parse_ipv6_transport_protocols(parser, transport, expected_protocol):
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / transport
    )

    record = parser.parse(make_capture(packet))

    assert record is not None
    assert record.protocol == expected_protocol
    assert record.source == "2001:db8::1"
    assert record.destination == "2001:db8::2"


def test_parse_ipv6_icmp_echo_request(parser):
    packet = (
        Ether()
        / IPv6(src="2001:db8::10", dst="2001:db8::20")
        / ICMPv6EchoRequest()
    )

    record = parser.parse(make_capture(packet))

    assert record is not None
    assert record.protocol == "ICMPv6"
    assert record.source == "2001:db8::10"
    assert record.destination == "2001:db8::20"


def test_parse_plain_ethernet_frame_as_other(parser):
    packet = Ether(
        src="02:00:00:00:00:11",
        dst="02:00:00:00:00:22",
        type=0x88B5,
    ) / b"application-specific payload"

    record = parser.parse(make_capture(packet))

    assert record is not None
    assert record.protocol == "OTHER"
    assert record.source == "02:00:00:00:00:11"
    assert record.destination == "02:00:00:00:00:22"
    assert record.source_mac == "02:00:00:00:00:11"
    assert record.destination_mac == "02:00:00:00:00:22"


def test_parse_preserves_capture_metadata_and_backend(parser):
    timestamp = datetime(2026, 5, 6, 7, 8, 9, tzinfo=UTC)
    packet = Ether() / IPv6(src="2001:db8::a", dst="2001:db8::b") / UDP()
    captured = make_capture(
        packet,
        timestamp=timestamp,
        interface="test-interface",
    )

    record = parser.parse(captured, backend="synthetic-fixture")

    assert record is not None
    assert record.timestamp == timestamp
    assert record.packet_size == len(bytes(packet))
    assert record.interface == "test-interface"
    assert record.link_type == 1
    assert record.capture_backend == "synthetic-fixture"


@pytest.mark.parametrize("link_type", [-1, 999, 65535])
def test_unknown_link_types_are_declined(parser, link_type):
    captured = make_capture(Ether() / IPv6() / TCP(), link_type=link_type)

    assert parser.parse(captured) is None


def test_empty_packet_bytes_are_non_fatal(parser):
    captured = CapturedPacket(
        timestamp=datetime(2026, 1, 2, tzinfo=UTC),
        packet_data=b"",
        interface="fixture1",
        link_type=1,
        original_length=0,
    )

    assert parser.parse(captured) is None
