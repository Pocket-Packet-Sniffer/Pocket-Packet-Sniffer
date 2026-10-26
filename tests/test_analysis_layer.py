from datetime import UTC, datetime

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from pocket_packet_sniffer.analysis.parser import PacketParser
from pocket_packet_sniffer.capture.models import CapturedPacket


def captured(packet, link_type=1):
    raw = bytes(packet)
    return CapturedPacket(
        timestamp=datetime.now(UTC),
        packet_data=raw,
        interface="test0",
        link_type=link_type,
        original_length=len(raw),
    )


def test_parse_tcp_packet():
    packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / TCP()
    record = PacketParser().parse(captured(packet))
    assert record is not None
    assert record.source == "192.0.2.1"
    assert record.destination == "198.51.100.2"
    assert record.protocol == "TCP"


def test_parse_udp_packet():
    packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / UDP()
    record = PacketParser().parse(captured(packet))
    assert record is not None
    assert record.protocol == "UDP"


def test_parse_arp_packet():
    packet = Ether() / ARP()
    record = PacketParser().parse(captured(packet))
    assert record is not None
    assert record.protocol == "ARP"


def test_parse_icmp_packet():
    packet = Ether() / IP() / ICMP()
    record = PacketParser().parse(captured(packet))
    assert record is not None
    assert record.protocol == "ICMP"


def test_parse_dns_packet():
    packet = (
        Ether()
        / IP(src="192.0.2.1", dst="198.51.100.2")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )
    record = PacketParser().parse(captured(packet))
    assert record is not None
    assert record.protocol == "DNS"


def test_unsupported_link_type_returns_none():
    packet = captured(Ether() / IP() / TCP(), link_type=999)
    assert PacketParser().parse(packet) is None


def test_malformed_packet_does_not_raise():
    packet = CapturedPacket(
        timestamp=datetime.now(UTC),
        packet_data=b"\x00",
        interface="test0",
        link_type=1,
        original_length=1,
    )

    assert PacketParser().parse(packet) is None
