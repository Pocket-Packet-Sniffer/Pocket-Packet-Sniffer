from __future__ import annotations

from datetime import UTC, datetime

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether

from pocket_packet_sniffer.analysis.suspicious import SuspiciousActivityDetector
from pocket_packet_sniffer.capture.models import CapturedPacket


def captured(packet, *, interface="fixture0", link_type=1):
    raw = bytes(packet)
    return CapturedPacket(
        timestamp=datetime.now(UTC),
        packet_data=raw,
        interface=interface,
        link_type=link_type,
        original_length=len(raw),
    )


def arp_reply(mac: str):
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc=mac, psrc="192.0.2.1",
        hwdst="ff:ff:ff:ff:ff:ff", pdst="192.0.2.10"
    )


def test_arp_sender_ip_mac_conflict_publishes_one_warning():
    detector = SuspiciousActivityDetector()
    delivered = []
    detector.subscribe(delivered.append)
    assert detector.observe(captured(arp_reply("02:00:00:00:00:01"))) == ()
    events = detector.observe(captured(arp_reply("02:00:00:00:00:02")))
    assert len(events) == 1
    assert events[0].rule_id == "ARP_SPOOFING_SUSPECTED"
    assert events[0].severity == "high"
    assert len(delivered) == 1
    assert detector.observe(captured(arp_reply("02:00:00:00:00:02"))) == ()
    assert len(delivered) == 1


def test_unknown_device_rule_requires_explicit_allowlist():
    unknown = Ether(src="02:00:00:00:00:99", dst="02:00:00:00:00:01") / IP(
        src="192.0.2.99", dst="198.51.100.9"
    ) / TCP()
    assert SuspiciousActivityDetector().observe(captured(unknown)) == ()
    detector = SuspiciousActivityDetector(known_devices=["02:00:00:00:00:01"])
    first = detector.observe(captured(unknown))
    assert [event.rule_id for event in first] == ["UNRECOGNIZED_DEVICE"]
    assert detector.observe(captured(unknown)) == ()


def test_unapproved_bssid_for_trusted_ssid_publishes_rogue_ap_warning():
    trusted = "02:00:00:00:00:50"
    observed = "02:00:00:00:00:99"
    beacon = (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=observed, addr3=observed)
        / Dot11Beacon()
        / Dot11Elt(ID="SSID", info=b"Campus-Lab")
    )
    detector = SuspiciousActivityDetector(known_access_points={"Campus-Lab": [trusted]})
    events = detector.observe(captured(beacon, interface="mon0", link_type=127))
    assert len(events) == 1
    assert events[0].rule_id == "ROGUE_AP_SUSPECTED"
    assert observed in events[0].summary


def test_unknown_ssids_are_not_called_rogue_without_a_trusted_baseline():
    beacon = (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                addr2="02:00:00:00:00:99", addr3="02:00:00:00:00:99")
        / Dot11Beacon()
        / Dot11Elt(ID="SSID", info=b"Unconfigured")
    )
    detector = SuspiciousActivityDetector(known_access_points={"Campus-Lab": ["02:00:00:00:00:50"]})
    assert detector.observe(captured(beacon, interface="mon0", link_type=127)) == ()


def test_observer_unsubscribe_stops_future_notifications():
    detector = SuspiciousActivityDetector()
    seen = []
    observer = seen.append
    detector.subscribe(observer)
    detector.unsubscribe(observer)
    detector.observe(captured(arp_reply("02:00:00:00:00:01")))
    detector.observe(captured(arp_reply("02:00:00:00:00:02")))
    assert seen == []
