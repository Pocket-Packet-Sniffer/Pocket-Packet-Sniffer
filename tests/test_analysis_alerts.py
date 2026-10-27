from datetime import UTC, datetime

from scapy.layers.l2 import ARP, Ether

from pocket_packet_sniffer.analysis.alerts import AlertBus, ArpAddressConflictDetector
from pocket_packet_sniffer.capture.models import CapturedPacket


def captured_arp(ip: str, mac: str) -> CapturedPacket:
    raw = bytes(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc=mac, psrc=ip, hwdst="00:00:00:00:00:00", pdst="192.0.2.1"
    ))
    return CapturedPacket(
        timestamp=datetime.now(UTC),
        packet_data=raw,
        interface="fixture0",
        link_type=1,
        original_length=len(raw),
    )


def test_arp_conflict_publishes_observer_event_after_second_mac():
    bus = AlertBus()
    events = []
    bus.subscribe(events.append)
    detector = ArpAddressConflictDetector(bus)

    assert detector.observe(captured_arp("192.0.2.10", "02:00:00:00:00:01")) is None
    event = detector.observe(captured_arp("192.0.2.10", "02:00:00:00:00:02"))

    assert event is not None
    assert event.rule_id == "ARP-IP-MAC-CONFLICT"
    assert event.severity == "warning"
    assert len(events) == 1
    assert "does not prove an attack" in event.description


def test_arp_conflict_detector_does_not_alert_same_ip_same_mac():
    bus = AlertBus()
    events = []
    bus.subscribe(events.append)
    detector = ArpAddressConflictDetector(bus)

    detector.observe(captured_arp("192.0.2.10", "02:00:00:00:00:01"))
    assert detector.observe(captured_arp("192.0.2.10", "02:00:00:00:00:01")) is None
    assert events == []


def test_alert_subscriber_failure_does_not_block_other_subscribers():
    bus = AlertBus()
    received = []
    bus.subscribe(lambda event: (_ for _ in ()).throw(RuntimeError("subscriber failed")))
    bus.subscribe(received.append)
    event = ArpAddressConflictDetector(bus)
    event.observe(captured_arp("192.0.2.10", "02:00:00:00:00:01"))
    published = event.observe(captured_arp("192.0.2.10", "02:00:00:00:00:02"))
    assert published is not None
    assert received == [published]
