from __future__ import annotations

from datetime import datetime, timezone

from pocket_packet_sniffer.analysis.alerts import (
    AlertEvent,
    AlertPublisher,
    SuspiciousActivityDetector,
)
from pocket_packet_sniffer.analysis.models import PacketRecord


def record(protocol: str, source: str, source_mac: str, *, destination_mac: str | None = None) -> PacketRecord:
    return PacketRecord(
        timestamp=datetime(2026, 10, 27, tzinfo=timezone.utc),
        source=source,
        destination="192.0.2.20",
        protocol=protocol,
        packet_size=60,
        interface="fixture0",
        link_type=1,
        source_mac=source_mac,
        destination_mac=destination_mac,
    )


def test_arp_address_conflict_emits_one_metadata_only_alert():
    publisher = AlertPublisher()
    events: list[AlertEvent] = []
    publisher.subscribe(events.append)
    detector = SuspiciousActivityDetector(publisher)

    detector.inspect(record("ARP", "192.0.2.1", "02:00:00:00:00:01"))
    detector.inspect(record("ARP", "192.0.2.1", "02:00:00:00:00:02"))
    detector.inspect(record("ARP", "192.0.2.1", "02:00:00:00:00:02"))

    assert len(events) == 1
    assert events[0].rule_id == "arp-address-conflict"
    assert "suspected" in events[0].message
    assert events[0].evidence["ip_address"] == "192.0.2.1"
    assert "packet_data" not in events[0].evidence


def test_unrecognized_device_rule_requires_allowlist_and_deduplicates():
    publisher = AlertPublisher()
    events: list[AlertEvent] = []
    publisher.subscribe(events.append)
    detector = SuspiciousActivityDetector(
        publisher, known_devices={"02:00:00:00:00:01"}
    )
    unknown = record("TCP", "192.0.2.5", "02:00:00:00:00:02")
    detector.inspect(unknown)
    detector.inspect(unknown)

    assert [event.rule_id for event in events] == ["unrecognized-device"]


def test_unrecognized_access_point_requires_allowlist():
    publisher = AlertPublisher()
    events: list[AlertEvent] = []
    publisher.subscribe(events.append)
    detector = SuspiciousActivityDetector(
        publisher, known_access_points={"02:00:00:00:00:01"}
    )

    detector.inspect(record("WIFI_BEACON", "02:00:00:00:00:02", "02:00:00:00:00:02"))

    assert len(events) == 1
    assert events[0].rule_id == "unrecognized-access-point"
    assert events[0].evidence == {"bssid": "02:00:00:00:00:02"}


def test_observer_failure_does_not_interrupt_other_subscribers():
    publisher = AlertPublisher()
    delivered: list[AlertEvent] = []
    publisher.subscribe(lambda _event: (_ for _ in ()).throw(RuntimeError("observer failed")))
    publisher.subscribe(delivered.append)
    event = AlertEvent(
        rule_id="test",
        severity="info",
        message="test event",
        timestamp=datetime(2026, 10, 27, tzinfo=timezone.utc),
        evidence={},
    )

    publisher.publish(event)

    assert delivered == [event]
    assert publisher.notification_failures == 1
