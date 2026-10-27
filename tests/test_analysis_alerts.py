from datetime import UTC, datetime

from pocket_packet_sniffer.analysis.alerts import AlertBus, SuspiciousActivityDetector
from pocket_packet_sniffer.analysis.models import PacketRecord


def record(protocol="ARP", source="192.0.2.1", source_mac="00:11:22:33:44:55", **kwargs):
    return PacketRecord(
        timestamp=datetime.now(UTC),
        source=source,
        destination="192.0.2.2",
        protocol=protocol,
        packet_size=60,
        interface="test0",
        link_type=1,
        source_mac=source_mac,
        **kwargs,
    )


def test_arp_ip_mac_mapping_change_emits_heuristic_alert():
    detector = SuspiciousActivityDetector()
    assert detector.inspect(record(source_mac="00:11:22:33:44:55")) == []
    alerts = detector.inspect(record(source_mac="66:77:88:99:aa:bb"))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "ARP_SPOOFING_HEURISTIC"
    assert alerts[0].subject == "192.0.2.1"


def test_unrecognized_device_requires_allowlist_and_emits_once():
    detector = SuspiciousActivityDetector(trusted_devices=["aa:bb:cc:dd:ee:ff"])
    first = detector.inspect(record(protocol="TCP", source_mac="00:11:22:33:44:55"))
    second = detector.inspect(record(protocol="TCP", source_mac="00:11:22:33:44:55"))
    assert [event.rule_id for event in first] == ["UNRECOGNIZED_DEVICE"]
    assert second == []


def test_untrusted_wifi_beacon_emits_rogue_ap_heuristic():
    detector = SuspiciousActivityDetector(trusted_aps=["aa:bb:cc:dd:ee:ff"])
    alerts = detector.inspect(
        record(protocol="WIFI-BEACON", source_mac=None, bssid="00:11:22:33:44:55", ssid="lab")
    )
    assert len(alerts) == 1
    assert alerts[0].rule_id == "ROGUE_AP_HEURISTIC"


def test_alert_bus_subscribe_unsubscribe_and_isolate_observer_errors():
    bus = AlertBus()
    received = []
    # Create an event through the detector's second ARP mapping.
    detector = SuspiciousActivityDetector()
    detector.inspect(record(source_mac="aa:bb:cc:dd:ee:ff"))
    alert = detector.inspect(record(source_mac="aa:bb:cc:dd:ee:00"))[0]
    remove = bus.subscribe(received.append)
    bus.subscribe(lambda _event: (_ for _ in ()).throw(RuntimeError("observer test")))
    bus.publish(alert)
    assert received == [alert]
    remove()
    bus.publish(alert)
    assert received == [alert]
