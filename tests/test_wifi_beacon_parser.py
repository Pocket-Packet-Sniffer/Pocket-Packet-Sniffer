from datetime import UTC, datetime

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from pocket_packet_sniffer.analysis.parser import PacketParser
from pocket_packet_sniffer.capture.models import CapturedPacket


def test_parser_extracts_wifi_beacon_bssid_and_ssid_from_radiotap_frame():
    bssid = "00:11:22:33:44:55"
    raw = bytes(
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
        / Dot11Beacon()
        / Dot11Elt(ID=0, info=b"authorized-lab")
    )
    packet = CapturedPacket(
        timestamp=datetime.now(UTC),
        packet_data=raw,
        interface="wlan0mon",
        link_type=127,
        original_length=len(raw),
    )

    result = PacketParser().parse(packet)

    assert result is not None
    assert result.protocol == "WIFI-BEACON"
    assert result.bssid == bssid
    assert result.source_mac == bssid
    assert result.ssid == "authorized-lab"
    assert result.interface == "wlan0mon"
