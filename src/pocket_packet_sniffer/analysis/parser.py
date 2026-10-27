"""Convert raw captured packets into normalized PacketRecord objects."""


from scapy.config import conf
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    IPv6,
)
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from pocket_packet_sniffer.capture.models import CapturedPacket

from .models import PacketRecord


def _decode_packet(captured: CapturedPacket) -> Packet | None:
    """Decode captured bytes using their PCAP link-layer type."""
    try:
        layer_class = conf.l2types.get(captured.link_type)

        if layer_class is None:
            return None

        return layer_class(captured.packet_data)
    except Exception:
        # Malformed packets must not interrupt the capture process.
        return None


class PacketParser:
    """Parse supported network protocols into normalized records."""

    def parse(
        self,
        captured: CapturedPacket,
        *,
        backend: str | None = None,
    ) -> PacketRecord | None:
        """Return a PacketRecord, or None for malformed or unsupported packets."""
        try:
            packet = _decode_packet(captured)

            if packet is None:
                return None

            source = None
            destination = None
            protocol = "OTHER"
            source_mac = packet[Ether].src if packet.haslayer(Ether) else None
            destination_mac = packet[Ether].dst if packet.haslayer(Ether) else None

            if packet.haslayer(Dot11Beacon) and packet.haslayer(Dot11):
                dot11 = packet[Dot11]
                bssid = dot11.addr3 or dot11.addr2
                ssid = None
                element = packet.getlayer(Dot11Elt)
                while isinstance(element, Dot11Elt):
                    if getattr(element, "ID", None) == 0:
                        try:
                            ssid = bytes(element.info or b"").decode("utf-8", errors="replace")
                        except Exception:
                            ssid = None
                        break
                    payload = element.payload
                    element = payload if isinstance(payload, Dot11Elt) else None
                return PacketRecord(
                    timestamp=captured.timestamp,
                    source=bssid,
                    destination=dot11.addr1,
                    protocol="WIFI-BEACON",
                    packet_size=captured.original_length,
                    interface=captured.interface,
                    link_type=captured.link_type,
                    capture_backend=backend,
                    source_mac=bssid,
                    destination_mac=dot11.addr1,
                    bssid=bssid,
                    ssid=ssid,
                )

            if packet.haslayer(ARP):
                arp = packet[ARP]
                source = arp.psrc or arp.hwsrc or None
                destination = arp.pdst or arp.hwdst or None
                source_mac = arp.hwsrc or source_mac
                destination_mac = arp.hwdst or destination_mac
                protocol = "ARP"

            elif packet.haslayer(IP):
                ip = packet[IP]
                source = ip.src
                destination = ip.dst

                if packet.haslayer(DNS):
                    protocol = "DNS"
                elif packet.haslayer(TCP):
                    protocol = "TCP"
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
                else:
                    protocol = "IPv4"

            elif packet.haslayer(IPv6):
                ip = packet[IPv6]
                source = ip.src
                destination = ip.dst

                if packet.haslayer(DNS):
                    protocol = "DNS"
                elif packet.haslayer(TCP):
                    protocol = "TCP"
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                elif (
                    packet.haslayer(ICMPv6EchoRequest)
                    or packet.haslayer(ICMPv6EchoReply)
                ):
                    protocol = "ICMPv6"
                else:
                    protocol = "IPv6"

            else:
                return None

            return PacketRecord(
                timestamp=captured.timestamp,
                source=source,
                destination=destination,
                protocol=protocol,
                packet_size=captured.original_length,
                interface=captured.interface,
                link_type=captured.link_type,
                capture_backend=backend,
                source_mac=source_mac,
                destination_mac=destination_mac,
            )

        except Exception:
            # Protect capture from malformed or unexpected packet-decoding errors.
            return None
