
"""Shared, backend-neutral records produced by packet analysis."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """Normalized information extracted from one captured packet.

    Attributes:
        timestamp: Time the packet was captured, with timezone information.
        source: Source IP or hardware address, when available.
        destination: Destination IP or hardware address, when available.
        protocol: Detected protocol, such as TCP, UDP, DNS, ARP, or ICMP.
        packet_size: Original packet length in bytes.
        interface: Name of the capture interface.
        link_type: PCAP link-layer type used to interpret the raw bytes.
        capture_backend: Capture implementation name, if supplied.
    """

    timestamp: datetime
    source: str | None
    destination: str | None
    protocol: str
    packet_size: int
    interface: str
    link_type: int
    capture_backend: str | None = None
    source_mac: str | None = None
    destination_mac: str | None = None
    bssid: str | None = None
    ssid: str | None = None
