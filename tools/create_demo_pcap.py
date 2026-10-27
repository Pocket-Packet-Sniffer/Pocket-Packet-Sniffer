"""Create a deterministic synthetic PCAP for a safe local project demo.

The fixture contains no real network traffic and is only written to a local
file. Replaying it reads the PCAP; it does not transmit network packets.
"""
from __future__ import annotations

import argparse
import os
from datetime import datetime, timezone
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

_BASE_EPOCH = datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc).timestamp()


def build_demo_packets():
    """Build representative TCP, UDP/DNS, ICMP and conflicting ARP fixtures."""
    packets = [
        Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:01")
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=51000, dport=443),
        Ether(src="02:00:00:00:00:11", dst="02:00:00:00:00:01")
        / IP(src="192.0.2.11", dst="198.51.100.21")
        / UDP(sport=52000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="demo.invalid")),
        Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:01")
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / ICMP(),
        Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=2,
            hwsrc="02:00:00:00:00:01",
            psrc="192.0.2.1",
            hwdst="ff:ff:ff:ff:ff:ff",
            pdst="192.0.2.10",
        ),
        Ether(src="02:00:00:00:00:99", dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=2,
            hwsrc="02:00:00:00:00:99",
            psrc="192.0.2.1",
            hwdst="ff:ff:ff:ff:ff:ff",
            pdst="192.0.2.10",
        ),
    ]
    for index, packet in enumerate(packets):
        packet.time = _BASE_EPOCH + index
    return packets


def create_demo_pcap(destination: str | os.PathLike[str]) -> Path:
    """Create a new PCAP without overwriting an existing file."""
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(path, flags, 0o600)
    os.close(descriptor)
    try:
        wrpcap(str(path), build_demo_packets(), append=False)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    if os.name == "posix":
        path.chmod(0o600)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", default="demo.pcap", help="destination for a new synthetic classic-PCAP file")
    args = parser.parse_args()
    try:
        output = create_demo_pcap(args.output)
    except FileExistsError:
        parser.error(f"refusing to overwrite existing file: {args.output}")
    print(f"Created synthetic PCAP with {len(build_demo_packets())} packets: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
