"""Generate a local synthetic classic-PCAP fixture; never sends network traffic."""
from __future__ import annotations

import argparse
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapWriter


def build_demo_frames():
    """Build deterministic TCP, UDP/DNS, ICMP and conflicting ARP examples."""
    first_mac = "02:00:00:00:00:10"
    second_mac = "02:00:00:00:00:11"
    gateway_mac = "02:00:00:00:00:20"
    frames = [
        Ether(src=first_mac, dst=gateway_mac)
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=51514, dport=443, flags="S"),
        Ether(src=gateway_mac, dst=first_mac)
        / IP(src="198.51.100.20", dst="192.0.2.10")
        / TCP(sport=443, dport=51514, flags="SA"),
        Ether(src=first_mac, dst=gateway_mac)
        / IP(src="192.0.2.10", dst="198.51.100.53")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.test")),
        Ether(src=first_mac, dst=gateway_mac)
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / ICMP(),
        Ether(src=first_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc=first_mac, psrc="192.0.2.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.0.2.10"),
        Ether(src=second_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc=second_mac, psrc="192.0.2.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.0.2.10"),
    ]
    for index, packet in enumerate(frames):
        packet.time = 1_700_000_000 + index
    return frames


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("sample-demo.pcap"))
    parser.add_argument("--force", action="store_true", help="replace an existing output file")
    args = parser.parse_args(argv)
    output = args.output.expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not args.force:
        parser.error(f"{output} already exists; choose another path or pass --force")
    packets = build_demo_frames()
    writer = PcapWriter(str(output), append=False, sync=True, linktype=1)
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()
    print(f"Created {len(packets)} synthetic Ethernet packets at {output}")
    print("The fixture is written to disk only; no network packets were sent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
