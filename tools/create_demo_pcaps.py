"""Generate local-only synthetic PCAPs for the end-to-end demo.

These packets are constructed in memory and written to files. The script never
sends packets to a network interface.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

TRUSTED_MAC = "02:00:00:00:00:01"
UNTRUSTED_MAC = "02:00:00:00:00:99"


def create_demo_pcaps(output_dir: str | Path) -> tuple[Path, Path]:
    """Write Ethernet and Wi-Fi-beacon classic-PCAP fixtures to a new location."""
    directory = Path(output_dir).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    ethernet_path = directory / "ethernet-demo.pcap"
    wifi_path = directory / "wifi-beacon-demo.pcap"
    existing = [path.name for path in (ethernet_path, wifi_path) if path.exists()]
    if existing:
        raise FileExistsError(
            "refusing to overwrite demo fixture(s): " + ", ".join(existing)
        )

    broadcast = "ff:ff:ff:ff:ff:ff"
    ethernet_packets = [
        Ether(src=TRUSTED_MAC, dst=broadcast)
        / ARP(op=2, hwsrc=TRUSTED_MAC, psrc="192.0.2.10", hwdst=broadcast, pdst="192.0.2.1"),
        # Same sender IP with a different MAC is a deliberately synthetic ARP conflict.
        Ether(src=UNTRUSTED_MAC, dst=broadcast)
        / ARP(op=2, hwsrc=UNTRUSTED_MAC, psrc="192.0.2.10", hwdst=broadcast, pdst="192.0.2.1"),
        Ether(src=TRUSTED_MAC, dst=UNTRUSTED_MAC)
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=41000, dport=443),
        Ether(src=TRUSTED_MAC, dst=UNTRUSTED_MAC)
        / IP(src="192.0.2.10", dst="198.51.100.53")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="demo.invalid")),
    ]
    wifi_beacon = (
        RadioTap()
        / Dot11(
            type=0,
            subtype=8,
            addr1=broadcast,
            addr2=UNTRUSTED_MAC,
            addr3=UNTRUSTED_MAC,
        )
        / Dot11Beacon()
        / Dot11Elt(ID=0, info=b"pps-demo-untrusted-ap")
    )

    wrpcap(str(ethernet_path), ethernet_packets)
    wrpcap(str(wifi_path), [wifi_beacon])
    return ethernet_path, wifi_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("demo-data"))
    args = parser.parse_args(argv)
    ethernet, wifi = create_demo_pcaps(args.output_dir)
    print(f"Created synthetic Ethernet PCAP: {ethernet}")
    print(f"Created synthetic Wi-Fi beacon PCAP: {wifi}")
    print("These files are local fixtures; no packets were transmitted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
