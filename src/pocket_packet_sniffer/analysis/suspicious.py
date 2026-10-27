"""Opt-in metadata-only suspicious-activity heuristics and observer events.

Alerts are investigation indicators rather than proof of an attack. Unknown-device
and rogue-access-point checks require an operator-maintained trust baseline.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from threading import RLock

from scapy.config import conf
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from pocket_packet_sniffer.capture.models import CapturedPacket

_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


@dataclass(frozen=True, slots=True)
class SuspiciousActivityEvent:
    """One metadata-only alert published by an Analysis rule."""

    rule_id: str
    severity: str
    timestamp: datetime
    interface: str
    summary: str
    subject: str


AlertObserver = Callable[[SuspiciousActivityEvent], None]


def _normalize_mac(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("MAC addresses must be strings")
    normalized = value.strip().lower()
    if not _MAC_RE.fullmatch(normalized):
        raise ValueError(f"invalid MAC address '{value}'; use aa:bb:cc:dd:ee:ff format")
    return normalized


def _decode(captured: CapturedPacket) -> Packet | None:
    """Decode only enough frame metadata for rules; never retain payloads."""
    try:
        layer_class = conf.l2types.get(captured.link_type)
        return layer_class(captured.packet_data) if layer_class is not None else None
    except Exception:
        return None


def _unicast_mac(value: str | None) -> bool:
    if not value:
        return False
    try:
        first_octet = int(value.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return False
    return len(value.split(":")) == 6 and not (first_octet & 1)


class SuspiciousActivityDetector:
    """Publish ARP-conflict, unknown-device, and rogue-AP warning events.

    ARP conflicts are reported when one IPv4 sender address is observed with
    multiple sender MACs. Unknown-device alerts need a non-empty MAC allowlist.
    Rogue-AP alerts compare trusted SSIDs to BSSIDs in captured 802.11 beacons.
    """

    def __init__(
        self,
        *,
        known_devices: Iterable[str] = (),
        known_access_points: Mapping[str, Iterable[str]] | None = None,
    ) -> None:
        self._known_devices = frozenset(_normalize_mac(item) for item in known_devices)
        self._known_access_points: dict[str, frozenset[str]] = {}
        for ssid, addresses in (known_access_points or {}).items():
            if not isinstance(ssid, str) or not ssid.strip():
                raise ValueError("known access-point SSIDs must be non-empty strings")
            if isinstance(addresses, (str, bytes)):
                raise ValueError(f"trusted BSSIDs for SSID '{ssid}' must be a list of MAC addresses")
            self._known_access_points[ssid] = frozenset(_normalize_mac(item) for item in addresses)

        self._lock = RLock()
        self._observers: list[AlertObserver] = []
        self._arp_bindings: dict[str, str] = {}
        self._arp_conflicts: set[tuple[str, str]] = set()
        self._unknown_devices: set[str] = set()
        self._rogue_access_points: set[tuple[str, str]] = set()

    def subscribe(self, observer: AlertObserver) -> None:
        """Subscribe to future alerts; duplicate registrations are ignored."""
        if not callable(observer):
            raise TypeError("observer must be callable")
        with self._lock:
            if observer not in self._observers:
                self._observers.append(observer)

    def unsubscribe(self, observer: AlertObserver) -> None:
        """Remove an observer if it is currently subscribed."""
        with self._lock:
            if observer in self._observers:
                self._observers.remove(observer)

    def observe(self, captured: CapturedPacket) -> tuple[SuspiciousActivityEvent, ...]:
        """Analyze one captured packet's metadata and publish matching events."""
        packet = _decode(captured)
        if packet is None:
            return ()

        events: list[SuspiciousActivityEvent] = []
        with self._lock:
            if packet.haslayer(ARP):
                arp = packet[ARP]
                sender_ip = str(arp.psrc or "").strip()
                sender_mac = str(arp.hwsrc or "").strip().lower()
                if sender_ip and sender_mac and sender_ip != "0.0.0.0":
                    previous_mac = self._arp_bindings.setdefault(sender_ip, sender_mac)
                    conflict_key = (sender_ip, sender_mac)
                    if previous_mac != sender_mac and conflict_key not in self._arp_conflicts:
                        self._arp_conflicts.add(conflict_key)
                        events.append(
                            SuspiciousActivityEvent(
                                rule_id="ARP_SPOOFING_SUSPECTED",
                                severity="high",
                                timestamp=captured.timestamp,
                                interface=captured.interface,
                                summary=(
                                    f"ARP sender {sender_ip} was first seen as {previous_mac} "
                                    f"and is now advertised as {sender_mac}; verify this conflict."
                                ),
                                subject=sender_ip,
                            )
                        )

            source_mac: str | None = None
            if packet.haslayer(Dot11):
                source_mac = str(packet[Dot11].addr2 or "").lower() or None
            elif packet.haslayer(Ether):
                source_mac = str(packet[Ether].src or "").lower() or None

            if (
                self._known_devices
                and source_mac
                and _unicast_mac(source_mac)
                and source_mac not in self._known_devices
                and source_mac not in self._unknown_devices
            ):
                self._unknown_devices.add(source_mac)
                events.append(
                    SuspiciousActivityEvent(
                        rule_id="UNRECOGNIZED_DEVICE",
                        severity="medium",
                        timestamp=captured.timestamp,
                        interface=captured.interface,
                        summary=f"Source device {source_mac} is not in the configured trusted-device list.",
                        subject=source_mac,
                    )
                )

            if packet.haslayer(Dot11Beacon) and packet.haslayer(Dot11) and packet.haslayer(Dot11Elt):
                ssid_bytes = bytes(packet[Dot11Elt].info or b"")
                ssid = ssid_bytes.decode("utf-8", errors="replace")
                bssid = str(packet[Dot11].addr2 or packet[Dot11].addr3 or "").lower()
                trusted_bssids = self._known_access_points.get(ssid)
                rogue_key = (ssid, bssid)
                if (
                    ssid
                    and trusted_bssids is not None
                    and bssid
                    and bssid not in trusted_bssids
                    and rogue_key not in self._rogue_access_points
                ):
                    self._rogue_access_points.add(rogue_key)
                    events.append(
                        SuspiciousActivityEvent(
                            rule_id="ROGUE_AP_SUSPECTED",
                            severity="high",
                            timestamp=captured.timestamp,
                            interface=captured.interface,
                            summary=(
                                f"Untrusted BSSID {bssid} is advertising configured SSID '{ssid}'. "
                                "Confirm against the authorized access-point inventory."
                            ),
                            subject=f"{ssid}/{bssid}",
                        )
                    )
            observers = tuple(self._observers)

        # An observer cannot break a capture because its display/export failed.
        for event in events:
            for observer in observers:
                try:
                    observer(event)
                except Exception:
                    continue
        return tuple(events)

    def __call__(self, captured: CapturedPacket) -> tuple[SuspiciousActivityEvent, ...]:
        """Allow use as a packet-observer callback."""
        return self.observe(captured)
