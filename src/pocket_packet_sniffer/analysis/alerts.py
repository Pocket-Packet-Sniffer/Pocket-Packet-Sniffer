"""Observer-style events and conservative ARP conflict detection.

The detector is a heuristic: seeing one IPv4 address associated with multiple
Ethernet source MAC addresses can indicate address conflict or spoofing, but is
not proof of an attack. It is intentionally opt-in and uses captured metadata
only; it never transmits packets.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from threading import RLock
from typing import Protocol

from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from pocket_packet_sniffer.capture.models import CapturedPacket


@dataclass(frozen=True, slots=True)
class AlertEvent:
    """A detection event safe to display without raw packet payloads."""

    rule_id: str
    severity: str
    title: str
    description: str
    timestamp: datetime
    source_address: str | None = None
    observed_value: str | None = None


class AlertSubscriber(Protocol):
    """Observer callback contract."""

    def __call__(self, event: AlertEvent) -> None: ...


class AlertBus:
    """Thread-safe event publisher with independent subscriber callbacks."""

    def __init__(self) -> None:
        self._subscribers: list[AlertSubscriber] = []
        self._lock = RLock()

    def subscribe(self, subscriber: AlertSubscriber) -> Callable[[], None]:
        """Register a subscriber and return an unsubscribe function."""
        if not callable(subscriber):
            raise TypeError("subscriber must be callable")
        with self._lock:
            self._subscribers.append(subscriber)

        def unsubscribe() -> None:
            with self._lock:
                if subscriber in self._subscribers:
                    self._subscribers.remove(subscriber)

        return unsubscribe

    def publish(self, event: AlertEvent) -> None:
        """Publish to a stable subscriber snapshot; subscriber errors are isolated."""
        with self._lock:
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber(event)
            except Exception:
                # A presentation subscriber must never terminate packet capture.
                continue


class ArpAddressConflictDetector:
    """Flag an IPv4 sender address observed from multiple Ethernet MACs."""

    rule_id = "ARP-IP-MAC-CONFLICT"

    def __init__(self, event_bus: AlertBus) -> None:
        self._event_bus = event_bus
        self._ip_to_mac: dict[str, str] = {}
        self._lock = RLock()

    def observe(self, captured: CapturedPacket) -> AlertEvent | None:
        """Inspect one captured frame; return/publish an event on a conflict."""
        try:
            packet: Packet = Ether(captured.packet_data)
            if not packet.haslayer(ARP):
                return None
            arp = packet[ARP]
            if int(arp.op) not in (1, 2):
                return None
            ip = str(arp.psrc).strip()
            mac = str(arp.hwsrc).strip().lower()
            if not ip or ip == "0.0.0.0" or not mac or mac == "00:00:00:00:00:00":
                return None
        except Exception:
            return None

        with self._lock:
            previous_mac = self._ip_to_mac.get(ip)
            if previous_mac is None:
                self._ip_to_mac[ip] = mac
                return None
            if previous_mac == mac:
                return None
            event = AlertEvent(
                rule_id=self.rule_id,
                severity="warning",
                title="Possible ARP address conflict",
                description=(
                    f"IPv4 address {ip} was observed with Ethernet source MAC "
                    f"{previous_mac} and {mac}. This may be an address conflict "
                    "or spoofing; packet evidence alone does not prove an attack."
                ),
                timestamp=captured.timestamp,
                source_address=ip,
                observed_value=f"{previous_mac} -> {mac}",
            )
            # Track the newest value so repeated packets from the second device
            # do not repeatedly emit the same alert.
            self._ip_to_mac[ip] = mac

        self._event_bus.publish(event)
        return event
