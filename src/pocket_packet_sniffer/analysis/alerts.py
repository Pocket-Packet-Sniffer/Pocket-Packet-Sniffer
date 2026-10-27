"""Observer-style security alerts for supported suspicious traffic heuristics."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from threading import RLock
from typing import Callable, Iterable

from .models import PacketRecord

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AlertEvent:
    """Metadata-only alert event; never contains packet payload bytes."""

    rule_id: str
    severity: str
    message: str
    timestamp: datetime
    interface: str
    subject: str | None = None
    evidence: str | None = None


AlertSubscriber = Callable[[AlertEvent], None]


class AlertBus:
    """Publish events to interested observers without coupling detection to UI."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._subscribers: list[AlertSubscriber] = []

    def subscribe(self, subscriber: AlertSubscriber) -> Callable[[], None]:
        """Register a subscriber and return an idempotent unsubscribe function."""
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
        """Notify a snapshot of observers; one broken observer cannot stop capture."""
        with self._lock:
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber(event)
            except Exception as exc:  # Observer failure must not stop passive capture.
                LOGGER.warning("alert observer failed (%s)", type(exc).__name__)


class SuspiciousActivityDetector:
    """Detect simple, explainable patterns from normalized packet metadata.

    ARP conflict alerts are heuristic indicators, not proof of an attack.
    Unrecognized-device alerts require an explicit trusted-device allowlist.
    Rogue-AP alerts require an explicit trusted-BSSID allowlist and Wi-Fi beacon
    metadata from a compatible monitor-mode/radiotap capture source.
    """

    def __init__(
        self,
        *,
        trusted_devices: Iterable[str] = (),
        trusted_aps: Iterable[str] = (),
    ) -> None:
        self.trusted_devices = {self._normalise(value) for value in trusted_devices}
        self.trusted_aps = {self._normalise(value) for value in trusted_aps}
        self._arp_bindings: dict[str, str] = {}
        self._reported_devices: set[str] = set()
        self._reported_aps: set[str] = set()
        self._lock = RLock()

    @staticmethod
    def _normalise(value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("trusted device/AP values must be non-empty strings")
        return value.strip().lower()

    def inspect(self, record: PacketRecord) -> list[AlertEvent]:
        """Return new alerts for one record using metadata only."""
        alerts: list[AlertEvent] = []
        source_mac = self._normalise(record.source_mac) if record.source_mac else None
        bssid = self._normalise(record.bssid) if record.bssid else None
        with self._lock:
            if record.protocol == "ARP" and record.source and source_mac:
                old_mac = self._arp_bindings.get(record.source)
                if old_mac is not None and old_mac != source_mac:
                    alerts.append(
                        AlertEvent(
                            rule_id="ARP_SPOOFING_HEURISTIC",
                            severity="high",
                            message="An ARP sender IP was observed with a different hardware address.",
                            timestamp=record.timestamp,
                            interface=record.interface,
                            subject=record.source,
                            evidence=f"previous_mac={old_mac}; observed_mac={source_mac}",
                        )
                    )
                self._arp_bindings[record.source] = source_mac

            if (
                source_mac
                and self.trusted_devices
                and source_mac not in self.trusted_devices
                and source_mac not in self._reported_devices
            ):
                self._reported_devices.add(source_mac)
                alerts.append(
                    AlertEvent(
                        rule_id="UNRECOGNIZED_DEVICE",
                        severity="medium",
                        message="A source hardware address is not in the configured trusted-device list.",
                        timestamp=record.timestamp,
                        interface=record.interface,
                        subject=source_mac,
                        evidence="source hardware address is absent from the configured allowlist",
                    )
                )

            if (
                record.protocol == "WIFI-BEACON"
                and bssid
                and self.trusted_aps
                and bssid not in self.trusted_aps
                and bssid not in self._reported_aps
            ):
                self._reported_aps.add(bssid)
                label = f" ({record.ssid})" if record.ssid else ""
                alerts.append(
                    AlertEvent(
                        rule_id="ROGUE_AP_HEURISTIC",
                        severity="high",
                        message="A Wi-Fi beacon came from a BSSID absent from the configured trusted-AP list.",
                        timestamp=record.timestamp,
                        interface=record.interface,
                        subject=bssid,
                        evidence=f"untrusted beacon BSSID{label}",
                    )
                )
        return alerts
