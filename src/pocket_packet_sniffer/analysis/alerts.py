"""Observer-based, explicitly heuristic suspicious-activity events.

Rules operate on parsed metadata only; captured payloads are never inspected or
included in alert evidence. Alerts are indicators for human review, not proof
of malicious activity.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from threading import RLock
from typing import Protocol

from .models import PacketRecord


@dataclass(frozen=True, slots=True)
class AlertEvent:
    """A metadata-only alert emitted by an Analysis rule."""

    rule_id: str
    severity: str
    message: str
    timestamp: datetime
    evidence: Mapping[str, str]


class AlertObserver(Protocol):
    """Observer callback contract for subscribers in Presentation or tests."""

    def __call__(self, event: AlertEvent) -> None:
        """Receive one alert event."""


class AlertPublisher:
    """Thread-safe Observer publisher that isolates subscriber failures."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._observers: list[AlertObserver] = []
        self._notification_failures = 0

    def subscribe(self, observer: AlertObserver) -> Callable[[], None]:
        """Register an observer and return an idempotent unsubscribe callback."""
        if not callable(observer):
            raise TypeError("observer must be callable")
        with self._lock:
            if observer not in self._observers:
                self._observers.append(observer)

        def unsubscribe() -> None:
            with self._lock:
                if observer in self._observers:
                    self._observers.remove(observer)

        return unsubscribe

    def publish(self, event: AlertEvent) -> None:
        """Publish an event without allowing a broken observer to stop capture."""
        with self._lock:
            observers = tuple(self._observers)
        for observer in observers:
            try:
                observer(event)
            except Exception:
                with self._lock:
                    self._notification_failures += 1

    @property
    def notification_failures(self) -> int:
        """Number of observer callbacks that raised an exception."""
        with self._lock:
            return self._notification_failures


class SuspiciousActivityDetector:
    """Small configurable metadata rules with conservative, documented limits.

    ARP conflict detection is available without an inventory. Unknown-device
    and rogue-AP rules activate only when the operator supplies an allowlist.
    All rules deduplicate alerts for the same observed condition.
    """

    def __init__(
        self,
        publisher: AlertPublisher,
        *,
        known_devices: set[str] | None = None,
        known_access_points: set[str] | None = None,
    ) -> None:
        if not isinstance(publisher, AlertPublisher):
            raise TypeError("publisher must be an AlertPublisher")
        self.publisher = publisher
        self.known_devices = self._normalize_set(known_devices)
        self.known_access_points = self._normalize_set(known_access_points)
        self._lock = RLock()
        self._ip_to_mac: dict[str, str] = {}
        self._unknown_seen: set[str] = set()
        self._rogue_aps_seen: set[str] = set()
        self._arp_conflicts_seen: set[tuple[str, str, str]] = set()

    @staticmethod
    def _normalize_set(values: set[str] | None) -> set[str]:
        if values is None:
            return set()
        if not isinstance(values, set):
            raise TypeError("device and access-point allowlists must be sets")
        normalized: set[str] = set()
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("allowlist entries must be non-empty strings")
            normalized.add(value.strip().lower())
        return normalized

    def inspect(self, record: PacketRecord) -> None:
        """Inspect one parsed record and publish any newly detected condition."""
        events: list[AlertEvent] = []
        timestamp = record.timestamp
        source_mac = (record.source_mac or "").strip().lower()
        source_address = (record.source or "").strip()

        with self._lock:
            if record.protocol == "ARP" and source_address and source_mac:
                previous_mac = self._ip_to_mac.get(source_address)
                if previous_mac is None:
                    self._ip_to_mac[source_address] = source_mac
                elif previous_mac != source_mac:
                    conflict = (source_address, previous_mac, source_mac)
                    if conflict not in self._arp_conflicts_seen:
                        self._arp_conflicts_seen.add(conflict)
                        events.append(
                            AlertEvent(
                                rule_id="arp-address-conflict",
                                severity="warning",
                                message=(
                                    f"ARP address conflict suspected for {source_address}: "
                                    f"{previous_mac} and {source_mac} both claimed this address"
                                ),
                                timestamp=timestamp,
                                evidence={
                                    "ip_address": source_address,
                                    "previous_mac": previous_mac,
                                    "observed_mac": source_mac,
                                },
                            )
                        )
                    self._ip_to_mac[source_address] = source_mac

            if self.known_devices and source_mac and source_mac not in self.known_devices:
                if source_mac not in self._unknown_seen:
                    self._unknown_seen.add(source_mac)
                    events.append(
                        AlertEvent(
                            rule_id="unrecognized-device",
                            severity="info",
                            message=f"Observed source device {source_mac} is not in the configured device allowlist",
                            timestamp=timestamp,
                            evidence={"source_mac": source_mac, "source_address": source_address},
                        )
                    )

            if (
                record.protocol == "WIFI_BEACON"
                and source_mac
                and self.known_access_points
                and source_mac not in self.known_access_points
                and source_mac not in self._rogue_aps_seen
            ):
                self._rogue_aps_seen.add(source_mac)
                events.append(
                    AlertEvent(
                        rule_id="unrecognized-access-point",
                        severity="warning",
                        message=f"Observed Wi-Fi beacon {source_mac} is not in the configured access-point allowlist",
                        timestamp=timestamp,
                        evidence={"bssid": source_mac},
                    )
                )

        for event in events:
            self.publisher.publish(event)
