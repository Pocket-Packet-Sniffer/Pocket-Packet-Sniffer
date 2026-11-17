"""Observer-based, explicitly heuristic suspicious-activity events.

Rules operate on parsed metadata only; captured payloads are never inspected or
included in alert evidence. Alerts are indicators for human review, not proof
of malicious activity.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
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
            # Observer failures must never interrupt packet capture.
            except Exception:  # noqa: BLE001
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
        destination_fanout_threshold: int = 30,
        destination_window_seconds: int = 30,
        packet_burst_threshold: int = 500,
        packet_window_seconds: int = 10,
    ) -> None:
        if not isinstance(publisher, AlertPublisher):
            raise TypeError("publisher must be an AlertPublisher")
        self.publisher = publisher
        self.known_devices = self._normalize_set(known_devices)
        self.known_access_points = self._normalize_set(known_access_points)
        for name, value in (
            ("destination_fanout_threshold", destination_fanout_threshold),
            ("destination_window_seconds", destination_window_seconds),
            ("packet_burst_threshold", packet_burst_threshold),
            ("packet_window_seconds", packet_window_seconds),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.destination_fanout_threshold = destination_fanout_threshold
        self.destination_window_seconds = destination_window_seconds
        self.packet_burst_threshold = packet_burst_threshold
        self.packet_window_seconds = packet_window_seconds
        self._lock = RLock()
        self._ip_to_mac: dict[str, str] = {}
        self._unknown_seen: set[str] = set()
        self._rogue_aps_seen: set[str] = set()
        self._arp_conflicts_seen: set[tuple[str, str, str]] = set()
        self._source_observations: dict[str, deque[tuple[datetime, str]]] = {}
        self._fanout_seen: set[str] = set()
        self._burst_seen: set[str] = set()

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
            if source_address and record.destination:
                observations = self._source_observations.setdefault(
                    source_address, deque()
                )
                observations.append((timestamp, record.destination))
                fanout_cutoff = timestamp - timedelta(
                    seconds=self.destination_window_seconds
                )
                burst_cutoff = timestamp - timedelta(
                    seconds=self.packet_window_seconds
                )
                while observations and observations[0][0] < min(
                    fanout_cutoff, burst_cutoff
                ):
                    observations.popleft()

                unique_destinations = {
                    destination
                    for seen_at, destination in observations
                    if seen_at >= fanout_cutoff
                }
                if (
                    source_address not in self._fanout_seen
                    and len(unique_destinations) >= self.destination_fanout_threshold
                ):
                    self._fanout_seen.add(source_address)
                    events.append(
                        AlertEvent(
                            rule_id="destination-fanout",
                            severity="warning",
                            message=(
                                f"Possible network scan: {source_address} contacted "
                                f"{len(unique_destinations)} destinations within "
                                f"{self.destination_window_seconds} seconds"
                            ),
                            timestamp=timestamp,
                            evidence={
                                "source_address": source_address,
                                "unique_destinations": str(len(unique_destinations)),
                                "window_seconds": str(self.destination_window_seconds),
                            },
                        )
                    )

                packet_count = sum(
                    seen_at >= burst_cutoff for seen_at, _ in observations
                )
                if (
                    source_address not in self._burst_seen
                    and packet_count >= self.packet_burst_threshold
                ):
                    self._burst_seen.add(source_address)
                    events.append(
                        AlertEvent(
                            rule_id="traffic-volume-burst",
                            severity="warning",
                            message=(
                                f"Unusually high packet volume from {source_address}: "
                                f"{packet_count} packets in "
                                f"{self.packet_window_seconds} seconds"
                            ),
                            timestamp=timestamp,
                            evidence={
                                "source_address": source_address,
                                "packet_count": str(packet_count),
                                "window_seconds": str(self.packet_window_seconds),
                            },
                        )
                    )

                if len(self._source_observations) > 2048:
                    oldest_source = next(iter(self._source_observations))
                    if oldest_source != source_address:
                        del self._source_observations[oldest_source]

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

            if (
                self.known_devices
                and source_mac
                and source_mac not in self.known_devices
                and source_mac not in self._unknown_seen
            ):
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
