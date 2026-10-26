"""Thread-safe traffic counters and a rolling packet-rate window."""

from __future__ import annotations

from collections import Counter, deque
from threading import Lock
import time
from collections.abc import Callable
from typing import Any

from .models import PacketRecord


class TrafficStatistics:
    """Accumulate lifetime traffic totals and a rolling packets-per-second rate.

    Talker counts are attributed to the source address, i.e. packets sent by
    that address. The default rate window is two seconds, matching the SRS
    dashboard refresh requirement.
    """

    def __init__(
        self,
        *,
        window_seconds: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if isinstance(window_seconds, bool) or not isinstance(window_seconds, (int, float)):
            raise ValueError("window_seconds must be a positive number")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be a positive number")
        self.window_seconds = float(window_seconds)
        self._clock = clock
        self._lock = Lock()
        self._protocols: Counter[str] = Counter()
        self._talkers: Counter[str] = Counter()
        self._recent_packets: deque[float] = deque()
        self._total_packets = 0
        self._total_bytes = 0

    def observe(self, record: PacketRecord) -> None:
        """Record one successfully stored analyzed packet."""
        now = self._clock()
        with self._lock:
            self._total_packets += 1
            self._total_bytes += record.packet_size
            self._protocols[record.protocol] += 1
            if record.source:
                self._talkers[record.source] += 1
            self._recent_packets.append(now)
            self._discard_old(now)

    def _discard_old(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._recent_packets and self._recent_packets[0] < cutoff:
            self._recent_packets.popleft()

    def snapshot(self) -> dict[str, Any]:
        """Return a renderer-compatible immutable-by-convention snapshot."""
        now = self._clock()
        with self._lock:
            self._discard_old(now)
            protocols = sorted(self._protocols.items(), key=lambda item: (-item[1], item[0]))
            talkers = sorted(self._talkers.items(), key=lambda item: (-item[1], item[0]))[:5]
            return {
                "total_packets": self._total_packets,
                "total_bytes": self._total_bytes,
                "packets_per_sec": len(self._recent_packets) / self.window_seconds,
                "protocols": protocols,
                "top_talkers": talkers,
            }
