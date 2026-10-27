"""Concurrent orchestration of multiple independent capture sessions."""
from __future__ import annotations

import re
import time
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from threading import Event, Lock, Thread
from typing import Any

from pocket_packet_sniffer.analysis.pipeline import PacketAnalyzer
from pocket_packet_sniffer.application.session import (
    CaptureSession,
    CaptureSessionResult,
)
from pocket_packet_sniffer.capture import CapturedPacket, Capturer
from pocket_packet_sniffer.presentation.capture_runner import (
    EXIT_CAPTURE_ERROR,
    EXIT_INTERRUPTED,
    EXIT_SUCCESS,
)
from pocket_packet_sniffer.storage.repository import Repository


@dataclass(frozen=True, slots=True)
class MultiCaptureSessionResult:
    """Immutable snapshot of child-session outcomes."""

    session_id: str
    results: Mapping[str, CaptureSessionResult]
    errors: Mapping[str, str]

    @property
    def exit_code(self) -> int:
        """Combine the exit status of the child sessions."""
        if self.errors or any(result.exit_code == EXIT_CAPTURE_ERROR for result in self.results.values()):
            return EXIT_CAPTURE_ERROR
        if any(result.exit_code == EXIT_INTERRUPTED for result in self.results.values()):
            return EXIT_INTERRUPTED
        return EXIT_SUCCESS


class MultiCaptureSession:
    """Run multiple Capturer strategies concurrently and aggregate statistics.

    Every child has its own session ID and PCAP file. This is intentional:
    classic PCAP stores one link-layer type in a file.
    """

    def __init__(
        self,
        capturers: Mapping[str, Capturer],
        repository: Repository,
        *,
        session_id: str | None = None,
        analyzer: PacketAnalyzer | None = None,
        on_captured_packet: Callable[[CapturedPacket], None] | None = None,
    ) -> None:
        if not isinstance(capturers, Mapping) or len(capturers) < 2:
            raise ValueError("at least two named capturers are required")
        if session_id is not None and (not isinstance(session_id, str) or not session_id.strip()):
            raise ValueError("session_id must be a non-empty string")
        names = [name.strip() if isinstance(name, str) else "" for name in capturers]
        if any(not name for name in names) or len(set(names)) != len(names):
            raise ValueError("capturer names must be non-empty and unique")
        self.session_id = session_id.strip() if session_id else str(uuid.uuid4())
        self._lock = Lock()
        self._started = False
        self._events = {name: Event() for name in names}
        self._results: dict[str, CaptureSessionResult] = {}
        self._errors: dict[str, str] = {}
        self._threads: dict[str, Thread] = {}
        self.sessions: dict[str, CaptureSession] = {}
        for index, (original_name, capturer) in enumerate(capturers.items(), start=1):
            name = original_name.strip()
            slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-._") or "backend"
            child_id = f"{self.session_id}-{index}-{slug}"
            self.sessions[name] = CaptureSession(
                capturer,
                repository,
                session_id=child_id,
                analyzer=analyzer,
                on_captured_packet=on_captured_packet,
            )

    def start(self) -> None:
        """Start all child sessions. A coordinator may only start once."""
        with self._lock:
            if self._started:
                raise RuntimeError("multi-capture session has already been started")
            self._started = True
            for name, child in self.sessions.items():
                thread = Thread(
                    target=self._run_child,
                    args=(name, child, self._events[name]),
                    name=f"pps-capture-{name}",
                    daemon=True,
                )
                self._threads[name] = thread
                thread.start()

    def _run_child(self, name: str, child: CaptureSession, stop_event: Event) -> None:
        try:
            result = child.run(stop_event)
        except Exception as exc:
            result = child.result(EXIT_CAPTURE_ERROR)
            with self._lock:
                self._errors[name] = f"{exc.__class__.__name__}: {exc}"
        with self._lock:
            self._results[name] = result

    def stop(self) -> None:
        """Request cooperative shutdown of all capture workers."""
        for event in self._events.values():
            event.set()

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for workers, returning False if any remain alive at timeout."""
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must be non-negative or None")
        deadline = None if timeout is None else time.monotonic() + timeout
        for thread in tuple(self._threads.values()):
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            thread.join(remaining)
        return not self.is_running()

    def is_running(self) -> bool:
        """Return whether any child worker remains alive."""
        return any(thread.is_alive() for thread in self._threads.values())

    def statistics_snapshot(self) -> dict[str, Any]:
        """Aggregate counters without moving analysis or storage into Presentation."""
        snapshots = [child.statistics_snapshot() for child in self.sessions.values()]
        protocols: Counter[str] = Counter()
        talkers: Counter[str] = Counter()
        total_packets = total_bytes = 0
        packets_per_sec = 0.0
        for snapshot in snapshots:
            total_packets += int(snapshot.get("total_packets", 0))
            total_bytes += int(snapshot.get("total_bytes", 0))
            packets_per_sec += float(snapshot.get("packets_per_sec", 0.0))
            protocols.update(dict(snapshot.get("protocols", ())))
            talkers.update(dict(snapshot.get("top_talkers", ())))
        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "packets_per_sec": packets_per_sec,
            "protocols": sorted(protocols.items(), key=lambda item: (-item[1], item[0])),
            "top_talkers": sorted(talkers.items(), key=lambda item: (-item[1], item[0]))[:5],
        }

    def result(self) -> MultiCaptureSessionResult:
        """Return current child results and worker errors."""
        with self._lock:
            return MultiCaptureSessionResult(
                session_id=self.session_id,
                results=dict(self._results),
                errors=dict(self._errors),
            )
