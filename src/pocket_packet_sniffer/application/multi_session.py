"""Concurrent capture-session orchestration with isolated PCAP link types."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from threading import Event, Lock, Thread

from pocket_packet_sniffer.analysis.alerts import AlertBus, SuspiciousActivityDetector
from pocket_packet_sniffer.analysis.pipeline import PacketAnalyzer
from pocket_packet_sniffer.analysis.statistics import TrafficStatistics
from pocket_packet_sniffer.capture import Capturer
from pocket_packet_sniffer.presentation.capture_runner import EXIT_SUCCESS
from pocket_packet_sniffer.storage.repository import Repository

from .session import CaptureSession, CaptureSessionResult


@dataclass(frozen=True, slots=True)
class MultiCaptureSessionResult:
    """Aggregate lifecycle result for independently stored backend sessions."""

    session_id: str
    sessions: tuple[CaptureSessionResult, ...]
    exit_code: int
    errors: tuple[str, ...] = ()

    @property
    def packets_seen(self) -> int:
        return sum(session.packets_seen for session in self.sessions)

    @property
    def packets_stored(self) -> int:
        return sum(session.packets_stored for session in self.sessions)

    @property
    def packets_ignored(self) -> int:
        return sum(session.packets_ignored for session in self.sessions)


class MultiCaptureSession:
    """Run independent CaptureSessions concurrently and aggregate statistics.

    Each backend has its own storage session because classic PCAP requires one
    link type per file. Analysis and storage remain unchanged, while statistics
    and alert observers can be shared safely across sessions.
    """

    def __init__(
        self,
        capturers: tuple[Capturer, ...] | list[Capturer],
        repository: Repository,
        *,
        session_id: str | None = None,
        analyzer: PacketAnalyzer | None = None,
        statistics: TrafficStatistics | None = None,
        alert_bus: AlertBus | None = None,
        detector: SuspiciousActivityDetector | None = None,
    ) -> None:
        self.capturers = tuple(capturers)
        if len(self.capturers) < 2:
            raise ValueError("MultiCaptureSession requires at least two backends")
        if len({id(capturer) for capturer in self.capturers}) != len(self.capturers):
            raise ValueError("each backend must be a distinct Capturer instance")
        self.session_id = session_id or str(uuid.uuid4())
        if not isinstance(self.session_id, str) or not self.session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        self.statistics = statistics or TrafficStatistics()
        self.alert_bus = alert_bus
        self.detector = detector
        self.sessions: list[CaptureSession] = []
        for index, capturer in enumerate(self.capturers, start=1):
            interface = getattr(capturer, "interface", None) or getattr(capturer, "name", "backend")
            safe_interface = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(interface)).strip("-")[:40] or "backend"
            self.sessions.append(
                CaptureSession(
                    capturer,
                    repository,
                    session_id=f"{self.session_id}-{index}-{safe_interface}",
                    analyzer=analyzer,
                    statistics=self.statistics,
                    alert_bus=alert_bus,
                    detector=detector,
                )
            )

    def statistics_snapshot(self) -> dict[str, object]:
        """Return combined statistics from all active and completed backends."""
        return self.statistics.snapshot()

    def run(
        self,
        stop_event: Event,
        *,
        count: int | None = None,
    ) -> MultiCaptureSessionResult:
        """Run all backend sessions in threads and stop peers on failure."""
        results: list[CaptureSessionResult | None] = [None] * len(self.sessions)
        result_lock = Lock()
        interrupted = False
        errors: list[str | None] = [None] * len(self.sessions)

        def run_session(index: int, session: CaptureSession) -> None:
            try:
                result = session.run(stop_event, count=count)
            except Exception as exc:
                result = session.result(2)
                errors[index] = f"{type(exc).__name__}: {exc}"
                stop_event.set()
            with result_lock:
                results[index] = result
            if result.exit_code != EXIT_SUCCESS:
                stop_event.set()

        workers = [
            Thread(
                target=run_session,
                args=(index, session),
                name=f"pps-session-{index + 1}",
                daemon=True,
            )
            for index, session in enumerate(self.sessions)
        ]
        for worker in workers:
            worker.start()
        try:
            while any(worker.is_alive() for worker in workers):
                if stop_event.wait(0.1):
                    break
        except KeyboardInterrupt:
            interrupted = True
            stop_event.set()
        finally:
            for worker in workers:
                worker.join()

        completed = tuple(
            result if result is not None else session.result(130 if interrupted else 2)
            for result, session in zip(results, self.sessions, strict=True)
        )
        exit_code = 130 if interrupted else next(
            (result.exit_code for result in completed if result.exit_code != EXIT_SUCCESS),
            EXIT_SUCCESS,
        )
        return MultiCaptureSessionResult(
            self.session_id,
            completed,
            exit_code,
            tuple(error for error in errors if error is not None),
        )
