"""Orchestrate Capture -> Analysis -> Storage with presentation-ready statistics."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from threading import Event, Lock
from typing import TextIO

from pocket_packet_sniffer.analysis.alerts import AlertBus, SuspiciousActivityDetector
from pocket_packet_sniffer.analysis.models import PacketRecord as AnalyzedPacket
from pocket_packet_sniffer.analysis.parser import PacketParser
from pocket_packet_sniffer.analysis.pipeline import PacketAnalyzer
from pocket_packet_sniffer.analysis.statistics import TrafficStatistics
from pocket_packet_sniffer.capture import CapturedPacket, Capturer
from pocket_packet_sniffer.presentation.capture_runner import (
    EXIT_SUCCESS,
    run_capture_with_error_handling,
)
from pocket_packet_sniffer.storage.models import PacketRecord as StoredPacket
from pocket_packet_sniffer.storage.repository import Repository


@dataclass(frozen=True, slots=True)
class CaptureSessionResult:
    """Counts and process exit status from one capture session."""

    session_id: str
    packets_seen: int
    packets_stored: int
    packets_ignored: int
    exit_code: int


class CaptureSession:
    """Coordinate layers without leaking capture-backend details into Analysis.

    CapturedPacket retains the original frame. Analysis produces normalized
    metadata. This application service adapts that metadata plus the original
    bytes to the Storage PacketRecord contract.
    """

    def __init__(
        self,
        capturer: Capturer,
        repository: Repository,
        *,
        session_id: str | None = None,
        analyzer: PacketAnalyzer | None = None,
        statistics: TrafficStatistics | None = None,
        on_record: Callable[[AnalyzedPacket], None] | None = None,
        alert_bus: AlertBus | None = None,
        detector: SuspiciousActivityDetector | None = None,
    ) -> None:
        self.capturer = capturer
        self.repository = repository
        self.session_id = session_id or str(uuid.uuid4())
        if not isinstance(self.session_id, str) or not self.session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        self.analyzer = analyzer or PacketParser()
        self.statistics = statistics or TrafficStatistics()
        self.on_record = on_record
        self.alert_bus = alert_bus
        self.detector = detector if detector is not None else (
            SuspiciousActivityDetector() if alert_bus is not None else None
        )
        self._lock = Lock()
        self._packets_seen = 0
        self._packets_stored = 0
        self._packets_ignored = 0

    def process_packet(self, captured: CapturedPacket) -> None:
        """Analyze and store one raw packet; malformed/unsupported packets are skipped."""
        with self._lock:
            self._packets_seen += 1

        backend = getattr(self.capturer, "name", type(self.capturer).__name__)
        analyzed = self.analyzer.parse(captured, backend=backend)
        if analyzed is None:
            with self._lock:
                self._packets_ignored += 1
            return

        stored = StoredPacket(
            session_id=self.session_id,
            protocol=analyzed.protocol,
            source_address=analyzed.source,
            destination_address=analyzed.destination,
            timestamp=analyzed.timestamp,
            packet_data=captured.packet_data,
            link_type=captured.link_type,
            original_length=captured.original_length,
            interface=analyzed.interface,
        )
        self.repository.save(stored)
        self.statistics.observe(analyzed)
        if self.detector is not None and self.alert_bus is not None:
            for alert in self.detector.inspect(analyzed):
                self.alert_bus.publish(alert)
        with self._lock:
            self._packets_stored += 1

        if self.on_record is not None:
            self.on_record(analyzed)

    def run(
        self,
        stop_event: Event,
        *,
        count: int | None = None,
        stderr: TextIO | None = None,
    ) -> CaptureSessionResult:
        """Run capture with stable exit codes and return session counts."""
        if stderr is None:
            exit_code = run_capture_with_error_handling(
                self.capturer, self.process_packet, stop_event, count=count
            )
        else:
            exit_code = run_capture_with_error_handling(
                self.capturer, self.process_packet, stop_event, count=count, stderr=stderr
            )
        return self.result(exit_code)

    def result(self, exit_code: int = EXIT_SUCCESS) -> CaptureSessionResult:
        """Snapshot current progress; safe to call after run() or during review."""
        with self._lock:
            return CaptureSessionResult(
                session_id=self.session_id,
                packets_seen=self._packets_seen,
                packets_stored=self._packets_stored,
                packets_ignored=self._packets_ignored,
                exit_code=exit_code,
            )

    def statistics_snapshot(self) -> dict[str, object]:
        """Return lifetime totals and the latest rolling rate for the dashboard."""
        return self.statistics.snapshot()
