"""Composable protocol-analyzer pipeline.

An analyzer receives the backend-neutral raw capture record and either
returns a normalized Analysis PacketRecord or declines the packet with None.
Specialized analyzers can be composed before the default PacketParser.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from pocket_packet_sniffer.capture.models import CapturedPacket

from .models import PacketRecord


class PacketAnalyzer(Protocol):
    """Protocol implemented by any specialized packet analyzer."""

    def parse(
        self,
        captured: CapturedPacket,
        *,
        backend: str | None = None,
    ) -> PacketRecord | None:
        """Return a normalized record when this analyzer recognizes the packet."""


class AnalyzerPipeline:
    """Try analyzers in order and return the first non-None result."""

    def __init__(self, analyzers: Iterable[PacketAnalyzer]) -> None:
        self._analyzers = tuple(analyzers)
        if not self._analyzers:
            raise ValueError("analyzer pipeline must contain at least one analyzer")

    @property
    def analyzers(self) -> tuple[PacketAnalyzer, ...]:
        """Return the configured analyzer sequence as an immutable tuple."""
        return self._analyzers

    def parse(
        self,
        captured: CapturedPacket,
        *,
        backend: str | None = None,
    ) -> PacketRecord | None:
        """Return the first analyzer result, or None if all decline the packet."""
        for analyzer in self._analyzers:
            record = analyzer.parse(captured, backend=backend)
            if record is not None:
                return record
        return None
