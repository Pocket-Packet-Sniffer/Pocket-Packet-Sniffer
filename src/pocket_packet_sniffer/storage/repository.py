"""Storage-independent repository interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Sequence

from .models import PacketRecord, SessionSummary


class Repository(ABC):
    """Common boundary used by analysis and presentation layers."""

    @abstractmethod
    def save(self, record: PacketRecord) -> None:
        """Persist one record or raise a RepositoryError; never fail silently."""

    @abstractmethod
    def query(
        self,
        protocol: str | None = None,
        address: str | None = None,
        time_window: Sequence[datetime | None] | None = None,
        session_id: str | None = None,
    ) -> list[PacketRecord]:
        """Return records matching every supplied filter, oldest first.

        A time window is an inclusive ``(start, end)`` pair. Either endpoint
        may be ``None`` to leave that side open.
        """

    @abstractmethod
    def get_session_summary(self, session_id: str) -> SessionSummary:
        """Return the count and timestamp bounds for a session."""
