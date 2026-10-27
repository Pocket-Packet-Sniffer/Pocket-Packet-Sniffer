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
    ) -> list[PacketRecord]:
        """Return records matching every supplied filter, oldest first.

        A time window is an inclusive ``(start, end)`` pair. Either endpoint
        may be ``None`` to leave that side open.
        """

    def query_session(
        self,
        session_id: str,
        protocol: str | None = None,
        address: str | None = None,
        time_window: Sequence[datetime | None] | None = None,
    ) -> list[PacketRecord]:
        """Return records from one session. Concrete repositories should query by session in the index."""
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        return [
            record
            for record in self.query(protocol=protocol, address=address, time_window=time_window)
            if record.session_id == session_id
        ]

    @abstractmethod
    def get_session_summary(self, session_id: str) -> SessionSummary:
        """Return the count and timestamp bounds for a session."""
