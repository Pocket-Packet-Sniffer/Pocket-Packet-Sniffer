"""Storage-independent repository interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
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

        Filters combine with AND semantics. A time window is an inclusive
        (start, end) pair. Either endpoint may be None to leave that side open.
        session_id optionally narrows results to one session.
        """

    def list_sessions(self) -> list[SessionSummary]:
        """Return summaries for persisted sessions, newest packet first.

        This compatibility implementation groups public query results.
        Indexed repositories should override it for efficiency.
        """
        grouped: dict[str, list[PacketRecord]] = {}
        for record in self.query():
            grouped.setdefault(record.session_id, []).append(record)
        summaries = [
            SessionSummary(
                session_id=session_id,
                packet_count=len(records),
                first_packet_at=min(record.timestamp for record in records),
                last_packet_at=max(record.timestamp for record in records),
            )
            for session_id, records in grouped.items()
        ]
        epoch = datetime.fromtimestamp(0, tz=timezone.utc)
        return sorted(
            summaries,
            key=lambda summary: (
                summary.last_packet_at or epoch,
                summary.session_id,
            ),
            reverse=True,
        )

    def query_session(self, session_id: str) -> list[PacketRecord]:
        """Return records for one session using a storage-independent contract.

        Repositories with session indexes should override this method to avoid
        reading unrelated sessions. The default keeps small test repositories
        source-compatible.
        """
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        return self.query(session_id=session_id)

    @abstractmethod
    def get_session_summary(self, session_id: str) -> SessionSummary:
        """Return the count and timestamp bounds for a session."""
