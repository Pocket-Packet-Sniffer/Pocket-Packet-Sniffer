from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from pocket_packet_sniffer.storage import PacketRecord, Repository, SessionSummary


class MemoryRepository(Repository):
    def __init__(self, records=()):
        self.records = list(records)

    def save(self, record: PacketRecord) -> None:
        self.records.append(record)

    def query(self, protocol=None, address=None, time_window=None, session_id=None):
        return list(self.records)

    def get_session_summary(self, session_id: str) -> SessionSummary:
        matching = [record for record in self.records if record.session_id == session_id]
        if not matching:
            return SessionSummary(session_id, 0, None, None)
        return SessionSummary(
            session_id,
            len(matching),
            min(record.timestamp for record in matching),
            max(record.timestamp for record in matching),
        )


def _record(record_id: str, session: str, timestamp: datetime) -> PacketRecord:
    return PacketRecord(
        record_id=record_id,
        session_id=session,
        timestamp=timestamp,
        protocol="TCP",
        source_address="192.0.2.1",
        destination_address="198.51.100.1",
        packet_data=b"frame",
    )


def test_repository_default_session_listing_groups_sorts_and_handles_empty():
    first_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    repository = MemoryRepository(
        [
            _record("a", "older", first_time),
            _record("b", "newer", first_time + timedelta(seconds=3)),
            _record("c", "older", first_time + timedelta(seconds=1)),
        ]
    )

    summaries = repository.list_sessions()

    assert [(item.session_id, item.packet_count) for item in summaries] == [("newer", 1), ("older", 2)]
    assert summaries[1].first_packet_at == first_time
    assert summaries[1].last_packet_at == first_time + timedelta(seconds=1)
    assert MemoryRepository().list_sessions() == []


def test_repository_default_session_query_validates_and_filters():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    records = [_record("a", "wanted", now), _record("b", "other", now)]
    repository = MemoryRepository(records)

    assert repository.query_session("wanted") == [records[0]]
    for invalid in ("", "   ", None, 42):
        with pytest.raises(ValueError, match="non-empty string"):
            repository.query_session(invalid)
