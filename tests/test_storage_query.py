from __future__ import annotations

import sqlite3
import struct
from datetime import datetime, timedelta, timezone

import pytest

from pocket_packet_sniffer.storage import (
    DuplicateRecordError,
    InvalidRecordError,
    PacketRecord,
    PcapSqliteRepository,
    Repository,
    StorageAccessError,
    StorageCorruptionError,
    StorageUnavailableError,
)

BASE_TIME = datetime(2026, 10, 26, 12, 30, 0, 123456, tzinfo=timezone.utc)


def record(
    *,
    record_id: str = "record-1",
    session_id: str = "session-1",
    protocol: str = "TCP",
    source: str | None = "192.0.2.10",
    destination: str | None = "198.51.100.20",
    timestamp: datetime = BASE_TIME,
    payload: bytes = b"sample-packet-bytes",
    link_type: int = 1,
) -> PacketRecord:
    return PacketRecord(
        record_id=record_id,
        session_id=session_id,
        protocol=protocol,
        source_address=source,
        destination_address=destination,
        timestamp=timestamp,
        packet_data=payload,
        link_type=link_type,
    )


def test_save_writes_pcap_and_query_restores_packet(tmp_path):
    repository = PcapSqliteRepository(tmp_path)
    packet = record()

    assert isinstance(repository, Repository)
    assert repository.save(packet) is None
    results = repository.query()

    assert results == [packet]
    pcap = next(tmp_path.glob("*.pcap"))
    content = pcap.read_bytes()
    global_header = struct.unpack("<IHHIIII", content[:24])
    packet_header = struct.unpack("<IIII", content[24:40])
    assert global_header == (0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    assert packet_header == (int(BASE_TIME.timestamp()), 123456, len(packet.packet_data), len(packet.packet_data))
    assert content[40:] == packet.packet_data


def test_query_filters_protocol_address_and_inclusive_time_window(tmp_path):
    repository = PcapSqliteRepository(tmp_path)
    first = record(record_id="first")
    second = record(
        record_id="second",
        session_id="session-2",
        protocol="udp",
        source="2001:db8::1",
        destination="2001:db8::2",
        timestamp=BASE_TIME + timedelta(seconds=1),
        link_type=101,
    )
    repository.save(first)
    repository.save(second)

    assert repository.query(protocol="tcp") == [first]
    assert repository.query(address="198.51.100.20") == [first]
    assert repository.query(address="2001:db8::1") == [second]
    assert repository.query(time_window=(BASE_TIME, BASE_TIME)) == [first]
    assert repository.query(protocol="UDP", time_window=(BASE_TIME, None)) == [second]
    assert repository.query(protocol="ICMP") == []


def test_query_matches_source_and_destination_addresses(tmp_path):
    repository = PcapSqliteRepository(tmp_path)
    packet = record()
    repository.save(packet)

    assert repository.query(address=packet.source_address) == [packet]
    assert repository.query(address=packet.destination_address) == [packet]


def test_query_combines_filters_with_and_semantics(tmp_path):
    repository = PcapSqliteRepository(tmp_path)
    packet = record()
    repository.save(packet)

    assert repository.query(protocol="tcp", address=packet.source_address) == [packet]
    assert repository.query(protocol="udp", address=packet.source_address) == []


def test_session_summary_and_empty_session(tmp_path):
    repository = PcapSqliteRepository(tmp_path)
    repository.save(record(timestamp=BASE_TIME))
    repository.save(record(record_id="second", timestamp=BASE_TIME + timedelta(seconds=2)))

    summary = repository.get_session_summary("session-1")
    assert (summary.packet_count, summary.first_packet_at, summary.last_packet_at) == (
        2,
        BASE_TIME,
        BASE_TIME + timedelta(seconds=2),
    )
    empty = repository.get_session_summary("not-created")
    assert empty.packet_count == 0
    assert empty.first_packet_at is empty.last_packet_at is None


def test_duplicate_record_id_is_rejected_without_extra_pcap_record(tmp_path):
    repository = PcapSqliteRepository(tmp_path)
    packet = record()
    repository.save(packet)

    with pytest.raises(DuplicateRecordError):
        repository.save(packet)

    assert repository.query() == [packet]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"protocol": "  "},
        {"address": "  "},
        {"time_window": (BASE_TIME, BASE_TIME - timedelta(seconds=1))},
        {"time_window": (None, None)},
        {"time_window": ("not-a-datetime", None)},
        {"time_window": (BASE_TIME,)},
        {"time_window": 42},
    ],
)
def test_invalid_filters_raise_clear_error(tmp_path, kwargs):
    repository = PcapSqliteRepository(tmp_path)

    with pytest.raises(InvalidRecordError):
        repository.query(**kwargs)


def test_invalid_packet_record_is_rejected():
    with pytest.raises(InvalidRecordError):
        record(timestamp=datetime(2026, 10, 26, 12, 30))
    with pytest.raises(InvalidRecordError):
        record(payload=b"")
    with pytest.raises(InvalidRecordError):
        record(payload=b"x" * 65536)


def test_records_cannot_change_link_type_within_a_session(tmp_path):
    repository = PcapSqliteRepository(tmp_path)
    repository.save(record(link_type=1))

    with pytest.raises(InvalidRecordError):
        repository.save(record(record_id="different", link_type=101))

    assert len(repository.query()) == 1


def test_missing_pcap_file_is_reported(tmp_path):
    repository = PcapSqliteRepository(tmp_path)
    repository.save(record())
    next(tmp_path.glob("*.pcap")).unlink()

    with pytest.raises(StorageUnavailableError):
        repository.query()


def test_missing_metadata_file_is_not_recreated_as_empty_store(tmp_path):
    repository = PcapSqliteRepository(tmp_path)
    repository.save(record())
    repository.database_path.unlink()

    with pytest.raises(StorageUnavailableError):
        repository.query()
    assert not repository.database_path.exists()


def test_truncated_pcap_is_reported_as_corruption(tmp_path):
    repository = PcapSqliteRepository(tmp_path)
    repository.save(record())
    next(tmp_path.glob("*.pcap")).write_bytes(b"broken")

    with pytest.raises(StorageCorruptionError):
        repository.query()


@pytest.mark.parametrize(
    ("column", "value"),
    [("pcap_offset", -1), ("protocol", "")],
)
def test_malformed_indexed_record_is_reported_as_corruption(tmp_path, column, value):
    repository = PcapSqliteRepository(tmp_path)
    repository.save(record())
    with sqlite3.connect(repository.database_path) as db:
        db.execute(f"UPDATE packets SET {column} = ?", (value,))

    with pytest.raises(StorageCorruptionError):
        repository.query()


def test_metadata_does_not_contain_packet_bytes(tmp_path):
    repository = PcapSqliteRepository(tmp_path)
    packet = record(payload=b"secret-captured-payload")
    repository.save(packet)
    with sqlite3.connect(repository.database_path) as db:
        stored_values = db.execute("SELECT * FROM packets").fetchone()

    assert packet.packet_data not in repr(stored_values).encode()


def test_permission_failure_is_reported(tmp_path, monkeypatch):
    repository = PcapSqliteRepository(tmp_path)
    repository.save(record())
    pcap = next(tmp_path.glob("*.pcap"))
    original_open = type(pcap).open

    def denied_open(path, *args, **kwargs):
        if path == pcap:
            raise PermissionError("denied for test")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(type(pcap), "open", denied_open)
    with pytest.raises(StorageAccessError):
        repository.query()


def test_save_permission_failure_is_reported_without_adding_record(tmp_path, monkeypatch):
    repository = PcapSqliteRepository(tmp_path)
    existing = record()
    repository.save(existing)
    pcap = next(tmp_path.glob("*.pcap"))
    pcap_size_before = pcap.stat().st_size
    original_open = type(pcap).open

    def denied_write_open(path, mode="r", *args, **kwargs):
        if path == pcap and mode == "r+b":
            raise PermissionError("denied for test")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(type(pcap), "open", denied_write_open)
    with pytest.raises(StorageAccessError):
        repository.save(record(record_id="second"))

    monkeypatch.setattr(type(pcap), "open", original_open)
    assert pcap.stat().st_size == pcap_size_before
    assert repository.query() == [existing]



def test_query_session_filters_in_sql_and_preserves_interface(tmp_path):
    repository = PcapSqliteRepository(tmp_path)
    first = record(record_id="session-a-1", session_id="session-a")
    second = record(record_id="session-b-1", session_id="session-b", protocol="UDP")
    repository.save(first)
    repository.save(second)

    assert repository.query_session("session-a") == [first]
    assert repository.query_session("session-a", protocol="UDP") == []
    assert repository.query_session("session-b") == [second]
    with pytest.raises(InvalidRecordError):
        repository.query_session("  ")


def test_legacy_database_is_migrated_with_unknown_interface_default(tmp_path):
    database = tmp_path / "metadata.sqlite3"
    with sqlite3.connect(database) as db:
        db.executescript(
            """
            CREATE TABLE captures (
                session_id TEXT PRIMARY KEY,
                pcap_name TEXT NOT NULL,
                link_type INTEGER NOT NULL
            );
            CREATE TABLE packets (
                record_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES captures(session_id),
                protocol TEXT NOT NULL,
                source_address TEXT,
                destination_address TEXT,
                timestamp_us INTEGER NOT NULL,
                pcap_offset INTEGER NOT NULL,
                captured_length INTEGER NOT NULL,
                original_length INTEGER NOT NULL
            );
            """
        )

    repository = PcapSqliteRepository(tmp_path)
    with sqlite3.connect(database) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(packets)")}
    assert "interface" in columns
    assert repository.query() == []
