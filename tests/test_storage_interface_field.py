from datetime import UTC, datetime
import sqlite3

from pocket_packet_sniffer.storage import PacketRecord, PcapSqliteRepository


def test_storage_round_trips_required_capture_interface(tmp_path):
    repository = PcapSqliteRepository(tmp_path / "captures")
    record = PacketRecord(
        session_id="interface-session",
        protocol="TCP",
        source_address="192.0.2.1",
        destination_address="198.51.100.2",
        timestamp=datetime.now(UTC),
        packet_data=b"frame",
        interface="eth0",
    )
    repository.save(record)

    loaded = repository.query(session_id="interface-session")[0]
    assert loaded.interface == "eth0"


def test_repository_migrates_legacy_metadata_database(tmp_path):
    directory = tmp_path / "captures"
    directory.mkdir()
    database = directory / "metadata.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript(
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

    PcapSqliteRepository(directory)
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(packets)")}
    assert "interface" in columns
