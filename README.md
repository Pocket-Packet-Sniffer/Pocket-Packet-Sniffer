# Pocket Packet Sniffer — Storage and Query Layer

This repository branch implements the Storage and Query layer for Pocket Packet Sniffer. It stores captured packet bytes in classic PCAP files and searchable packet metadata in SQLite. The layer exposes a `Repository` interface so capture, analysis, and presentation code can use storage without opening files or databases directly.

The implementation is limited to storage and querying. It does not capture traffic, parse packets, or provide a CLI. Use packet data from networks and devices you are authorized to monitor.

## Requirements

- Python 3.10 or newer
- SQLite (included with Python)
- Pytest for running the tests

Install the package and test dependency from the repository root:

```sh
python -m pip install -e ".[test]"
```

## Storage format

- Raw packet bytes are written to classic PCAP 2.4 files with microsecond timestamps and a 65,535-byte snap length.
- Each session has its own PCAP file because classic PCAP records one link type in its global header. A session cannot change link type after its first packet.
- The local `metadata.sqlite3` database stores record/session IDs, protocol, addresses, timestamp, packet lengths, link type association, and PCAP offsets. Packet payload bytes are not duplicated in SQLite.
- Session IDs are hashed for PCAP filenames. Captures are not uploaded or exported automatically.
- On POSIX systems, newly created directories request mode `0700` and files request mode `0600`. On other platforms, filesystem ACLs control access.

## Using the repository

`PacketRecord` is the value passed from analysis to storage. Timestamps must be timezone-aware. Addresses are strings so IPv4, IPv6, MAC, and other analyzer-provided identifiers can be represented.

```python
from datetime import datetime, timezone

from pocket_packet_sniffer.storage import PacketRecord, PcapSqliteRepository

repository = PcapSqliteRepository("captures")
record = PacketRecord(
    session_id="capture-001",
    protocol="TCP",
    source_address="192.0.2.10",
    destination_address="198.51.100.20",
    timestamp=datetime.now(timezone.utc),
    packet_data=b"sample captured bytes",
    link_type=1,  # Ethernet
)

repository.save(record)
matching_packets = repository.query(
    protocol="TCP",
    address="192.0.2.10",
)
summary = repository.get_session_summary("capture-001")
```

`save(record)` persists one packet. `query()` returns matching `PacketRecord` objects in timestamp order; with no filters it returns all stored records. `get_session_summary(session_id)` returns the session's packet count and first/last timestamps.

## Query filters

Filters combine with AND semantics:

- `protocol="TCP"` matches protocol names case-insensitively.
- `address="192.0.2.10"` matches an exact source **or** destination address.
- `time_window=(start, end)` includes both timezone-aware datetime endpoints. Either endpoint may be `None` for an open bound, but both cannot be `None`.

No matches produce an empty list. Invalid filters raise `InvalidRecordError`.

## Errors

- `InvalidRecordError`: malformed packet record, protocol/address, or query filter.
- `DuplicateRecordError`: a record ID is already stored.
- `StorageUnavailableError`: a required metadata or capture file is missing or unavailable.
- `StorageAccessError`: the process lacks permission to access storage.
- `StorageCorruptionError`: a PCAP file or indexed record is malformed or inconsistent.
- `RepositoryError`: another storage-layer failure.

The package exports these exceptions and the `Repository`, `PacketRecord`, `SessionSummary`, and `PcapSqliteRepository` types from `pocket_packet_sniffer.storage`.

## Tests

Run the storage/query tests from the repository root:

```sh
pytest
```

The suite uses generated packet bytes and temporary storage to cover PCAP round-trip, protocol/address/time filtering, empty results, malformed and duplicate records, missing/corrupt files, and access/storage failures.

## Limitations

- Classic PCAP only; PCAPNG is not supported.
- Each capture session has one link type.
- The layer does not parse packet bytes or verify that supplied metadata matches them; that belongs to Analysis.
- There is no encryption, retention/pruning policy, or automatic recovery for a PCAP append left unindexed by a sudden process or system crash.
