# Storage and Query Layer

This implementation covers SRS REQ-5 and REQ-6 and follows the Storage Layer and Repository Interface in SASD sections 3.4, 4.3.2, and 4.4. It intentionally does not implement capture, packet parsing, CLI, or presentation concerns.

## Contract

`PacketRecord` is the common analysis-to-storage record. It contains a record ID, session ID, UTC-aware capture timestamp, normalized protocol, optional source and destination address strings, captured packet bytes, PCAP link type, and original packet length. Address strings are not restricted to IP formats because Ethernet and BLE analyzers may supply MAC or other identifiers.

`Repository` defines:

- `save(record)`: persist one record or raise a storage-layer exception.
- `query(protocol=None, address=None, time_window=None)`: return records oldest first. Supplied filters combine with AND. Protocol matching is case-insensitive; address matches either source or destination exactly; time bounds are inclusive. A time window is `(start, end)` with either endpoint optionally `None`.
- `get_session_summary(session_id)`: return packet count and earliest/latest timestamps.

`PcapSqliteRepository` is the concrete implementation. It accepts a local storage directory and can be reopened against that directory to query prior captures.

## Data formats

- Raw bytes use classic PCAP version 2.4, little-endian microsecond timestamps, and a 65,535-byte snap length. Each session has one PCAP file. A session must use one link type, as required by the classic PCAP global header. Session IDs are hashed for filenames and are not used as paths.
- `metadata.sqlite3` stores packet IDs, session IDs, protocol, addresses, timestamp, packet length, PCAP offset, and link type association. It does not store packet payload bytes. Indexes support protocol, source/destination address, time, and session lookups.
- PCAP and SQLite remain local. Newly created directories request mode `0700`; files request `0600` on POSIX systems.

## Errors and consistency

- Invalid records and query filters raise `InvalidRecordError`.
- A repeated record ID raises `DuplicateRecordError`; duplicates are not silently appended.
- Missing/unavailable files raise `StorageUnavailableError`; permission failures raise `StorageAccessError`.
- Truncated or inconsistent PCAP records raise `StorageCorruptionError`.
- Other SQLite and filesystem write/read failures raise `RepositoryError`.
- A save appends and fsyncs the PCAP record before committing its SQLite metadata row. If the metadata operation fails, the writer attempts to truncate the PCAP back to its previous length (or remove a newly created PCAP). A process or machine crash between these operations can leave an unindexed trailing PCAP record; the repository does not attempt automatic crash recovery.

## Verification and limitations

`tests/test_storage_query.py` covers PCAP output and restore, protocol/address/time filters, combined filters, empty results, summaries, duplicate IDs, malformed records/filters, missing and corrupt PCAP files, link-type consistency, payload privacy in metadata, and permission errors.

The implementation does not parse packet bytes or validate that the supplied metadata agrees with those bytes; the Analysis Layer owns that responsibility. It does not prune captures, encrypt data at rest, support PCAPNG, or recover an orphaned PCAP append after a sudden process or system crash. On non-POSIX systems, file permissions are governed by platform ACLs; the implementation does not rewrite Windows ACLs.
