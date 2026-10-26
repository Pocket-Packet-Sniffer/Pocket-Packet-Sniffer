# Pocket Packet Sniffer

Pocket Packet Sniffer is a Software Engineering project for authorized, passive network traffic monitoring. It captures packets from supported interfaces, extracts metadata, stores captures, and presents traffic statistics and query/report functions.

## Architecture

The design follows the four-layer architecture defined by the SRS and SASD:

1. **Capture** — captures raw packets through a common Capturer interface.
2. **Analysis** — parses packets, extracts required metadata, and runs protocol analyzers.
3. **Storage** — persists PCAP data and indexed metadata through a Repository interface.
4. **Presentation** — provides the primary CLI for capture control, live statistics, queries, and reports.

WiFi, Ethernet, and BLE remain represented in the requirements. Backend availability depends on hardware, drivers, operating system, and permissions. BLE, suspicious-activity detection, concurrent multi-backend capture, Zeek integration, and the web dashboard are stretch/optional work until implemented and validated.

## Requirements and project documents

The approved project documents currently live under Docs:
- Project proposal
- Software Requirements Specification (SRS) v1.3
- Software Test Plan (STP) v1.3
- Software Architecture and Design Specification (SASD)

The SRS is the source of functional and non-functional requirements. The STP defines the verification approach and test mapping. The SASD explains the design and component boundaries. Implementation decisions should be traceable to these documents.

## Engineering workflow

- Use one branch per issue: feat/PPS-number-short-name, fix/PPS-number-short-name, or docs/PPS-number-short-name.
- Create an issue before starting work and include acceptance criteria and SRS/STP traceability.
- Open a pull request into main; link the issue using Closes #number.
- A different team member should review changes. Do not merge failing checks or unreviewed work.
- Update tests, docs, and the Requirement Traceability Matrix where appropriate.
- Do not mark work Done until acceptance criteria pass and evidence is recorded.

See CONTRIBUTING.md for the detailed working agreement.

## Development setup and tests

Use Python 3.10 or newer. From the repository root:

```bash
python -m pip install -r requirements-dev.txt -r requirements-capture.txt
PYTHONPATH=src pytest -q
ruff check --select E4,E7,E9,F,I src tests
```

The tests use generated PCAP fixtures and mocked capture backends; they do not require root privileges or live network traffic. The current repository contains Capture, Storage/Query, a statistics renderer, and CSV report export. The complete Analysis layer and full CLI/session integration are still in progress, so these commands verify the available modules rather than an end-to-end product demo.

## Planning and traceability

- [Requirement Traceability Matrix](Docs/REQUIREMENT_TRACEABILITY.md) — SRS-to-issue and STP-to-test mapping with verification status.
- [Sprint Plan](Docs/SPRINT_PLAN.md) — proposed Sprint 1/Sprint 2 scope and review records.
- [GitHub Operating Guide](Docs/GITHUB_OPERATING_GUIDE.md) — repository workflow, milestones, labels, reviews and security settings.

## Team engineering resources

- [GitHub operating guide](Docs/GITHUB_OPERATING_GUIDE.md) — issue labels, milestones, branching, reviews, merge rules, releases, and repository settings.
- [Project process](Docs/PROJECT_PROCESS.md) — requirements authority, layer responsibilities, prioritization, and quality gates.
- [Architecture Decision Record template](Docs/adr/0000-template.md) — record important design choices and their trade-offs.
- [Contributing guide](CONTRIBUTING.md) — the expected issue-to-PR workflow.
- [Security and safe use](SECURITY.md) — passive-only scope and sensitive capture-data handling.
- [Security validation record](Docs/SECURITY_VALIDATION.md) — automated permission checks and remaining manual platform verification.
- [Capture Layer guide](Docs/CAPTURE_LAYER.md) — capture backends, typed failures, setup and limitations.

## Storage and query layer (PPS-04/PPS-05)

The Storage/Query package provides the boundary between packet analysis and presentation:

- `PacketRecord` carries a session ID, record ID, timezone-aware timestamp, normalized protocol, source/destination addresses, captured bytes, PCAP link type, and original packet length.
- `Repository` defines `save(record)`, `query(protocol, address, time_window)`, and `get_session_summary(session_id)`.
- `PcapSqliteRepository` stores packet bytes in classic PCAP 2.4 files and searchable metadata in a local SQLite database (`metadata.sqlite3`). SQLite stores packet offsets and metadata, not packet payloads. Each capture session uses one link type.

Example:

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
packets = repository.query(protocol="TCP", address="192.0.2.10")
summary = repository.get_session_summary("capture-001")
```

Query filters combine with AND semantics. Protocol matching is case-insensitive; an address matches the exact source or destination; the optional `(start, end)` time window uses inclusive, timezone-aware datetime bounds. Either time bound may be `None`. No matches return an empty list.

Invalid records and filters raise `InvalidRecordError`; duplicate IDs raise `DuplicateRecordError`; missing files raise `StorageUnavailableError`; permission failures raise `StorageAccessError`; corrupt PCAP or indexed data raises `StorageCorruptionError`. Other persistence failures use `RepositoryError`.

Install this package and its test extra from the repository root with `python -m pip install -e ".[test]"`. Run the storage/query tests with `pytest tests/test_storage_query.py`. The tests use generated packet bytes and temporary storage.

The implementation is limited to persistence and querying; packet capture, parsing, and CLI behavior belong to their respective layers. Limitations include classic PCAP only, one link type per session, no encryption or retention policy, and no crash recovery for an unindexed trailing PCAP record. Captures remain local; use authorized traffic and protect the storage directory.

## Safe use

Only capture traffic on networks/devices you own or are explicitly authorized to monitor. This tool is intended to be passive: it must not inject, alter, or replay network traffic. Capture files may contain sensitive information; keep them local and protect them with suitable file permissions. The CLI must not silently upload captured data.

## Current implementation status

Do not infer implementation status from the design documents alone. Requirements and stretch goals should only be marked complete after the relevant code is merged and tests or demonstration evidence support the claim.