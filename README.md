# Pocket Packet Sniffer

Pocket Packet Sniffer is a Software Engineering project for authorized, passive network traffic monitoring. It captures packets from supported interfaces, extracts metadata, stores captures, and presents traffic statistics and query/report functions.

## Architecture

The design follows the four-layer architecture defined by the SRS and SASD:

1. **Capture** — captures raw packets through a common Capturer interface.
2. **Analysis** — parses packets, extracts required metadata, and runs protocol analyzers.
3. **Storage** — persists PCAP data and indexed metadata through a Repository interface.
4. **Presentation** — provides the primary CLI for capture control, live statistics, queries, and reports.

WiFi, Ethernet, and BLE are represented by the requirements. The review branch adds metadata decoding for supported Ethernet/IP, ARP, 802.11 beacon/frame, and BLE advertisement link types; passive live Wi-Fi monitor-mode and BLE-adapter behavior still require validation on actual hardware. The branch also adds heuristic suspicious-activity events and concurrent capture for multiple supported backends. Zeek integration and the web dashboard remain optional/deferred; the dashboard comes after backend verification.

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
python -m pip install -e .
python -m pip install -r requirements-dev.txt
ruff check --select E4,E7,E9,F,I src tests tools
pytest -q
```

The tests use generated PCAP fixtures and mocked capture backends; they do not require root privileges or live network traffic. The repository now includes the Capture, Analysis, Storage, and Presentation/application session path, plus CLI and generated-PCAP integration tests. The latest `main` CI run completed successfully with Ruff passing and 81 tests passing. Live-interface and target-platform behaviour still needs manual verification.

## Planning and traceability

- [Requirement Traceability Matrix](Docs/REQUIREMENT_TRACEABILITY.md) — SRS-to-issue and STP-to-test mapping with verification status.
- [Sprint Plan](Docs/SPRINT_PLAN.md) — proposed Sprint 1/Sprint 2 scope and review records.
- [Sprint 1 review/retrospective draft](Docs/SPRINT_1_REVIEW_RETROSPECTIVE.md) — verified deliveries and placeholders for actual team review outcomes.
- [GitHub Operating Guide](Docs/GITHUB_OPERATING_GUIDE.md) — repository workflow, milestones, labels, reviews and security settings.

## Team engineering resources

- [GitHub operating guide](Docs/GITHUB_OPERATING_GUIDE.md) — issue labels, milestones, branching, reviews, merge rules, releases, and repository settings.
- [Project process](Docs/PROJECT_PROCESS.md) — requirements authority, layer responsibilities, prioritization, and quality gates.
- [Architecture Decision Record template](Docs/adr/0000-template.md) — record important design choices and their trade-offs.
- [ADR 0001 — Analysis/Storage record adapter](Docs/adr/0001-analysis-storage-record-adapter.md) — explicit application-boundary mapping that preserves layer dependency direction.
- [Contributing guide](CONTRIBUTING.md) — the expected issue-to-PR workflow.
- [Security and safe use](SECURITY.md) — passive-only scope and sensitive capture-data handling.
- [Security validation record](Docs/SECURITY_VALIDATION.md) — automated permission checks and remaining manual platform verification.
- [Capture Layer guide](Docs/CAPTURE_LAYER.md) — capture backends, typed failures, setup and limitations.
- [End-to-end guide](Docs/END_TO_END_GUIDE.md) — CLI install/usage, layer contracts, safe demo, tests and manual checks.

## Storage and query layer (PPS-04/PPS-05)

The Storage/Query package provides the boundary between packet analysis and presentation:

- `PacketRecord` carries a session ID, record ID, timezone-aware timestamp, normalized protocol, source/destination addresses, captured bytes, PCAP link type, and original packet length.
- `Repository` defines `save(record)`, `query(protocol, address, time_window)`, and `get_session_summary(session_id)`.
- `PcapSqliteRepository` stores packet bytes in local classic PCAP 2.4 files and searchable metadata in SQLite (`metadata.sqlite3`). SQLite stores offsets and metadata, not packet payloads. A logical session may use separate PCAP files for different link-layer types; the index associates each packet with its file, interface, and backend.

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

The implementation is limited to persistence and querying; capture, analysis, and CLI behavior belong to their respective layers. Limitations include classic PCAP only, no encryption or retention policy, and no crash recovery for an unindexed trailing PCAP record. Captures remain local; use authorized traffic and protect the storage directory.

## Safe use

Only capture traffic on networks/devices you own or are explicitly authorized to monitor. This tool is intended to be passive: it must not inject, alter, or replay network traffic. Capture files may contain sensitive information; keep them local and protect them with suitable file permissions. The CLI must not silently upload captured data.

## CLI usage

Install the application and its CLI:

```bash
python -m pip install -e .
python -m pip install -r requirements-dev.txt
pocket-packet-sniffer --help
```

You can also run the CLI as a module with `python -m pocket_packet_sniffer`.

Replay a local classic PCAP into a new local capture session (this reads a file and does not transmit packets):

```bash
pocket-packet-sniffer capture --pcap-file sample.pcap --storage-dir captures --session-id demo-session
```

Passively capture an interface you are authorized to monitor and refresh the dashboard every two seconds:

```bash
pocket-packet-sniffer capture --interface eth0 --storage-dir captures --session-id live-session --live-dashboard
```

The capture process prints its session ID. From a second terminal in the same working directory, request a graceful stop with:

```bash
pocket-packet-sniffer stop --storage-dir captures --session-id live-session
```

Pressing Ctrl+C in the capture terminal also stops it. The explicit stop command writes a local session-specific control marker; it does not send network packets.

List saved sessions, then query one session's stored metadata and export reports:

```bash
pocket-packet-sniffer sessions --storage-dir captures
pocket-packet-sniffer query --storage-dir captures --session-id live-session --protocol TCP --address 192.0.2.10
pocket-packet-sniffer export --storage-dir captures --session-id demo-session --output demo-session.csv --format csv
pocket-packet-sniffer export --storage-dir captures --session-id demo-session --output demo-session.pdf --format pdf
```

Query stored metadata and export a CSV session report:

```bash
pocket-packet-sniffer query --storage-dir captures --protocol TCP --address 192.0.2.10
pocket-packet-sniffer export --storage-dir captures --session-id demo-session --output demo-session.csv --format csv
pocket-packet-sniffer export --storage-dir captures --session-id demo-session --output demo-session.pdf --format pdf
```

The query command accepts optional timezone-aware `--start` and `--end` ISO-8601 datetimes. CSV and PDF exports refuse to overwrite an existing file and include session/packet metadata, not raw packet payloads. Capture outputs and the SQLite index remain local under the configured storage directory.

## Reproducible synthetic demo

```bash
python -m pip install -r requirements-dev.txt -r requirements-capture.txt
python tools/create_demo_pcap.py demo.pcap
pocket-packet-sniffer capture --pcap-file demo.pcap --storage-dir demo-captures --session-id demo-session
pocket-packet-sniffer sessions --storage-dir demo-captures
pocket-packet-sniffer query --storage-dir demo-captures --session-id demo-session --protocol TCP
pocket-packet-sniffer export --storage-dir demo-captures --session-id demo-session --output demo-session.csv --format csv
pocket-packet-sniffer export --storage-dir demo-captures --session-id demo-session --output demo-session.pdf --format pdf
```

The synthetic fixture contains TCP, DNS/UDP, ICMP and two conflicting ARP claims to demonstrate metadata processing and a heuristic alert. It is local test data; replay reads the file and does not transmit packets. The generator refuses to overwrite an existing output file.

To exercise concurrent fan-in on two local PCAP sources (no live interface needed):

```bash
python tools/create_demo_pcap.py demo-a.pcap
python tools/create_demo_pcap.py demo-b.pcap
pocket-packet-sniffer capture-multi --pcap-file demo-a.pcap --pcap-file demo-b.pcap --storage-dir demo-multi-captures --session-id multi-demo --count 6
```

## Current implementation status

The integrated Capture → Analysis → Storage → Presentation/CLI workflow is merged into `main` (PR #24). The latest successful `main` CI run is [40357674966](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40357674966): Ruff passed and `pytest -q` reported 81 passed.

Known limitations remain: classic PCAP only; passive live capture depends on platform/driver/permissions; live Wi-Fi monitor-mode and BLE-adapter support are not hardware-verified; Raspberry Pi packet-loss/performance figures have not been measured; Windows ACL behavior remains unverified. The new SRS compliance work is on `feat/PPS-28-srs-compliance` pending CI and independent review, not yet a claim about the current `main` branch. Repository branch protection and plan-available security settings still require maintainer UI verification.