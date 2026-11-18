# Pocket Packet Sniffer

Pocket Packet Sniffer is a Software Engineering project for authorized, passive network traffic monitoring. It captures packets from supported interfaces, extracts metadata, stores captures, and presents traffic statistics and query/report functions.

**Current stable version: 1.0.0.** This marks the first stable release of the documented local capture and analysis workflow. See the [1.0.0 release notes](Docs/RELEASE_NOTES.md) for capabilities, setup, verification, and hardware limitations.

## Architecture

The design follows the four-layer architecture defined by the SRS and SASD:

1. **Capture** — captures raw packets through a common Capturer interface.
2. **Analysis** — parses packets, extracts required metadata, and runs protocol analyzers.
3. **Storage** — persists PCAP data and indexed metadata through a Repository interface.
4. **Presentation** — provides the CLI and web dashboard for capture control, live statistics, queries, and reports. The dashboard communicates with a local sensor; Vercel hosts the interface, not the capture API or packet data.

Ordinary Wi-Fi and Ethernet capture use interfaces exposed by the operating system and capture driver. Live Wi-Fi monitor mode is adapter/driver-dependent; live BLE scanning is not included in the current Windows sensor. The parser can read supported BLE metadata from selected PCAP link types, which is file replay rather than radio scanning. The dashboard uses a near-black visual system with signal-green/cyan accents and displays data returned by the local capture agent. Capture and replay are explicit operator actions; metadata-only heuristic alerts are review signals, not attack verdicts.

## Requirements and project documents

The approved project documents currently live under Docs:
- Project proposal
- Software Requirements Specification (SRS) v1.3
- Software Test Plan (STP) v1.3
- Software Architecture and Design Specification (SASD)

The SRS is the source of functional and non-functional requirements. The STP defines the verification approach and test mapping. The SASD explains the design and component boundaries. Implementation decisions should be traceable to these documents.

The six requested GitHub submission reports are collected in the [Submission Reports index](Submission_Reports/README.md): SRS, STP, SASD, unit-test report, system-test report, and combined code/branch-coverage report.

## Engineering workflow

- Use one branch per issue: feat/PPS-number-short-name, fix/PPS-number-short-name, or docs/PPS-number-short-name.
- Create an issue before starting work and include acceptance criteria and SRS/STP traceability.
- Open a pull request into main; link the issue using Closes #number.
- A different team member should review changes. Do not merge failing checks or unreviewed work.
- Update tests, docs, and the Requirement Traceability Matrix where appropriate.
- Do not mark work Done until acceptance criteria pass and evidence is recorded.

See CONTRIBUTING.md for the detailed working agreement.

## Development setup and tests

Run `ruff check .` to verify Python code quality and `pytest --cov=pocket_packet_sniffer --cov-report=term-missing` to inspect test coverage.

Use Python 3.10 or newer. From the repository root:

```bash
python -m pip install -e .
python -m pip install -r requirements-dev.txt
ruff check --select E4,E7,E9,F,I src tests tools
python -m pytest -q
python -m pytest -q --cov=pocket_packet_sniffer --cov-branch --cov-report=term-missing
```

Automated tests use generated fixtures and mocked capture sources; they do not put synthetic traffic into the live product or require administrator privileges. The current Windows acceptance run and all outstanding hardware limits are recorded in the [SRS acceptance report](tests/docs/ACCEPTANCE_TEST_REPORT.md). For a real-traffic presentation, use the [demo guide](Docs/DEMO_SCRIPT.md).

## Planning and traceability

- [Requirement Traceability Matrix](Docs/REQUIREMENT_TRACEABILITY.md) — SRS-to-issue and STP-to-test mapping with verification status.
- [Implementation Gap Audit](Docs/IMPLEMENTATION_GAP_AUDIT.md) — direct SRS v1.3-to-code comparison, branch status, and outstanding hardware checks.
- [Sprint Plan and closeout](Docs/SPRINT_PLAN.md) — completed sprint records and the remaining evidence-based follow-up.
- [Sprint 1 review/retrospective](Docs/SPRINT_1_REVIEW_RETROSPECTIVE.md) — verified deliveries, asynchronous evidence review, limitations, and process improvements.
- [GitHub Operating Guide](Docs/GITHUB_OPERATING_GUIDE.md) — repository workflow, milestones, labels, reviews and security settings.
- [Course alignment](Docs/COURSE_ALIGNMENT.md) — maps Unit 3 network topics and Unit 4 software-quality/testing topics to project evidence.
- [Privacy guidelines](Docs/PRIVACY_GUIDELINES.md) — authorized use, local capture handling, and sharing precautions.
- [SRS acceptance report](tests/docs/ACCEPTANCE_TEST_REPORT.md) — current real-interface result, automated verification, and remaining acceptance gates.
- [Six-report submission index](Submission_Reports/README.md) — direct GitHub links to each required report.

## Team engineering resources

- [GitHub operating guide](Docs/GITHUB_OPERATING_GUIDE.md) — issue labels, milestones, branching, reviews, merge rules, releases, and repository settings.
- [Project process](Docs/PROJECT_PROCESS.md) — requirements authority, layer responsibilities, prioritization, and quality gates.
- [Architecture Decision Record template](Docs/adr/0000-template.md) — record important design choices and their trade-offs.
- [ADR 0001 — Analysis/Storage record adapter](Docs/adr/0001-analysis-storage-record-adapter.md) — explicit application-boundary mapping that preserves layer dependency direction.
- [Contributing guide](CONTRIBUTING.md) — the expected issue-to-PR workflow.
- [Security and safe use](SECURITY.md) — passive-only scope and sensitive capture-data handling.
- [Security validation record](Docs/SECURITY_VALIDATION.md) — automated permission checks and remaining manual platform verification.
- [Capture Layer guide](Docs/CAPTURE_LAYER.md) — capture backends, typed failures, setup and limitations.
- [End-to-end guide](Docs/END_TO_END_GUIDE.md) — CLI install/usage, layer contracts, tests and manual checks.
- [Live-traffic presentation guide](Docs/DEMO_SCRIPT.md) — real authorized capture, dashboard walkthrough, and local report export.
- [Test documentation and execution reports](tests/README.md) — test plan, categorized test reports, coverage evidence, requirement mapping, and pending hardware checks.
- [Replay throughput benchmark](tools/benchmark_pipeline.py) — measures synthetic replay, analysis, and local storage throughput; it is not a live packet-loss test.

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

For dashboard-specific guidance on local storage, replay files, reports, and visibility limits, see [Privacy and responsible-use guidelines](Docs/PRIVACY_GUIDELINES.md).

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
pocket-packet-sniffer query --storage-dir captures --session-id live-session --suspicious-only
pocket-packet-sniffer query --storage-dir captures --session-id live-session --show-classification
pocket-packet-sniffer export --storage-dir captures --session-id demo-session --output demo-session.csv --format csv
pocket-packet-sniffer export --storage-dir captures --session-id demo-session --output demo-session.pdf --format pdf
```

The query command accepts optional timezone-aware `--start` and `--end` ISO-8601 datetimes. `--suspicious-only` re-parses the saved records and shows only packets that trigger a configured heuristic, including the rule and reason; `--show-classification` labels all queried records `SUSPICIOUS/REVIEW` or `NO RULE MATCHED`. Optional query-time `--known-device MAC` and `--known-access-point BSSID` arguments enable inventory-based rules. A no-match does not mean traffic is safe, and these heuristics are not a guaranteed malware detector. CSV and PDF exports refuse to overwrite an existing file and include session/packet metadata, not raw packet payloads. Capture outputs and the SQLite index remain local under the configured storage directory. The PCAP files contain original captured bytes; metadata-only query and report output does not redact or remove payloads from those files.

## Generated PCAP fixture for automated testing only

This generated fixture is for regression/CI checks only. It is not a product demo and must never be presented as live traffic. For the presentation, use the [live-traffic guide](Docs/DEMO_SCRIPT.md).

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

The Capture → Analysis → Storage → Presentation workflow, local sensor, dashboard, and CI/CD are implemented. Current `main` is commit `0839abf9d102d0b4c1da4f0f58a205ef6d9a4525`; GitHub Actions [run 44364160089](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) passed. On 2026-11-18, the local Windows acceptance run captured **175 real packets**, stored all 175, and exported CSV and PDF reports. Python checks reported 171 passed / 2 skipped; the dashboard type-check, production build, and all 13 browser tests passed. Full results are in the [acceptance report](tests/docs/ACCEPTANCE_TEST_REPORT.md) and [submission index](Submission_Reports/README.md).

Live Wi-Fi monitor mode, live BLE scanning, simultaneous physical adapters, Windows ACL behavior, and Raspberry Pi throughput/drop rates are not validated. The current Windows sensor does not include live BLE scanning. The production dashboard is deployed and returned HTTP 200; packet capture and storage remain local. Branch-protection and GitHub security settings remain subject to admin-level verification.

## Third-party acknowledgements

- **[Scapy](https://scapy.readthedocs.io/)** provides the project's live-capture integration and supported packet/link-layer decoding.
- **[pytest](https://docs.pytest.org/)** runs the automated unit and integration tests.
- **[Ruff](https://docs.astral.sh/ruff/)** checks Python source, tests, and demo tooling for the configured lint rules.
- The PDF report writer in this implementation uses the Python standard library. Zeek is mentioned as an optional integration in project materials but is not implemented or claimed as an integrated feature.

Please retain third-party acknowledgements in project submissions and follow each dependency's distribution/licensing terms.
## Local dashboard + API

The Next.js dashboard reads real stored packet metadata from the local FastAPI API and can explicitly start or stop a local capture/replay session. It contains no synthetic user-facing data. Vercel hosts the interface only; the capture API and packet storage stay on the operator's computer. See [dashboard deployment](Docs/WEB_DEPLOYMENT.md) for the local-sensor connection boundary and CI/CD setup.

### Start on Windows (PowerShell)

Terminal 1, from the repository root:

```powershell
python -m pip install -e .
python -m uvicorn pocket_packet_sniffer.api:app --reload --host 127.0.0.1 --port 8000
```

Terminal 2:

```powershell
cd web
npm ci
npm run dev
```

Open the dashboard at http://127.0.0.1:5173. The API health endpoint is http://127.0.0.1:8000/api/health.

Optional: set `PPS_STORAGE_DIR` to choose the local PCAP/SQLite storage directory. The default is `captures` in the current working directory.


### Start and stop capture from the dashboard

The dashboard's **Capture session** panel can start passive live capture or replay a local classic PCAP file. It uses the same Capture → Analysis → Storage pipeline as the CLI. Capture writes packet metadata to SQLite and packet bytes to per-session PCAP files under the configured storage directory.

- **Live interface:** enter the exact interface name reported by Scapy (it may not be the friendly label “Wi-Fi”). On Windows, install a supported Npcap driver and run the terminal with the privileges required by your adapter/driver.
- **PCAP replay:** enter a path to a local classic `.pcap` file accessible to the Python process. PCAPNG is not supported by the current replay reader.
- Use **Stop capture** to request a graceful stop. Status and packet counters refresh automatically.
- Only capture traffic on networks and interfaces you own or are authorized to monitor. Capture remains local; this API is intended for localhost development and is not authenticated for exposure to other machines.

Capture API endpoints: `POST /api/capture/start`, `POST /api/capture/stop`, and `GET /api/capture/status`.
