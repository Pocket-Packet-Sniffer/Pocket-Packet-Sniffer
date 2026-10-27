# SRS v1.3 implementation-gap audit

**Basis:** the approved `Pocket_Packet_Sniffer_SRS.pdf` (Version 1.3), Sections 1-6, checked against repository source and tests. This is a code-level audit, not a claim that untested hardware works. The SRS backend-completion changes were merged into `main` by PR #29 at commit `cd80e958bf572c32126c3f222579aec638da04b7`. Latest main CI run [40479490511](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40479490511) passed Ruff and **106 tests in 1.87 seconds**. Live-source and platform-specific claims remain subject to the manual checks described below.

## Functional requirements

| SRS requirement | Code evidence / coverage | Status and limits |
|---|---|---|
| REQ-1: capture raw packets from a selected Wi-Fi monitor-mode, Ethernet, or BLE-advertisement source | `capture/pcap_file.py`, `capture/scapy_live.py`, `capture/concurrent.py`; `analysis/parser.py` recognizes Ethernet/IP, ARP, 802.11 beacon metadata where link type 105 is delivered, and BLE advertisement metadata for link types 251/256. | **Partial pending target validation.** Classic-PCAP replay is deterministic; generic Scapy capture is available for selected interfaces. This does not prove a Wi-Fi adapter is in monitor mode or that a specific Bluetooth adapter/HCI path emits the supported BLE link type. Validate on the approved target device/driver. |
| REQ-2: actionable unavailable-interface / permission errors | Typed Capture errors, Scapy startup validation and CLI/session error handling; existing capture/error tests. | **Code path implemented; platform smoke tests pending.** Exact live-driver diagnostics remain environment-specific. |
| REQ-3: source/destination address, protocol, size and timestamp | `analysis/parser.py` and `analysis/models.py`; metadata for IPv4/IPv6 TCP, UDP, DNS, ICMP/ICMPv6, ARP, Ethernet OTHER frames, 802.11 frames/beacons and BLE advertisements when their link types are decoded. | **Implemented for supported decoders; partial for unsupported/malformed input.** Parser intentionally declines packets whose link-layer decoder is unavailable or whose bytes are malformed. |
| REQ-4: add analyzers without changing existing analyzers | `analysis/pipeline.py` provides the ordered `PacketAnalyzer` contract; existing pipeline/fallback tests. | **Implemented.** Keep layer-boundary tests in CI. |
| REQ-5: persist PCAP and indexed metadata | `storage/pcap_sqlite_repository.py` writes local PCAP + SQLite metadata. PR #29 merged per-session/per-link-type PCAP mapping and schema migration into main, allowing a concurrent logical session to contain more than one link type. | **Implemented on main; migration and mixed-link-type tests passed CI.** Each classic PCAP file still has exactly one link type; SQLite maps files to the logical session. |
| REQ-6: query by protocol, address, and time | Repository query filters and CLI `query`; new `query_session` method supports session-scoped report retrieval. | **Implemented** subject to regression tests. |
| REQ-7: live packet rate, protocol distribution, top five talkers, refresh no slower than two seconds | `analysis/statistics.py`, `presentation/dashboard.py`, `CaptureSession`, CLI `--live-dashboard`; refresh interval is 2 seconds. | **Implemented for sessions that are actively delivering supported packets.** No traffic means the rate can be zero; generated fixtures prove aggregation, not target-hardware throughput. |
| REQ-8: export session summary as CSV or PDF | `presentation/report_export.py` (CSV), `presentation/report_pdf.py` (standard-library PDF); CLI `export --format csv|pdf`; session-scoped storage retrieval. | **Implemented on main.** Exports contain summary and packet metadata, never packet payload bytes; both refuse to overwrite a destination. PDF generation and CLI behavior passed CI. |
| REQ-9 (stretch): ARP spoofing, rogue AP, and unfamiliar device events via Observer | New `analysis/alerts.py` publishes metadata-only `AlertEvent` objects to subscribers. Rules flag ARP address-to-MAC conflicts; unknown source MACs when a device allowlist is supplied; and observed Wi-Fi beacons outside an AP allowlist. CLI subscribes and prints alert summaries. | **Implemented on main as conservative heuristics.** Inventory-based rules need operator-supplied allowlists; AP detection requires decoded Wi-Fi beacon packets. A match is a review signal, not proof of an attack. An unfamiliar-device rule cannot identify devices absent from observed traffic. CI passed; target-hardware validation remains required. |
| REQ-10 (stretch): run multiple capture backends concurrently without capture-source-specific changes to downstream layers | New `capture/concurrent.py` fans multiple `Capturer` instances into one callback with shared stop/count semantics; CLI `capture-multi`; stored records retain interface/backend; storage maps different link types to separate PCAP files within one session. | **Implemented on main.** Automated tests cover aggregation, cancellation/error propagation and mixed link types; actual two-interface capture must be validated on available target hardware. |
| Optional Zeek integration | No live Zeek adapter/log importer exists in the current code. | **Not implemented.** SRS calls Zeek optional/stretch. Do not claim integration. |
| Web dashboard | No browser UI/local HTTP API yet. | **Deferred deliberately** until backend/demo readiness is accepted; it is described as a stretch/optional addition in SRS Section 3.1. |

## Non-functional requirements (SRS Section 6)

| SRS requirement | Current evidence | Status / limit |
|---|---|---|
| Raspberry Pi-class capture/parsing without drops; refresh within 2 seconds | Statistics window and CLI refresh are 2 seconds. New `tools/benchmark_pipeline.py` measures synthetic replay → analysis → PCAP/SQLite throughput on the machine where it runs. | Refresh behavior is implemented; the benchmark is automated/tested. **No Raspberry Pi benchmark or live NIC/kernel-drop measurement has been recorded**, so the hardware performance/no-drop claim remains unverified. Run on the actual target and record board, OS, Python, adapter/driver, duration, offered rate, received/stored counts and drop counters where available. |
| Passive-only: never inject, alter or replay packets onto the monitored network | Scapy backend listens; PCAP replay reads a local file; no send/injection API is part of the CLI workflow. Concurrent capture composes these same strategies. | Code/design review supports passive-only behavior. Recheck changes during review; do not confuse local PCAP replay with network transmission. |
| Authorized capture only | CLI documentation/usage warning and operator-selected interface. | Operator responsibility; software cannot determine authorization. Use only networks/devices owned or explicitly authorized. |
| Saved captures have private permissions | Repository sets POSIX capture directory to 0700 and PCAP/SQLite files to 0600; existing automated permission checks. | POSIX modes are covered by tests. **Windows ACLs are not verified.** |
| No data leaves the device unless explicitly exported | Current CLI reads/writes local capture, SQLite, CSV/PDF files; no upload/network-service command. | Current CLI is local-only. The later web UI must bind locally and make no external calls. |
| Modular layers, extensible strategies, maintainability | Capture, Analysis, Storage and Presentation modules; analyzer/capturer contracts; architecture tests; setup/interface documentation. | Existing automated architecture tests support the design claim; keep them enabled. |
| Usability and graceful errors | CLI subcommands, typed errors, usage text and actionable capture failures. | Automated code paths covered; actual live-device permission messages remain platform-dependent. |
| Operating environment / BLE hardware | Python 3.10+, Scapy/libpcap-dependent live path; BLE/802.11 metadata decode is conditional on provided link type. | **Not verified on Raspberry Pi, ESP32-class hardware, BLE dongle, or Wi-Fi monitor-mode adapter in this environment.** Do not claim tested support until a real hardware smoke test is recorded. |

## Reproducible synthetic demo

Install the project and test dependencies, then use generated traffic only:

```bash
python -m pip install -e .
python -m pip install -r requirements-dev.txt -r requirements-capture.txt
python tools/create_demo_pcap.py demo.pcap
pocket-packet-sniffer capture --pcap-file demo.pcap --storage-dir demo-captures --session-id demo-session
pocket-packet-sniffer query --storage-dir demo-captures --protocol TCP
pocket-packet-sniffer query --storage-dir demo-captures --address 192.0.2.1
pocket-packet-sniffer export --storage-dir demo-captures --session-id demo-session --output demo-session.csv --format csv
pocket-packet-sniffer export --storage-dir demo-captures --session-id demo-session --output demo-session.pdf --format pdf
```

The fixture is synthetic and contains TCP, DNS/UDP, ICMP and two conflicting ARP claims to exercise the heuristic alert. Replay reads the PCAP and does not transmit any packet. Output reports are local; the generated capture and metadata may contain sensitive information in real use.

To exercise concurrent fan-in without live interfaces, generate two separate PCAP files and run:

```bash
python tools/create_demo_pcap.py demo-a.pcap
python tools/create_demo_pcap.py demo-b.pcap
pocket-packet-sniffer capture-multi --pcap-file demo-a.pcap --pcap-file demo-b.pcap --storage-dir demo-multi-captures --session-id multi-demo --count 6
```

## Verification gate

The requirement-to-test execution record is published at [Docs/TEST_EXECUTION_REPORT.md](TEST_EXECUTION_REPORT.md). It separates automated CI results from not-yet-executed live-interface, Wi-Fi/BLE hardware, Windows ACL, and Raspberry Pi packet-loss checks.

- [x] CI Ruff check passes on latest main — [run 40479490511](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40479490511), all selected checks passed.
- [x] Full pytest suite passes — latest main CI [40479490511](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40479490511) reports **106 passed in 1.87s**, including the concurrent-capture Ctrl+C cleanup regression test.
- [ ] A teammate reviews and approves the implementation PR before merge.
- [ ] Perform and record authorized live-interface startup/stop tests on the intended OS/driver.
- [ ] Record Raspberry Pi throughput/drop-rate measurements if Raspberry Pi remains a performance target.
- [ ] Record Wi-Fi monitor-mode and BLE adapter/HCI tests before claiming those live paths work.
- [ ] Verify Windows ACLs if Windows is a target.
