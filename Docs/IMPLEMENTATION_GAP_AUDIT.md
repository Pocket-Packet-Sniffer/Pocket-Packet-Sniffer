# SRS v1.3 Implementation Gap Audit

**Audit scope:** source-grounded review of the approved SRS v1.3 stored in Docs/Pocket_Packet_Sniffer_SRS .pdf, current repository implementation on the feature branch, and associated tests.

**Evidence caveat:** new code and tests in this branch must pass CI before being described as verified. This audit does not substitute automated PCAP tests for live-hardware or operating-system validation.

## Functional requirement comparison

| Requirement | SRS intent | Code and test evidence | Status / limitation |
|---|---|---|---|
| REQ-1 | Capture selected-interface raw packets for Wi-Fi monitor mode, Ethernet, or BLE advertisements. | Capture/Capturer, ScapyCapturer and PcapFileCapturer provide passive live interface capture and local classic-PCAP replay. CapturedPacket retains timestamp, interface, link type, bytes and original length. | **Partial.** Ethernet and supported Scapy interfaces are implemented. Wi-Fi monitor mode depends on adapter/driver and needs target-device testing. BLE HCI advertisement scanning is not implemented; do not claim REQ-1 fully satisfied. |
| REQ-2 | Clearly report missing interfaces and insufficient permissions. | Typed Capture errors, capture_runner, CLI exit handling and capture-layer tests. | Implemented for known Scapy/PCAP failure paths; manual target-OS permission checks remain. |
| REQ-3 | Extract timestamp, source/destination, protocol and packet size. Appendix B additionally makes interface mandatory. | PacketParser handles tested IP/TCP/UDP/DNS/ARP paths and this branch adds Wi-Fi beacon metadata. Storage PacketRecord and SQLite migration preserve interface. | Implemented for supported parser/link types. Unsupported or malformed frames are intentionally ignored; BLE is not parsed. |
| REQ-4 | Add analyzers without modifying existing analyzers. | AnalyzerPipeline and PacketAnalyzer interfaces with fallback/custom analyzer tests. | Implemented. |
| REQ-5 | Persist PCAP and/or indexed metadata. | PcapSqliteRepository stores classic PCAP bytes and indexed SQLite metadata. Each stored session uses one link type per PCAP. | Implemented. Existing SQLite databases are migrated to preserve a new interface column. |
| REQ-6 | Filter by protocol, address or time window. | Repository.query; CLI query validates timezone-aware endpoints. This branch adds session_id filtering and the sessions command. | Implemented, subject to tests passing in CI. |
| REQ-7 | Show packet rate, protocol breakdown and top five talkers with refresh no slower than two seconds. | TrafficStatistics and presentation dashboard renderer; CLI --live-dashboard refresh interval is 2 seconds. | Implemented for supported/observed packets. Raspberry Pi throughput is not yet measured. |
| REQ-8 | Export a session summary as CSV **or** PDF. | The current CSV exporter includes session summary and per-packet metadata; this branch adds the required capture interface field and uses session-scoped repository queries. Tests cover contents and no-overwrite behavior. | CSV satisfies the literal SRS requirement, which says CSV or PDF. PDF generation is not required by the current SRS wording and is not implemented. |
| REQ-9 (Stretch) | Publish alerts for ARP spoofing, rogue APs and unrecognized devices through an Observer event. | This branch adds AlertBus, AlertEvent and SuspiciousActivityDetector. Rules cover ARP IP-to-MAC changes, source MACs missing from an explicit trusted-device allowlist, and Wi-Fi beacon BSSIDs missing from a trusted-AP list. | Implemented as **heuristics**, pending CI. Rules require suitable observed metadata/configuration and are not proof of an attack. Rogue-AP rules require compatible Wi-Fi beacon metadata. |
| REQ-10 (Stretch) | Run multiple backends concurrently with combined statistics and without forcing layer-specific changes. | This branch adds MultiCaptureSession. Each backend has an independent storage session/PCAP (required because classic PCAP stores one link type per file) while stats and alert observers are shared. CLI supports --multi-interface and --multi-pcap-file. Synthetic integration tests are added. | Implemented in code, pending CI. Real simultaneous live-interface behavior is still platform-dependent. BLE backend support remains absent. |

## Non-functional requirements

| Requirement | Evidence | Status / remaining validation |
|---|---|---|
| Performance on Raspberry Pi-class hardware | Existing CI uses generated PCAPs and mocks, not a target board. | **Not verified.** Run the documented capture fixture/live smoke test on the actual target and record rate, duration, CPU/memory, and any drops. Do not infer performance from unit tests. |
| Refresh within two seconds | Presentation dashboard restricts refresh_interval to at most 2.0 seconds; CLI uses 2.0. | Implemented in code; verify visually during a real demo. |
| Passive-only safety | Live Scapy capture listens; PCAP replay reads a local file and never writes traffic to the network. No upload or packet-injection feature is introduced. | Code-level constraint; keep regressions covered by security tests. |
| Local data protection | PcapSqliteRepository creates private POSIX storage/files and this branch persists interface metadata. | POSIX mode-bit behavior has automated coverage. Windows ACL behavior remains manual. Captures are not encrypted and need user-controlled retention/handling. |
| Modularity and extensibility | Capture strategy interface, PacketAnalyzer/AnalyzerPipeline, Repository boundary and architecture-boundary tests. | Implemented at the code boundary; verify changes maintain direction of dependencies. |
| Reliability and usability | Typed failure paths, CLI commands, query validation, CSV no-overwrite behavior, and tests. | New features pending CI; live driver/permission failures require environment checks. |
| BLE and Wi-Fi hardware support | SRS assumes compatible hardware, and the risk appendix explicitly calls BLE/ESP32 a stretch goal. | BLE advertisement scanning remains missing. Wi-Fi monitor-mode and target-interface claims must remain conditional until tested on actual hardware. |

## Changes made on the feature branch

- Store the capture interface alongside packet metadata, including a safe SQLite migration for existing databases.
- Add a session-scoped query filter, public session listing, and CLI sessions command.
- Add Wi-Fi beacon BSSID/SSID parsing when the PCAP link type supplies Radiotap/802.11 frames.
- Add an Observer event bus and explicitly scoped suspicious-activity heuristics.
- Add concurrent capture-session orchestration with per-backend PCAP storage and shared statistics.
- Add concurrent local PCAP replay so the multi-backend flow can be demonstrated safely without live network capture.
- Add a generator for synthetic Ethernet/ARP/TCP/DNS and Wi-Fi-beacon demo PCAPs.
- Add tests for the new event rules, interface metadata migration, multi-session behavior, Wi-Fi beacon parsing and end-to-end synthetic demo.

## Reproducible demo

Install the existing package and development dependencies, then run:

~~~bash
python tools/create_demo_pcaps.py --output-dir demo-data
pocket-packet-sniffer capture --multi-pcap-file demo-data/ethernet-demo.pcap demo-data/wifi-beacon-demo.pcap --storage-dir demo-captures --session-id demo-run --alerts --trusted-device 02:00:00:00:00:01 --trusted-ap 02:00:00:00:00:01 --replay-delay 0.25 --live-dashboard
pocket-packet-sniffer sessions --storage-dir demo-captures
pocket-packet-sniffer query --storage-dir demo-captures --protocol ARP --address 192.0.2.10
~~~

The fixture generator creates files only and does not transmit packets. The Ethernet fixture deliberately reuses an ARP sender IP with a different MAC address; the Wi-Fi fixture includes a beacon whose BSSID is not in the configured trusted-AP list. The multi-capture command prints per-backend session IDs; use those IDs for CSV exports. The current CLI CSV exporter refuses to overwrite an existing report.

## Release gate and honest gaps

1. Run CI for this branch and fix any lint/test failures before merge.
2. Confirm all current SRS claims against the passing tests and update this matrix with actual CI evidence.
3. Run authorized live-interface smoke tests on the intended OS/driver and record results.
4. Measure performance on the target Raspberry Pi-class device if that remains a project claim.
5. Do not claim BLE advertisement scanning, Wi-Fi monitor-mode operation on untested adapters, or Windows ACL behavior until implemented/validated.
6. Main branch protection and repository security settings are GitHub-admin tasks, not application functionality.
