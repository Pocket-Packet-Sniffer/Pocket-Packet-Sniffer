# SRS acceptance test report

**Basis:** approved Pocket Packet Sniffer SRS v1.3, Software Test Plan v1.3, the requirement traceability matrix, and the course mapping in [COURSE_ALIGNMENT.md](../../Docs/COURSE_ALIGNMENT.md).

**Run date:** 2026-11-18. Automated results below were run on Windows 11, Python 3.13.1, Node 22, and Chromium. The live-capture check used the user's connected Wi-Fi adapter through the local sensor and Npcap. Capture files and the SQLite index were kept in an isolated local application-data folder; no capture files or packet addresses are included in this report.

**Current merged source:** `main` commit `0839abf9d102d0b4c1da4f0f58a205ef6d9a4525`; post-merge GitHub Actions [run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) completed successfully. The live capture evidence predates the merge and is dated above; CI run #731 verifies the merged software tree.

## Acceptance disposition

The core sniffer workflow is implemented and passed a real local Windows Wi-Fi capture, storage, query, and report-export check. **Full SRS acceptance is not complete:** live BLE scanning is not included in the Windows sensor, Wi-Fi monitor mode has not been verified on a monitor-capable adapter, and target-specific performance/security checks remain open. Do not present those capabilities as validated.

## Functional requirements

| SRS requirement | Result | Evidence and limits |
|---|---|---|
| REQ-1 — capture from a selected interface | **PARTIAL** | Real local Windows Wi-Fi capture passed: 175 packets seen, 175 stored, 0 ignored, exit code 0; capture stopped cleanly. Ethernet and Wi-Fi monitor mode were not separately tested. Live BLE scanning is not shipped in the current Windows sensor. Parser tests cover supported BLE PCAP link types; this is not live-radio evidence. |
| REQ-2 — explain unavailable-interface and permission failures | **PASS in automated paths** | Python capture/API tests exercise invalid or unavailable interfaces and startup errors. The actual acceptance capture demonstrates successful startup/stop; an actual denied-driver-permission scenario was not induced on this machine. |
| REQ-3 — extract address, protocol, size, and time | **PASS for supported packets** | Real saved records were queried and included protocol, source/destination, size, and timestamp metadata. Parser unit and edge-case suites cover supported TCP/UDP, IPv4/IPv6, ARP, DNS, ICMP, and supplied link types. Unsupported or malformed records can be ignored by design. |
| REQ-4 — extensible analyzer pipeline | **PASS** | Analyzer pipeline, fallback, and architecture-boundary tests pass. |
| REQ-5 — persist PCAP and searchable metadata | **PASS** | The live session was saved locally and returned 175 matching records from the session query. Storage round-trip, migration, and session integration tests pass. |
| REQ-6 — query by protocol, address, and time window | **PASS** | Storage/API query tests and dashboard filtering tests pass for the supported filters. |
| REQ-7 — live packet rate, protocol mix, top talkers | **PASS for this live run** | Five live statistics samples were received during capture (14, 32, 4, 7, and 30 packets/second); the session stored 175 actual packets. Other adapters and sustained/high-volume rates were not measured. |
| REQ-8 — export a session summary | **PASS** | CSV and PDF endpoints both returned HTTP 200 for the real local capture session. Exporter tests verify metadata-only reports and safe output behavior. |
| REQ-9 — suspicious-activity events (stretch) | **PASS in automated rule tests** | Match/non-match tests cover ARP conflicts and allowlist-based unknown-device/access-point indicators. No malicious traffic was generated for this acceptance run; alerts remain heuristic review signals, not proof of an attack. |
| REQ-10 — concurrent capture backends (stretch) | **PASS for automated fan-in; live hardware NOT RUN** | Concurrent fixture, cancellation/error, and mixed-link storage tests pass. Simultaneous physical adapters were not tested. |

## Non-functional and release checks

| Area | Result | Evidence and limits |
|---|---|---|
| Passive operation and authorized use | **PASS for reviewed workflow** | The actual run passively listened on the selected local adapter; no test packets were transmitted. Automated security-contract tests and source review check the passive-only boundary. Operators remain responsible for authorization. |
| Data locality and privacy | **PASS for local-agent flow** | The dashboard connects to loopback; real packet records, PCAP, SQLite, and reports stayed in the local sensor's storage. Browser tests cover unapproved-origin rejection, local replay, and privacy guidance. The selected PCAP replay flow stages a file only on the same computer's sensor. |
| File permissions | **PARTIAL** | POSIX mode tests are skipped on Windows. Windows ACLs were not inspected, so Windows file-access protection is not claimed as verified. |
| Modularity and maintainability | **PASS for automated checks** | Architecture-boundary tests and analyzer/capture contracts pass. |
| Dashboard usability and accessibility flows | **PASS for tested browser flows** | Production build and type-check passed; all 13 Chromium end-to-end tests passed, including mobile layout, privacy/capability guidance, capture controls, packet filtering/details, replay, and report downloads. Browser tests mock local-agent responses; the separate live API capture above verifies the real capture path. |
| Statement coverage | **79.46% (1,899 / 2,390)** | Measured by pytest-cov on Python source; this is a baseline, not a correctness guarantee or threshold. |
| Branch coverage | **68.29% (519 / 760)** | Measured by pytest-cov on Python source; this is a baseline, not a threshold. |
| Raspberry Pi throughput / zero packet loss | **NOT RUN** | No Raspberry Pi benchmark or NIC/kernel drop-counter measurement was collected. The short Wi-Fi acceptance capture does not establish a no-drop or throughput guarantee. |
| Wi-Fi monitor mode | **NOT RUN** | Requires a compatible adapter and driver in monitor mode. The dashboard does not change radio mode. |
| BLE live scanning | **NOT IMPLEMENTED in current Windows sensor** | BLE metadata decoding from supported PCAP link types is available; live BLE radio/HCI acquisition is not shipped or validated. |
| Production CI/CD | **CI configured; CD is Vercel Git integration** | GitHub Actions runs Python lint/tests on Linux and Windows, coverage, and dashboard build/browser tests. Vercel handles preview and production deployments separately; it does not host the local sensor or captures. Deployment/required-check settings must be verified from current GitHub/Vercel status before claiming merge protection. |
| Merged release status | **PASS** | PR #60 merged as `0839abf`; post-merge CI [run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) succeeded. Production returned HTTP 200 and served the updated dashboard/privacy text. Branch-protection enforcement remains unverified. |

## Commands and results

| Command | Result |
|---|---|
| `ruff check --select E4,E7,E9,F,I src tests tools` | PASS — all checks passed. |
| `python -m pytest -q --cov=pocket_packet_sniffer --cov-branch --cov-report=term-missing --cov-report=xml:coverage.xml` | PASS — 171 passed, 2 skipped. The skips are POSIX permission-mode checks and do not verify Windows ACLs. |
| `npm run typecheck` | PASS. |
| `npm run build` | PASS — optimized Next.js production build completed. |
| `npm run test:e2e -- --workers=1` | PASS — 13 passed. |
| Local real-interface capture, query, CSV, and PDF checks | PASS — 175/175 packets stored; 0 ignored; CSV/PDF each HTTP 200. |

The coverage run emitted non-fatal `ResourceWarning` messages from coverage.py's internal SQLite collector during shutdown; pytest exited successfully. This does not indicate packet-storage corruption. The warning is recorded rather than hidden.

## Remaining acceptance gates

### Supplemental automated coverage run — 2026-11-19

The local working tree added risk-focused tests and now reports **195 passed, 2 skipped, 0 failed**, **83.93% statement coverage** (2,006/2,390), and **74.61% branch coverage** (567/760). Ruff passed for `src`, `tests`, and `tools`. These results are local and have not yet been confirmed by GitHub CI. The skipped POSIX permission tests do not verify Windows ACLs. See the [detailed coverage report](CODE_AND_BRANCH_COVERAGE_REPORT.md).

- Validate Wi-Fi monitor mode only with the intended compatible adapter/driver.
- Add or explicitly exclude live BLE capture from the accepted product scope; current Windows agent does not scan BLE radios.
- Verify Windows ACLs if Windows is a supported target.
- Measure Raspberry Pi performance and live packet/drop counters if the SRS performance claim remains in scope.
- Test physical concurrent adapters if simultaneous live capture is to be claimed.

Until those checks are run or the SRS scope is formally narrowed, report the product as **demo-ready for supported local Wi-Fi/Ethernet capture and metadata analysis, with the limitations above**, not as fully hardware-accepted against every SRS claim.
