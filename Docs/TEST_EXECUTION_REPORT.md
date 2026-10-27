# Pocket Packet Sniffer — Test Execution Report

**SRS:** v1.3  
**STP:** v1.3  
**Implementation under test:** PR #29, branch `feat/PPS-28-srs-compliance`  
**Code revision at recorded CI run:** `8494469f09fc0fbfcf5ab41d071536629983e2c7`  
**CI evidence:** [GitHub Actions run 40473984177](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40473984177)  
**Run date:** 2026-10-27

## Automated result

| Check | Environment / command | Result |
|---|---|---|
| Python lint | Ubuntu 24.04, Python 3.12; `ruff check --select E4,E7,E9,F,I src tests tools` | PASS — “All checks passed!” |
| Unit and integration tests | `pytest -q` | PASS — **105 passed in 1.31 seconds** |
| Full review merge gate | PR #29 | **Not complete** — an independent teammate approval is still required; PR is open and not merged. |

CI uses generated PCAP fixtures and mocked capture backends. It does not require root/administrator privileges or send traffic.

## SRS / STP functional traceability

| SRS requirement / STP case | Automated evidence in the repository | Result and limitations |
|---|---|---|
| REQ-1 / TC-CAP-01 — capture selected raw packets | `tests/test_capture_layer.py`, `tests/test_session_integration.py`, `tests/test_concurrent_capture.py` | **Partial overall.** Local classic-PCAP replay and concurrent synthetic sources are tested. Live Ethernet smoke test is not recorded; Wi-Fi monitor mode and BLE radio capture are not hardware-verified. |
| REQ-2 / TC-CAP-02 — unavailable interface / permission errors | `tests/test_capture_layer.py`, `tests/test_capture_runner.py`, `tests/test_cli.py` | Typed error paths and CLI behavior are automated-tested with controlled conditions. Actual driver/OS permission diagnostics remain a manual target check. |
| REQ-3 / TC-ANA-01 — protocol, addresses, size, timestamp | `tests/test_analysis_layer.py`, `tests/test_session_integration.py` | Supported decoders are tested on synthetic fixtures. Malformed and unsupported link types may be ignored by design; live BLE/Wi-Fi source behavior is not proven by parser fixtures. |
| REQ-4 / TC-ANA-02 — extensible analyzer pipeline | `tests/test_analysis_pipeline.py`, `tests/test_architecture_boundaries.py` | PASS for tested pipeline extension/fallback behavior and the Analysis/Storage dependency boundary. |
| REQ-5 / TC-STO-01 — PCAP and searchable metadata | `tests/test_storage_query.py`, `tests/test_session_integration.py` | PASS for local PCAP/SQLite persistence, session-scoped retrieval, migration, and mixed-link-type synthetic sessions. |
| REQ-6 / TC-STO-02 — protocol/address/time filters | `tests/test_storage_query.py`, `tests/test_cli.py` | PASS for query combinations and time-window validation. |
| REQ-7 / TC-PRE-01 — packet rate, protocol breakdown, top five talkers | `tests/test_analysis_statistics.py`, `tests/test_presentation_dashboard.py`, `tests/test_session_integration.py` | PASS for snapshots and the 2-second CLI refresh contract using test data. Live target throughput is not measured by CI. |
| REQ-8 / TC-PRE-02 — session report export | `tests/test_presentation_report_export.py`, `tests/test_report_pdf.py` | PASS for CSV and PDF output, content/summary, invalid destinations, and no-overwrite behavior. The SRS says CSV **or** PDF; the branch supports both. |
| REQ-9 / TC-SEC-01 — Observer suspicious-activity events (stretch) | `tests/test_analysis_alerts.py`, `tests/test_cli.py` | PASS for tested match/non-match cases: ARP IP/MAC conflict and allowlist-based device/AP indicators. Alerts are heuristics, not proof of malicious activity. AP detection requires decoded Wi-Fi beacon frames and an explicit allowlist. |
| REQ-10 / TC-CAP-03 — concurrent capture (stretch) | `tests/test_concurrent_capture.py`, `tests/test_storage_query.py`, `tests/test_session_integration.py` | PASS for synthetic concurrent file sources, aggregation, cancellation/error paths and mixed-link-type storage. Two actual live adapters have not been tested simultaneously. |

## Non-functional and security verification

| SRS/STP claim | Automated/code evidence | Remaining gap |
|---|---|---|
| Passive-only behavior | Capture strategies listen; PCAP replay only reads a local file. Automated tests use mocks/fixtures; code review of the CLI found no packet-send/injection command. | Continue review on future changes. No packet injection is part of the intended design. |
| Saved artifacts stay local and private | Storage permission tests cover POSIX directory mode 0700 and PCAP/SQLite file mode 0600. CSV/PDF exporters refuse overwrite and omit payload bytes. | Windows ACL behavior is not verified. Real captures can contain sensitive metadata/payloads; protect local files. |
| Refresh within two seconds | The CLI dashboard refresh interval is configured to 2.0 seconds and renderer behavior has tests. | Live terminal responsiveness on the target hardware remains unmeasured. |
| Raspberry Pi processing and zero drops | `tools/benchmark_pipeline.py` can measure synthetic PCAP replay → parsing → local PCAP/SQLite write throughput on the machine where it is run. A test verifies its accounting and session reuse guard. | **No Raspberry Pi throughput measurement and no live NIC/kernel-drop counter measurement is recorded.** Replay throughput does not establish zero live packet loss. Run on the approved target and record board, OS, adapter/driver, traffic rate, duration, received/stored counts, and available drop counters. |
| Wi-Fi monitor mode / BLE advertisement scanning | Parser tests cover supplied PCAP link types where supported metadata is available. | **Actual radio/backend tests not executed.** Verify a compatible Wi-Fi monitor-mode adapter and BLE sniffer/HCI path on intended hardware before claiming live support. |
| Portability / graceful failure | Typed errors, CLI status mapping, permission tests and unit tests cover controlled failure cases. | Live OS/driver messages require smoke tests on each supported target. |
| Third-party acknowledgement | README acknowledges Scapy, pytest and Ruff with documentation links; Zeek is documented as optional and not implemented. | Keep the project report's third-party references aligned with the submitted dependency set. |

## Required manual execution before claiming full SRS acceptance

1. Run an authorized live Ethernet capture start/stop test on the actual target OS and driver. Record interface name, permissions, errors and session summary.
2. If Wi-Fi monitor mode is part of the supported demo, test it with the actual compatible adapter/driver and save the result.
3. If BLE capture is claimed, test the actual BLE sniffer/HCI device and record the captured link type and decoded advertisement metadata. A parser fixture is not sufficient evidence.
4. Run `python tools/benchmark_pipeline.py --repeats 1000 --storage-dir benchmark-captures` on the target device and record its output. Separately generate representative authorized live traffic and record packet/drop counters if the platform exposes them.
5. Verify Windows ACLs if Windows is part of the approved support matrix.
6. Have a teammate independently review PR #29, resolve any review feedback, and merge only after approval.

## Overall disposition

The code-level backend work and synthetic demo path pass the recorded automated CI run. The SRS is **not yet fully hardware-verified**: live-source support, Raspberry Pi performance/drop behavior, and platform-specific checks remain open, and PR #29 must receive independent review before becoming merged `main` functionality.
