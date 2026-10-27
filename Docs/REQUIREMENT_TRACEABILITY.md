# Requirement Traceability Matrix

This matrix connects the approved SRS requirements to GitHub work items and the Software Test Plan (STP). It is a planning/verification index, not proof that a feature is implemented. A requirement should be marked complete only after the relevant implementation is merged and verification evidence is recorded.

## Functional requirements

| SRS requirement | Requirement summary | GitHub issue | STP test case | Current evidence/status |
|---|---|---|---|---|
| REQ-1 | Capture raw packets from a selected supported interface/backend, including SRS-listed Wi-Fi monitor and BLE capabilities. Actual support depends on hardware, drivers, OS and permissions. | [#3](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/3) | TC-CAP-01 | Core Ethernet/Scapy-supported capture and local classic-PCAP replay are implemented. This branch adds Wi-Fi beacon metadata parsing where compatible Radiotap/802.11 frames are supplied. **Partial:** BLE advertisement scanning is not implemented; Wi-Fi monitor mode and live target interfaces need hardware/driver verification. SRS appendices also identify ESP32/BLE as hardware-dependent/stretch risk. |
| REQ-2 | Report unavailable interfaces and capture permission/startup failures clearly. | [#9](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/9) | TC-CAP-02 | Typed capture errors are merged in PR #17 and stable exit handling in PR #22. PR #24 integrates the helper in the session/CLI path and tests it with generated PCAP data. Live permission/startup checks remain platform-specific. |
| REQ-3 | Extract timestamp, source/destination address, protocol, packet size and capture interface. | [#4](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/4) | TC-ANA-01 | PacketParser and controlled TCP/UDP/ARP/ICMP/DNS tests are in PR #23; this branch preserves capture interface in storage using an additive SQLite migration and parses compatible Wi-Fi beacon metadata. New tests exist in this branch; CI must pass before these changes are verified. Unsupported/malformed frames are deliberately skipped. |
| REQ-4 | Provide an extensible protocol-analyzer pipeline. | [#4](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/4) | TC-ANA-02 | PR #23 provides protocol classification; PR #24 adds the ordered AnalyzerPipeline, custom analyzer/fallback tests, and generated-PCAP end-to-end verification. |
| REQ-5 | Store captures as PCAP and/or retain searchable packet metadata. | [#5](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/5) | TC-STO-01 | Storage/Query merged in PR #19; PR #24 connects Analysis to PCAP/SQLite. This branch adds persisted capture interface metadata, backward-compatible DB migration, and independent session storage for concurrent backends. New branch tests are pending CI. Classic PCAP stores one link type per capture file. |
| REQ-6 | Filter/query stored captures by protocol, address and time window. | [#6](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/6) | TC-STO-02 | Existing protocol/address/time-window filters are covered by tests. This branch adds the session_id filter and a sessions command backed by public Repository methods; branch CI remains the verification gate. |
| REQ-7 | Display live packet rate, protocol breakdown and top five talkers. | [#7](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/7) | TC-PRE-01 | The renderer merged in PR #20. PR #24 adds rolling packet-rate/protocol/top-talker statistics and wires them into CaptureSession and the CLI live dashboard. |
| REQ-8 | Export a capture-session summary as CSV or PDF. | [#8](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/8) | TC-PRE-02 | CSV export is implemented, wired into the CLI, refuses overwrite and is covered by tests. The SRS uses CSV **or** PDF, so CSV satisfies the stated format requirement; PDF is not mandatory under the current wording. This branch adds the required capture interface field to report rows and session-scoped query retrieval. |
| REQ-9 (Stretch) | Detect/report supported suspicious patterns and publish alert events through Observer. | [#13](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/13) | TC-SEC-01 | This branch adds AlertBus/AlertEvent and heuristics for ARP IP-to-MAC changes, source MACs absent from an explicitly configured trusted-device list, and Wi-Fi beacon BSSIDs outside an explicitly configured trusted-AP list. Tests are present but pending CI. These indicators do not prove an attack; beacon detection requires compatible Wi-Fi metadata. |
| REQ-10 (Stretch) | Capture concurrently across multiple supported backends with combined statistics. | [#14](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/14) | TC-CAP-03 | This branch adds concurrent multi-session orchestration, per-backend storage sessions and shared stats/alerts, plus concurrent local PCAP replay and tests. CI and real multi-interface target verification remain pending. Backend capability still depends on OS/driver/hardware. |

## Cross-cutting quality requirements

| Quality/security area | Work item(s) | Verification evidence required |
|---|---|---|
| Passive-only operation and authorized use | [#10](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/10) | Capture remains passive and the CLI only reads a PCAP or listens on the selected authorized interface; there is no upload command. Automated POSIX private-directory/file permission tests are included; live-interface and target-platform checks remain pending. |
| Local capture-data confidentiality and permissions | [#5](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/5), [#10](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/10) | Storage enforces POSIX directory mode 0700 and PCAP/SQLite file mode 0600, including existing storage folders. Automated tests check these modes; Windows ACL checks remain manual. |
| Reliability and actionable errors | [#9](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/9), [#11](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/11) | Capture tests cover unavailable interfaces, permissions, malformed PCAPs, startup failures and Ctrl+C cleanup. PR #24 adds stable CLI exit codes and a generated-PCAP Capture → Analysis → Storage → query/statistics/CSV test. |
| Raspberry Pi/target-platform performance and statistics refresh interval | [#10](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/10), [#11](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/11) | Record measurements on the target hardware; do not infer performance from unit tests on CI. |
| Modularity and maintainability | [#1](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/1), [#11](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/11) | Review documented boundaries between Capture, Analysis, Storage and Presentation; check the cross-layer interfaces in integration tests. |
| Setup, limitations and safe demo | [#12](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/12) | Fresh setup follows the README; demo instructions use controlled/synthetic traffic or an authorized interface. |

## Snapshot notes (2026-10-27 feature branch audit)

- Merged PRs: #17 Capture, #18 process/traceability documentation, #19 Storage/Query, #20 statistics renderer, #21 CSV exporter, #22 error/security helpers, #23 Analysis parser, and #24 end-to-end application integration.
- Main commit 240e9a1dfc4f4120866c89e797cf7ffad9d9f90d (PR #25 merge) passed CI run [40357674966](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40357674966): Ruff passed and pytest reported 81 passed.
- The main branch includes AnalyzerPipeline, TrafficStatistics, CaptureSession, the CLI, architecture checks and generated-PCAP integration coverage. The Sprint 1 closeout and review record are in Docs/SPRINT_PLAN.md and Docs/SPRINT_1_REVIEW_RETROSPECTIVE.md. Live interface/Wi-Fi monitor mode/BLE/Raspberry Pi verification, any required PDF export, and repository branch protection remain separate follow-ups.

## Verification record

For every acceptance criterion, record:
- the implementing PR/commit;
- the command or test case run and its result;
- any platform-specific/manual verification and environment;
- any limitation or unsupported configuration.

Status changes must be based on evidence, not on an issue being assigned, a branch existing, or a PR being opened. Keep this matrix synchronized as issues and tests evolve.
