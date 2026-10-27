# Requirement Traceability Matrix

This matrix connects the approved SRS requirements to GitHub work items and the Software Test Plan (STP). It is a planning/verification index, not proof that a feature is implemented. A requirement should be marked complete only after the relevant implementation is merged and verification evidence is recorded.

## Functional requirements

| SRS requirement | Requirement summary | GitHub issue | STP test case | Current evidence/status |
|---|---|---|---|---|
| REQ-1 | Capture raw packets from a selected interface: Ethernet, Wi-Fi monitor mode, or BLE advertisement source. | [#3](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/3) | TC-CAP-01 | Base PCAP replay and passive Scapy backend are in main. PR #29 merged concurrent capturers and conditional parser support for supplied Wi-Fi/BLE link types into main. Wi-Fi monitor mode and actual BLE radio capture still require target hardware/driver smoke tests. |
| REQ-2 | Report unavailable interfaces and capture permission/startup failures clearly. | [#9](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/9) | TC-CAP-02 | Typed capture errors are merged in PR #17 and stable exit handling in PR #22. PR #24 integrates the helper in the session/CLI path and tests it with generated PCAP data. Live permission/startup checks remain platform-specific. |
| REQ-3 | Extract source/destination address, protocol, size, and timestamp. | [#4](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/4) | TC-ANA-01 | Main covers TCP/UDP/ARP/ICMP/DNS/IPv4/IPv6. PR #29 merged source/destination MAC metadata and Wi-Fi/BLE link-type decoding tests where address metadata is exposed. Malformed or unsupported link types are explicitly declined; BLE advertisement destination may not be present in the frame. |
| REQ-4 | Provide an extensible protocol-analyzer pipeline. | [#4](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/4) | TC-ANA-02 | PR #23 provides protocol classification; PR #24 adds the ordered AnalyzerPipeline, custom analyzer/fallback tests, and generated-PCAP end-to-end verification. |
| REQ-5 | Store captures as PCAP and retain searchable packet metadata. | [#5](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/5) | TC-STO-01 | Main covers local PCAP and SQLite round-trip. PR #29 merged per-session/per-link-type PCAP mapping and interface/backend metadata for concurrent mixed-link sessions; schema migration and regression tests passed in main CI. |
| REQ-6 | Filter/query stored captures by protocol, address and time window. | [#6](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/6) | TC-STO-02 | Protocol/address/time-window query methods merged in PR #19. PR #24 exposes CLI query options and exercises them against generated PCAP data. |
| REQ-7 | Display live packet rate, protocol breakdown and top five talkers. | [#7](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/7) | TC-PRE-01 | The renderer merged in PR #20. PR #24 adds rolling packet-rate/protocol/top-talker statistics and wires them into CaptureSession and the CLI live dashboard. |
| REQ-8 | Export a capture-session summary as CSV or PDF. | [#8](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/8) | TC-PRE-02 | Main provides both CSV and PDF using session-scoped Repository retrieval. Both formats include session/packet metadata only and refuse overwrite; PDF generation and CLI behavior are covered by CI. |
| REQ-9 | Flag supported suspicious patterns through an Observer event. | [#13](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/13) | TC-SEC-01 | Main includes metadata-only Observer events for ARP IP/MAC conflicts and optional inventory-based unknown device/AP indicators, with match and non-match tests. They are heuristics, not proof of an attack. Latest main CI passed 106 tests ([run 40479490511](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40479490511)); target-hardware validation remains pending. |
| REQ-10 | Run more than one capture backend together without changing downstream layers. | [#14](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/14) | TC-CAP-03 | Main includes `ConcurrentCapturer` with shared stop/count, per-source metadata, mixed-link storage mapping, and synthetic fan-in/error tests. Latest main CI passed 106 tests ([run 40479490511](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40479490511)); actual simultaneous multi-radio capture remains target-hardware verification. |

## Cross-cutting quality requirements

| Quality/security area | Work item(s) | Verification evidence required |
|---|---|---|
| Passive-only operation and authorized use | [#10](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/10) | Capture remains passive and the CLI only reads a PCAP or listens on the selected authorized interface; there is no upload command. Automated POSIX private-directory/file permission tests are included; live-interface and target-platform checks remain pending. |
| Local capture-data confidentiality and permissions | [#5](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/5), [#10](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/10) | Storage enforces POSIX directory mode 0700 and PCAP/SQLite file mode 0600, including existing storage folders. Automated tests check these modes; Windows ACL checks remain manual. |
| Reliability and actionable errors | [#9](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/9), [#11](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/11) | Capture tests cover unavailable interfaces, permissions, malformed PCAPs, startup failures and Ctrl+C cleanup. PR #24 adds stable CLI exit codes and a generated-PCAP Capture → Analysis → Storage → query/statistics/CSV test. |
| Raspberry Pi/target-platform performance and statistics refresh interval | [#10](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/10), [#11](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/11) | Record measurements on the target hardware; do not infer performance from unit tests on CI. |
| Modularity and maintainability | [#1](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/1), [#11](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/11) | Review documented boundaries between Capture, Analysis, Storage and Presentation; check the cross-layer interfaces in integration tests. |
| Setup, limitations and safe demo | [#12](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/12) | Fresh setup follows the README; demo instructions use controlled/synthetic traffic or an authorized interface. |

## Snapshot notes

### Main baseline (2026-10-26)



- Merged PRs: #17 Capture, #18 process/traceability documentation, #19 Storage/Query, #20 statistics renderer, #21 CSV exporter, #22 error/security helpers, #23 Analysis parser, and #24 end-to-end application integration.
- Current main commit `cd80e958bf572c32126c3f222579aec638da04b7` (PR #29 merge) passed latest main CI [40479490511](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40479490511): Ruff passed and pytest reported **106 passed in 1.87s**.
- Main includes AnalyzerPipeline, TrafficStatistics, CaptureSession, the CLI, architecture checks and generated-PCAP integration coverage. The Sprint 1 closeout and review record are in Docs/SPRINT_PLAN.md and Docs/SPRINT_1_REVIEW_RETROSPECTIVE.md. Live interface/Wi-Fi monitor mode/BLE/Raspberry Pi verification and repository branch protection remain separate follow-ups.

### SRS compliance branch (2026-10-27)

- Branch: `feat/PPS-28-srs-compliance`.
- Added implementation candidates for PDF export, metadata-only Observer alerting, concurrent capture, multi-link-type per-session storage, synthetic PCAP demo tooling, and source-context persistence.
- Latest main CI (2026-10-27): [run 40479490511](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40479490511) passed Ruff and reported **106 passed in 1.87s** after PR #29 merged. The replay benchmark is a local processing/storage measure, not a live packet-loss result; target-hardware verification remains pending.
- This branch is not merged into `main`; its functional rows above describe review-branch code, not the current main release.

## Verification record

See [Docs/TEST_EXECUTION_REPORT.md](TEST_EXECUTION_REPORT.md) for the current CI run, STP test-case mapping, and unexecuted target-environment checks.

For every acceptance criterion, record:
- the implementing PR/commit;
- the command or test case run and its result;
- any platform-specific/manual verification and environment;
- any limitation or unsupported configuration.

Status changes must be based on evidence, not on an issue being assigned, a branch existing, or a PR being opened. Keep this matrix synchronized as issues and tests evolve.


## Latest backend compliance branch verification

PR #29 merged into `main` as commit `cd80e958bf572c32126c3f222579aec638da04b7`. The resulting main CI run [40479490511](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40479490511) passed Ruff and reported 106 passed in 1.87s. Target-hardware validation remains required.
