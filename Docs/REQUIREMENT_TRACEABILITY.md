# Requirement Traceability Matrix

This matrix connects the approved SRS requirements to GitHub work items and the Software Test Plan (STP). It is a planning/verification index, not proof that a feature is implemented. A requirement should be marked complete only after the relevant implementation is merged and verification evidence is recorded.

## Functional requirements

| SRS requirement | Requirement summary | GitHub issue | STP test case | Current evidence/status |
|---|---|---|---|---|
| REQ-1 | Capture raw packets from a selected supported interface/backend. Actual support depends on hardware, drivers, OS and permissions. | [#3](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/3) | TC-CAP-01 | Capture implementation merged in PR #17 and main CI passed. Live hardware capture is not validated; passing the backend-neutral packet callback to the complete Analysis pipeline remains blocked on #4. |
| REQ-2 | Report unavailable interfaces and capture permission/startup failures clearly. | [#9](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/9) | TC-CAP-02 | Typed capture errors/tests merged in PR #17. The current PR adds a tested Presentation-layer error/exit-code wrapper; the full CLI/session command still needs to invoke it after Analysis integration. |
| REQ-3 | Extract timestamp, source/destination address, protocol and packet size. | [#4](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/4) | TC-ANA-01 | No complete Analysis implementation is merged to main as of this snapshot; end-to-end verification is pending. |
| REQ-4 | Provide an extensible protocol-analyzer pipeline. | [#4](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/4) | TC-ANA-02 | Analysis implementation and extensibility verification are pending. |
| REQ-5 | Store captures as PCAP and retain searchable packet metadata. | [#5](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/5) | TC-STO-01 | Storage/Query implementation merged in PR #19; CI passed lint/tests and issue #5 is closed. End-to-end integration with Analysis remains pending. |
| REQ-6 | Filter/query stored captures by protocol, address and time window. | [#6](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/6) | TC-STO-02 | Protocol/address/time-window query methods and their tests merged in PR #19; issue #6 is closed. User-facing CLI integration remains pending. |
| REQ-7 | Display live packet rate, protocol breakdown and top five talkers. | [#7](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/7) | TC-PRE-01 | The statistics renderer merged in PR #20 and has controlled snapshot tests. The PR documents the Analysis statistics-provider and full CLI/session wiring as outstanding; do not infer end-to-end REQ-7 completion from the renderer alone. |
| REQ-8 | Export capture-session summaries, including the required CSV/PDF output. | [#8](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/8) | TC-PRE-02 | CSV session-report export merged in PR #21 with controlled tests. Full CLI/session wiring and any additional report formats required by the approved SRS remain to be confirmed. |
| REQ-9 | Detect/report suspicious patterns and emit alerts. | [#13](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/13) | TC-SEC-01 | Stretch requirement; not committed until the core pipeline is stable. |
| REQ-10 | Support concurrent capture backends. | [#14](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/14) | TC-CAP-03 | Stretch requirement; not committed until single-backend end-to-end capture is stable. |

## Cross-cutting quality requirements

| Quality/security area | Work item(s) | Verification evidence required |
|---|---|---|
| Passive-only operation and authorized use | [#10](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/10) | Code review of current Capture/Storage paths found no packet transmission/injection API; a permission-mode test and a documented manual verification checklist are added in the current capture-error/security PR. Authorized live-interface and target-platform checks remain pending. |
| Local capture-data confidentiality and permissions | [#5](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/5), [#10](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/10) | Storage creates local PCAP/SQLite files with private POSIX mode bits; current PR adds automated mode checks and records that capture data stays local. Windows ACL and complete-CLI audit remain manual follow-ups. |
| Reliability and actionable errors | [#9](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/9), [#11](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/11) | Capture tests cover unavailable interfaces, permissions, malformed PCAPs and startup failures; the current PR adds stable CLI-style exit-code tests. End-to-end application error handling remains pending. |
| Raspberry Pi/target-platform performance and statistics refresh interval | [#10](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/10), [#11](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/11) | Record measurements on the target hardware; do not infer performance from unit tests on CI. |
| Modularity and maintainability | [#1](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/1), [#11](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/11) | Review documented boundaries between Capture, Analysis, Storage and Presentation; check the cross-layer interfaces in integration tests. |
| Setup, limitations and safe demo | [#12](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/12) | Fresh setup follows the README; demo instructions use controlled/synthetic traffic or an authorized interface. |

## Snapshot notes (2026-10-26)

- Merged layer PRs: #17 Capture, #19 Storage/Query, #20 statistics renderer, and #21 CSV report exporter; process/traceability updates are in #18.
- Latest observed main CI passed lint and tests. The current capture-error/security PR has its own checks in progress.
- The Analysis layer is not yet integrated into main, so the Capture → Analysis → Storage → Presentation system has not yet been verified end to end.

## Verification record

For every acceptance criterion, record:
- the implementing PR/commit;
- the command or test case run and its result;
- any platform-specific/manual verification and environment;
- any limitation or unsupported configuration.

Status changes must be based on evidence, not on an issue being assigned, a branch existing, or a PR being opened. Keep this matrix synchronized as issues and tests evolve.
