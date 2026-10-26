# Requirement Traceability Matrix

This matrix connects the approved SRS requirements to GitHub work items and the Software Test Plan (STP). It is a planning/verification index, not proof that a feature is implemented. A requirement should be marked complete only after the relevant implementation is merged and verification evidence is recorded.

## Functional requirements

| SRS requirement | Requirement summary | GitHub issue | STP test case | Current evidence/status |
|---|---|---|---|---|
| REQ-1 | Capture raw packets from a selected supported interface/backend. Actual support depends on hardware, drivers, OS and permissions. | [#3](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/3) | TC-CAP-01 | Capture implementation is in open PR #17. CI passes on that PR; peer review and merge are pending. Live hardware capture is not yet validated. |
| REQ-2 | Report unavailable interfaces and capture permission/startup failures clearly. | [#9](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/9) | TC-CAP-02 | Capture-layer typed errors and unit tests are included in PR #17; CLI exit-code integration and peer review remain. |
| REQ-3 | Extract timestamp, source/destination address, protocol and packet size. | [#4](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/4) | TC-ANA-01 | Analysis implementation and end-to-end verification are pending. |
| REQ-4 | Provide an extensible protocol-analyzer pipeline. | [#4](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/4) | TC-ANA-02 | Analysis implementation and extensibility verification are pending. |
| REQ-5 | Store captures as PCAP and retain searchable packet metadata. | [#5](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/5) | TC-STO-01 | Storage code exists on branch `feat/PPS-04-storage-query`; a PR, peer review, test verification and integration are pending. |
| REQ-6 | Filter/query stored captures by protocol, address and time window. | [#6](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/6) | TC-STO-02 | Implementation and verification are pending review/integration. |
| REQ-7 | Display live packet rate, protocol breakdown and top five talkers. | [#7](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/7) | TC-PRE-01 | Presentation implementation and verification are pending. |
| REQ-8 | Export capture-session summaries, including the required CSV/PDF output. | [#8](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/8) | TC-PRE-02 | Presentation/report implementation and verification are pending. |
| REQ-9 | Detect/report suspicious patterns and emit alerts. | [#13](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/13) | TC-SEC-01 | Stretch requirement; not committed until the core pipeline is stable. |
| REQ-10 | Support concurrent capture backends. | [#14](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/14) | TC-CAP-03 | Stretch requirement; not committed until single-backend end-to-end capture is stable. |

## Cross-cutting quality requirements

| Quality/security area | Work item(s) | Verification evidence required |
|---|---|---|
| Passive-only operation and authorized use | [#10](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/10) | Review confirms no packet injection, modification or network transmission; authorized lab/demo procedure is documented. |
| Local capture-data confidentiality and permissions | [#5](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/5), [#10](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/10) | Check local file permissions, sensitive-data handling and that capture data is not silently uploaded. |
| Reliability and actionable errors | [#9](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/9), [#11](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/11) | Tests cover missing interfaces, insufficient privileges, malformed PCAPs, backend startup failures and error cleanup. |
| Raspberry Pi/target-platform performance and statistics refresh interval | [#10](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/10), [#11](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/11) | Record measurements on the target hardware; do not infer performance from unit tests on CI. |
| Modularity and maintainability | [#1](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/1), [#11](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/11) | Review documented boundaries between Capture, Analysis, Storage and Presentation; check the cross-layer interfaces in integration tests. |
| Setup, limitations and safe demo | [#12](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/12) | Fresh setup follows the README; demo instructions use controlled/synthetic traffic or an authorized interface. |

## Verification record

For every acceptance criterion, record:
- the implementing PR/commit;
- the command or test case run and its result;
- any platform-specific/manual verification and environment;
- any limitation or unsupported configuration.

Status changes must be based on evidence, not on an issue being assigned, a branch existing, or a PR being opened. Keep this matrix synchronized as issues and tests evolve.
