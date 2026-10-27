# Implementation Gap Audit — Pocket Packet Sniffer

**Audit basis:** approved Pocket Packet Sniffer SRS v1.3, SASD v1.3, STP v1.3, the current `main` source tree, existing tests, and `Docs/REQUIREMENT_TRACEABILITY.md`.

**Audit date:** 2026-10-27

**Rule:** a requirement is not marked fully verified merely because an issue is closed. Automated fixture tests, source review, and target-platform manual checks are different kinds of evidence.

## Functional requirements

| Requirement | Current implementation/evidence | Audit status | Remaining action |
|---|---|---|---|
| REQ-1 — Capture raw packets from a selected Wi-Fi monitor-mode, Ethernet, or BLE interface | `Capturer`, `PcapFileCapturer`, `ScapyCapturer`; capture tests and generated-PCAP end-to-end test. PCAP replay is supported; live capture depends on Scapy, OS, driver and permissions. | **Partial** — passive live capture exists, but Wi-Fi monitor mode and BLE are not implemented/validated claims. | Validate an authorized Ethernet/live interface on the intended OS. Do not claim monitor-mode or BLE support without a dedicated backend and hardware verification. |
| REQ-2 — Clear unavailable-interface/permission errors | Typed Capture errors, error-handling helper, CLI handling, mocked failure tests. | **Implemented in automated path; manual validation pending** | Perform one authorized live-interface startup and permission failure check on target OS. |
| REQ-3 — Extract source/destination, protocol, size and timestamp | `PacketParser`, normalized packet model, adapter in `CaptureSession`, parser/integration tests. | **Implemented for supported parsed protocols** | Keep unsupported/malformed packet behavior explicit; do not imply every protocol has full parsing. |
| REQ-4 — Add an analyzer without changing existing analyzers | `AnalyzerPipeline`, parser adapter and pipeline tests. | **Implemented** | Maintain architecture-boundary tests for future additions. |
| REQ-5 — Persist captures as PCAP and/or indexed metadata | `PcapSqliteRepository`, PCAP files, SQLite metadata and storage tests. | **Implemented** | Confirm fresh-directory demo and generated output paths. |
| REQ-6 — Query stored captures by protocol, address or time window | Repository query filters and CLI `query`; storage/CLI integration tests. | **Implemented** | Add session-scoped public retrieval only if required by reports or usability; do not access private SQLite internals from Presentation. |
| REQ-7 — Live packet rate, protocol breakdown and top five talkers | `TrafficStatistics`, renderer, live CLI dashboard and session integration; prior main CI run reported 81 passing tests. | **Implemented in tested code path** | Record real target-hardware refresh/performance evidence separately; refresh interval must remain <= 2 seconds. |
| REQ-8 — Export session summary as CSV or PDF | CSV exporter and CLI export path; tests for report output/error behavior. SRS says **CSV or PDF**, not both. | **Implemented via CSV** | Verify current branch's end-to-end session export on a clean demo. PDF is not required by this wording unless an approved revision says otherwise. |
| REQ-9 — Publish suspicious-pattern alerts through an Observer event | Issue #13 is marked stretch; current main RTM says not implemented. | **Missing (stretch)** | Add Analysis-layer rule/event interfaces, at least one narrowly scoped and testable heuristic, subscriber support in Presentation, positive and negative tests, and explicit heuristic limitations. |
| REQ-10 — Run multiple capture backends concurrently without changes to other layers | Issue #14 is marked stretch; current main RTM says not implemented. | **Missing (stretch)** | Add a multi-capturer coordinator with safe shared stop/error handling, per-backend context, aggregate statistics, and deterministic tests using fake capturers. Do not claim BLE merely because concurrent coordination exists. |

## Non-functional requirements and claims

| Requirement/claim | Current evidence | Status / honest limit |
|---|---|---|
| Passive-only; no packet injection or modification | Capture backend and CLI code paths are receive/replay-file oriented; source/security tests. | **Implemented by current design**. PCAP replay reads a file and is not transmission onto a network. Re-check new code for any send/inject APIs. |
| Local-only capture data, no silent uploads | Current CLI and storage path operate locally; no upload command. | **Implemented for current CLI path**. Any future frontend must call a local API and must not upload captures. |
| Restrict saved capture permissions | POSIX storage directory mode 0700 and file mode 0600; automated tests. | **Automated POSIX checks implemented**; Windows ACL behavior remains unverified. |
| Graceful failures and useful errors | Typed errors, stable CLI exit handling, mocked capture failure tests. | **Automated path implemented**; actual driver/permission behavior remains environment-specific. |
| Layer separation, modularity and extensibility | Capture/Analysis/Storage/Presentation packages, analyzer pipeline, application adapter, architecture tests. | **Implemented in current tested design**. Keep new alert/concurrent coordination behind layer contracts. |
| Refresh every two seconds | Statistics rolling window and live renderer integration. | **Code contract supports <= 2-second refresh**; record target hardware measurements separately. |
| Raspberry Pi/ESP32-class resource/performance claims | Existing tests are fixture-based and CI-hosted. | **Not verified**. No performance/packet-loss claim should be made until benchmarked on the named target. |
| Wi-Fi monitor mode and BLE support | Current backend docs explicitly list these as unverified/not claimed. | **Not implemented/verified**. Do not represent them as supported features. |
| Demo reproducibility | Generated-PCAP integration tests exist, but a single documented, evaluator-friendly command sequence and expected output should be verified. | **Partial**. Add/verify a deterministic demo fixture/generator and step-by-step CLI demo. |

## Implementation order

1. Keep the existing REQ-1 through REQ-8 core path stable and run Ruff + the complete pytest suite on the feature branch.
2. Implement REQ-9 alert/event contracts and one deliberately limited, deterministic rule with match/non-match tests.
3. Implement REQ-10 concurrent coordination with fake capturers, explicit stop semantics, error propagation, and retained backend/interface metadata. Validate no layer-specific coupling is introduced.
4. Add a synthetic classic-PCAP demo fixture or generator and document exact commands, expected results, storage paths, query examples, and CSV export.
5. Update RTM, security validation, end-to-end guide, README, and tests from actual results.
6. Run a real authorized live-interface smoke test on the intended OS if available. Record it as pending if the environment cannot be accessed. Do not fabricate results.
7. Build the frontend only after the backend demo is reproducible.

## Acceptance gate

The project must not claim full SRS compliance until REQ-9 and REQ-10 are either implemented and tested or explicitly excluded through an approved scope revision. The SRS itself marks them **Stretch**, but they remain functional requirements within that stretch scope. REQ-1's Wi-Fi monitor-mode/BLE wording and the Raspberry Pi/ESP32 performance requirement need dedicated implementation or real target validation before those capabilities can be claimed.

The previous CI snapshot (81 tests passing) is a historical baseline, not evidence that future changes pass. Record fresh command output and CI results after implementation.
