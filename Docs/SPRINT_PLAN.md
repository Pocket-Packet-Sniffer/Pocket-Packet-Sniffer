# Pocket Packet Sniffer — Sprint Plan

This plan groups work into two delivery increments. Sprint dates and commitments must be agreed by the team; no due dates are inferred here. The sprint assignments are a planning proposal and do not indicate that work is completed.

## Sprint 1 — Foundation and core packet pipeline

**Goal:** establish a reviewable workflow and bring the base capture-to-storage pipeline together.

| Issue | Work | Owner/coordinator | Intended outcome |
|---|---|---|---|
| #1 | Foundation workflow, CI and requirement traceability | Vikas coordinates; shared work | Workflow and traceability are documented; CI is active and passing on merged code. |
| #3 | Raw packet capture via common Capturer interface | Vikas | Replay fixture backend and supported passive live capture implementation, reviewed and tested. |
| #4 | Parse/classify packets into a common packet record | Shivanand | Agree the shared packet model with Capture and Storage; parsing tests pass. |
| #5 | PCAP storage and Repository interface | Shivakumara GP | Persist packets/metadata and verify retrieval, after agreeing the shared model. |
| #9 | Missing interface and permission failures | Vikas | Actionable typed errors; Presentation/CLI integration is handled with the owning layer. |
| #10 | Start security/passive-use and portability checks | Vikas + Shivakumara, shared | Capture/storage safety review begins; evidence is recorded. |
| #11 | Test scaffolding and CI setup | Sanjith coordinates, shared | Initial CI and unit tests run on PRs; end-to-end scope is planned. |
| #15 | Sprint planning/review/retrospective records | Vikas coordinates; shared | Agree sprint commitment, note blockers, then record review and retrospective at sprint end. |
| #16 | Repository configuration | Vikas | Complete contributor access check and remaining repository settings when prerequisites are ready. |

## Sprint 2 — Query, presentation, integration and release readiness

**Goal:** deliver a demonstrable end-to-end user flow and record verification evidence.

| Issue | Work | Owner/coordinator | Intended outcome |
|---|---|---|---|
| #6 | Filter and query saved captures | Shivakumara GP | Search by protocol, address and time window using the agreed Repository API. |
| #7 | Live traffic statistics in CLI | Sanjith R | Display packet rate, protocol breakdown and top five talkers using Analysis events/data. |
| #8 | Export session reports | Sanjith R | Generate the required session report formats and test outputs. |
| #10 | Finish security and portability verification | Shared; Capture/Storage lead relevant checks | Review passive-only behaviour, privacy, local file permissions and target-platform limitations. |
| #11 | Integration and end-to-end tests | Shared; Sanjith coordinates | Verify Capture → Analysis → Storage → Presentation using controlled PCAP fixtures; record actual test results. |
| #12 | Architecture/setup/demo documentation | Sanjith R coordinates, shared contributions | Document installation, supported backends, safe demo steps, outputs, tests and known limitations. |

Issues #10 and #11 can span both sprints. The team should carry unfinished work forward rather than mark it done to fit the plan. Issue #16 should remain open until its repository-level checklist is actually complete.

## Stretch backlog — not part of the committed sprint scope

- **#13 — Suspicious-activity alerts (REQ-9):** consider only once the core pipeline is stable and there is evidence supporting detections.
- **#14 — Concurrent capture backends (REQ-10):** consider only after single-backend end-to-end capture is stable.

## Sprint 1 progress snapshot — 2026-10-26

This is a mid-sprint evidence snapshot, not the sprint review or retrospective.

### Verified merged deliveries

- **PR #17 — Capture:** common Capturer contract, classic-PCAP replay, passive Scapy backend, typed capture errors, synthetic fixture tests and CI.
- **PR #19 — Storage/Query:** PCAP persistence, indexed SQLite metadata, Repository interface, query filters and storage/query tests.
- **PR #18 — Process/traceability:** workflow documentation, SRS-to-issue/STP mapping and sprint plan.
- Main CI was green after the Capture and Storage merges. The statistics renderer (PR #20) and CSV report exporter (PR #21) are also merged, but their complete CLI/session integration remains dependent on Analysis and is not counted as a finished end-to-end pipeline.

### Outstanding Sprint 1 work

| Issue | Current evidence | Remaining before closing |
|---|---|---|
| #1 | Workflow/docs/CI are present and merged. | Keep the issue's acceptance checklist synchronized; end-to-end architectural proof belongs to #11. |
| #3 | Capture code is merged and its CI passed. | Verify the common callback feeds the actual Analysis implementation; confirm supported live-interface behaviour in an authorized environment. |
| #4 | Analysis dependency is not yet integrated into main. | Implement packet metadata extraction, protocol analyzers and controlled tests. |
| #9 | Capture error types and unit tests are merged; an exit-code helper is under review in a follow-up PR. | Wire the helper into the real CLI/session entry point and verify no traceback/misleading active session. |
| #10 | Capture is passive by design; Storage permission handling exists; a POSIX mode test and security validation record are being added. | Review after the full CLI exists; verify target OS/driver and Raspberry Pi constraints manually. |
| #11 | CI and per-layer unit tests are present. | Add cross-layer integration/end-to-end tests after Analysis is merged. |
| #15 | Sprint goal, scope and dependencies are recorded above. | Team must record the actual sprint review, incomplete items, demo evidence and retrospective at sprint end. |
| #16 | Labels/milestones and contributor write access are verified; CODEOWNERS is in main. | Repository branch protection, required check settings and plan-dependent security settings still need maintainer UI configuration. |

Do not close a partial issue merely because its code is merged. The key blocker for declaring the core Sprint 1 pipeline complete is the common Analysis implementation and the end-to-end Capture → Analysis → Storage path.

## Sprint review and retrospective

At each sprint end, record:
- completed issues and linked merged PRs;
- demo evidence and test results;
- incomplete work and blockers carried forward;
- one or two process improvements, each with an owner.

Do not use the Project board's `Done` status until acceptance criteria have been verified and implementation is merged where code is involved.
