# Pocket Packet Sniffer — Sprint Plan

This plan groups work into two delivery increments. Sprint dates and commitments must be agreed by the team; no due dates are inferred here. The sprint assignments are a planning proposal and do not indicate that work is completed.

## Sprint 1 — Foundation and core packet pipeline

**Goal:** establish a reviewable workflow and bring the base capture-to-storage pipeline together.

| Issue | Work | Owner/coordinator | Estimate (points) | Intended outcome |
|---|---|---|---|
| #1 | Foundation workflow, CI and requirement traceability | Vikas coordinates; shared work | 5 | Workflow and traceability are documented; CI is active and passing on merged code. |
| #3 | Raw packet capture via common Capturer interface | Vikas | 5 | Replay fixture backend and supported passive live capture implementation, reviewed and tested. |
| #4 | Parse/classify packets into a common packet record | Shivanand | 5 | Agree the shared packet model with Capture and Storage; parsing tests pass. |
| #5 | PCAP storage and Repository interface | Shivakumara GP | 5 | Persist packets/metadata and verify retrieval, after agreeing the shared model. |
| #9 | Missing interface and permission failures | Vikas | 3 | Actionable typed errors; Presentation/CLI integration is handled with the owning layer. |
| #10 | Start security/passive-use and portability checks | Vikas + Shivakumara, shared | 5 | Capture/storage safety review begins; evidence is recorded. |
| #11 | Test scaffolding and CI setup | Sanjith coordinates, shared | 5 | Initial CI and unit tests run on PRs; end-to-end scope is planned. |
| #15 | Sprint planning/review/retrospective records | Vikas coordinates; shared | 2 | Agree sprint commitment, note blockers, then record review and retrospective at sprint end. |
| #16 | Repository configuration | Vikas | TBD | Complete contributor access check and remaining repository settings when prerequisites are ready. |

## Sprint 2 — Query, presentation, integration and release readiness

**Goal:** deliver a demonstrable end-to-end user flow and record verification evidence.

| Issue | Work | Owner/coordinator | Estimate (points) | Intended outcome |
|---|---|---|---|
| #6 | Filter and query saved captures | Shivakumara GP | 5 | Search by protocol, address and time window using the agreed Repository API. |
| #7 | Live traffic statistics in CLI | Sanjith R | 5 | Display packet rate, protocol breakdown and top five talkers using Analysis events/data. |
| #8 | Export session reports | Sanjith R | 3 | Generate the required session report formats and test outputs. |
| #10 | Finish security and portability verification | Shared; Capture/Storage lead relevant checks | Review passive-only behaviour, privacy, local file permissions and target-platform limitations. |
| #11 | Integration and end-to-end tests | Shared; Sanjith coordinates | Verify Capture → Analysis → Storage → Presentation using controlled PCAP fixtures; record actual test results. |
| #12 | Architecture/setup/demo documentation | Sanjith R coordinates, shared contributions | 3 | Document installation, supported backends, safe demo steps, outputs, tests and known limitations. |

Issues #10 and #11 can span both sprints. The team should carry unfinished work forward rather than mark it done to fit the plan. Issue #16 should remain open until its repository-level checklist is actually complete.

## Stretch backlog — not part of the committed sprint scope

- **#13 — Suspicious-activity alerts (REQ-9):** consider only once the core pipeline is stable and there is evidence supporting detections.
- **#14 — Concurrent capture backends (REQ-10):** consider only after single-backend end-to-end capture is stable.

## Sprint 1 progress snapshot — 2026-10-26

This is an evidence-based progress snapshot, not a claim that the team has completed its final sprint review.

### Verified merged deliveries
- **PR #17 — Capture:** common Capturer contract, classic-PCAP replay, passive Scapy backend, typed errors and tests.
- **PR #18 — Process/traceability:** workflow documentation, RTM and sprint plan.
- **PR #19 — Storage/Query:** classic-PCAP persistence, SQLite index, Repository boundary, filters and tests.
- **PR #20 — Statistics renderer:** presentation-only renderer and refresh loop.
- **PR #21 — CSV report exporter:** local CSV export and tests.
- **PR #22 — Error/security support:** stable capture exit helper, POSIX permission checks and documentation.
- **PR #23 — Analysis parser:** normalized packet metadata and TCP/UDP/ARP/ICMP/DNS fixture tests.
- Main CI passed after PR #23 with lint successful and 68 tests passing.

### Current integration branch
The branch `feat/PPS-11-end-to-end-session` adds an extensible AnalyzerPipeline, CaptureSession adapter from Analysis metadata plus raw packet bytes to the Storage record contract, rolling traffic statistics, CLI commands for capture/query/CSV export, architecture-boundary tests, and generated-PCAP end-to-end tests. The latest CI run on the final branch commit must pass, and the PR must receive peer review/merge before these changes count as delivered to `main`.

### Remaining before Sprint 1 is fully closed
| Issue | Evidence | Remaining |
|---|---|---|
| #1 | Governance/docs and CI are merged; the updated RTM and CLI guide are in the integration branch. | Merge/verify the latest documentation, then reconcile acceptance checklist with the merged evidence. |
| #3 | Capture code is merged; CaptureSession is in the integration branch. | Merge after review and run an authorized live-interface smoke test. |
| #4 | Analysis parser is merged in PR #23; AnalyzerPipeline is in the integration branch. | Merge the pipeline and tests; then verify acceptance criteria. |
| #9 | Stable error helper is merged and the integration branch uses it in the CLI/session path. | Review the new integration, then verify live permission/startup handling in an authorized environment if available. |
| #10 | POSIX private directory/file modes are automated; passive-only constraints are documented. | Windows ACL, live driver, Raspberry Pi/performance, and full live-CLI security checks are manual. |
| #11 | Per-layer tests and generated-PCAP end-to-end tests are in the integration branch. | Review/merge and retain live-interface/hardware checks as follow-ups. |
| #15 | Sprint goal, estimates, dependencies, and blockers are recorded. | The team must supply actual review/demo feedback, retrospective improvements/owners, and estimate-versus-actual observations. |
| #16 | Contributor access, labels, milestones, and initial CODEOWNERS are recorded. | Repository admin must configure main-branch protection and available secret-scanning/Dependabot settings in GitHub Settings; connector cannot write these controls. |

Stretch requirements #13 (alerts) and #14 (concurrent backends) remain deferred. Do not claim the sprint complete until the integration PR is merged and the actual team review/retrospective has been recorded.

## Sprint review and retrospective

At each sprint end, record:
- completed issues and linked merged PRs;
- demo evidence and test results;
- incomplete work and blockers carried forward;
- one or two process improvements, each with an owner.

Do not use the Project board's `Done` status until acceptance criteria have been verified and implementation is merged where code is involved.
