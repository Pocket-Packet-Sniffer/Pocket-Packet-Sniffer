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

## Sprint review and retrospective

At each sprint end, record:
- completed issues and linked merged PRs;
- demo evidence and test results;
- incomplete work and blockers carried forward;
- one or two process improvements, each with an owner.

Do not use the Project board's `Done` status until acceptance criteria have been verified and implementation is merged where code is involved.
