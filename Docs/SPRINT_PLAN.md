# Pocket Packet Sniffer — Sprint Plan and Closeout

This document records the planned work and an evidence-based status snapshot as of 2026-10-26. Sprint dates and retrospective outcomes are not inferred; the team must record those separately. A merged PR and passing CI prove implementation/test status, but do not substitute for the team's actual sprint review and retrospective.

## Sprint 1 — Foundation and core packet pipeline

**Goal:** establish a reviewable workflow and bring the base capture-to-storage pipeline together.

### Planned scope and current disposition

| Issue | Work | Owner/coordinator | Estimate | Sprint 1 disposition |
|---|---|---|---:|---|
| #1 | Foundation workflow, CI and requirement traceability | Vikas coordinates; shared work | 5 | **Complete.** README/process/RTM baseline exists; PR #24 refreshes implementation status. |
| #3 | Raw packet capture via common Capturer interface | Vikas | 5 | **Complete.** Common interface, PCAP replay, passive Scapy backend and integrated handoff to Analysis are merged and tested. |
| #4 | Parse/classify packets and establish the cross-layer record contract | Shivanand | 5 | **Complete by explicit adapter.** PR #23 provides parsing; PR #24 provides AnalyzerPipeline and a tested application adapter. ADR 0001 records the accepted adapter design. |
| #5 | PCAP storage and Repository interface | Shivakumara GP | 5 | **Complete.** PCAP persistence, SQLite metadata, filters and repository tests are merged. |
| #9 | Missing interface and permission failures | Vikas | 3 | **Complete for the implemented path.** Typed errors and stable exit handling are merged; the CLI/session path uses the helper. Live driver behaviour remains a manual environment check. |
| #10 | Start security/passive-use and portability checks | Vikas + Shivakumara | 5 | **Sprint 1 portion complete; release checks carry over.** Automated POSIX permission tests and passive-use documentation are merged. Windows ACL, live interface and target-hardware verification remain in the M4 issue. |
| #11 | Test scaffolding and end-to-end tests | Sanjith coordinates; shared | 5 | **Complete for automated fixture coverage.** CI runs lint and tests; a generated-PCAP test exercises Capture → Analysis → Storage → query/statistics/CSV export. |
| #15 | Sprint planning, review and retrospective | Vikas coordinates; shared | 2 | **Closeout in progress.** This plan and the factual review draft are prepared; the team still needs to confirm actual review feedback, retrospective actions and estimate-versus-actual notes. |
| #16 | Repository configuration | Vikas | TBD | **Carry-over.** Contributor access, labels, milestones and CODEOWNERS are in place; main protection and available security controls still require a maintainer UI action. |

## Verified implementation evidence

PRs merged into main:

- **#17 — Capture:** common Capturer interface, classic-PCAP replay, passive Scapy capture and typed capture errors.
- **#18 — Process/traceability:** workflow and project traceability documentation.
- **#19 — Storage/Query:** PCAP persistence, SQLite metadata index and query filters.
- **#20 — Statistics renderer:** presentation-only statistics formatting and refresh.
- **#21 — CSV export:** local session report exporter.
- **#22 — Error/security support:** stable capture exit handling and POSIX permission checks.
- **#23 — Analysis:** normalized protocol parsing and representative controlled packet tests.
- **#24 — End-to-end application:** AnalyzerPipeline, CaptureSession, storage adapter, rolling statistics, CLI commands, architecture checks and generated-PCAP integration tests.

**Latest verified main commit:** c55b116de6465849e6c7d9cbeb6d692ee6bf84c4 (merge of PR #24).

**Latest verified CI:** [Run 40353363252](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40353363252) — Ruff passed and pytest reported **81 passed**. These tests use generated packet fixtures; they do not prove live hardware or target-platform behaviour.

## Sprint closeout decision

The **committed core implementation goal has been delivered**: the integrated path is merged to main, and its automated test suite is green. The project must not claim that every release/governance item is complete.

Carry these items forward rather than misreporting them as done:

| Carry-over | Reason | Destination |
|---|---|---|
| #10 — live interface/portability/security verification | Requires target OS/driver, Windows ACL and/or hardware checks that CI does not perform. | M4 Release Readiness |
| #15 — actual sprint review/retrospective record | Requires team confirmation of demo/review feedback, actual effort, and agreed improvement actions. A factual draft is in Docs/SPRINT_1_REVIEW_RETROSPECTIVE.md. | Close when the team confirms the record |
| #16 — repository protection/security settings | Current GitHub integration cannot write these settings; maintainer must configure and verify them in GitHub Settings. | Repository governance / release readiness |
| PDF report export, if required by the approved SRS | Current CLI exports CSV only; confirm the exact required format before claiming PDF support. | Confirm against SRS; create/reopen a scoped issue if required |

Issues #13 (suspicious-activity alerts) and #14 (concurrent capture backends) remain optional stretch work and are not Sprint 1 completion criteria unless the team changes scope.

## Sprint 2 — Query, presentation, integration and release readiness

**Original goal:** deliver a demonstrable end-to-end user flow and record verification evidence.

Several items originally planned for Sprint 2 were delivered early through PRs #19–#24. The remaining Sprint 2/release focus is manual platform/security verification, any report-format gap required by the SRS, final documentation review, and release preparation. Do not duplicate completed implementation work; update the board to reflect merged issue/PR evidence.

## Review and retrospective procedure

- Use Docs/SPRINT_1_REVIEW_RETROSPECTIVE.md to review the factual results and record team feedback.
- Agree one or two process improvements and assign owners in the meeting; the draft's suggestions are not team consensus.
- Carry incomplete work forward with updated acceptance criteria and ownership.
- Use the Project board's Done status only when the relevant acceptance criteria are verified and implementation is merged.
