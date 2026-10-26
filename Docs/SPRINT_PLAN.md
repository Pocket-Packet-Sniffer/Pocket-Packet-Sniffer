# Pocket Packet Sniffer — Sprint Plan and Closeout

**Closeout snapshot:** 2026-10-26. Sprint 1's core implementation goal is delivered and merged. The evidence-based closeout review is documented in `Docs/SPRINT_1_REVIEW_RETROSPECTIVE.md`. This record distinguishes automated test evidence from manual hardware checks and distinguishes the maintainer's asynchronous review from a synchronous team meeting (none is recorded in the repository).

## Sprint 1 — Foundation and core packet pipeline

**Goal:** establish a reviewable workflow and bring the base capture-to-storage pipeline together.

### Planned scope and final disposition

| Issue | Work | Owner/coordinator | Estimate | Closeout disposition |
|---|---|---|---:|---|
| #1 | Foundation workflow, CI and requirement traceability | Vikas; shared | 5 | **Closed.** Workflow, CI, README, requirements traceability and repository process baseline are merged. |
| #3 | Raw packet capture via common Capturer interface | Vikas | 5 | **Closed.** Common interface, classic-PCAP replay, passive Scapy backend and Analysis handoff are merged and tested. |
| #4 | Packet parsing and cross-layer record contract | Shivanand | 5 | **Closed.** PR #23 provides parsing; PR #24 provides AnalyzerPipeline and a tested application adapter. ADR 0001 records the accepted application-boundary contract. |
| #5 | PCAP storage and Repository interface | Shivakumara GP | 5 | **Closed.** PCAP persistence, SQLite metadata, filters and repository tests are merged. |
| #9 | Missing interface and permission failures | Vikas | 3 | **Closed for the implemented path.** Typed errors and stable CLI/session exit handling are merged. Live-driver behaviour remains a manual release-readiness check. |
| #10 | Security/passive-use and portability checks | Vikas + Shivakumara | 5 | **Carried into M4.** Automated POSIX permissions, passive-use constraints and local-only CLI behaviour are covered. Authorized live-interface, Windows ACL and target-hardware checks remain open in #10. |
| #11 | Test scaffolding and end-to-end tests | Sanjith; shared | 5 | **Closed for automated fixture coverage.** CI runs lint and tests; generated-PCAP tests exercise Capture → Analysis → Storage → query/statistics/CSV export. |
| #15 | Sprint review/retrospective and process record | Vikas; shared | 2 | **Closeout record prepared.** A maintainer-led asynchronous evidence review and two Sprint 2 process actions are documented. Historical actual effort was not captured; the gap and next-sprint action are recorded without invented values. |
| #16 | Repository configuration | Vikas | TBD | **Carried into M4.** Access, labels, milestones, CODEOWNERS and use of the existing board are recorded. Main branch protection and plan-available security controls need a repository-admin UI action. |

Issues #10 and #16 span foundation and release-readiness work. They remain open as carry-overs and should not be represented as completed technical checks.

## Verified merged implementation evidence

- **PR #17 — Capture:** common Capturer interface, classic-PCAP replay, passive Scapy capture and typed capture errors.
- **PR #18 — Process/traceability:** workflow and project traceability documentation.
- **PR #19 — Storage/Query:** PCAP persistence, SQLite metadata index and query filters.
- **PR #20 — Statistics renderer:** presentation-only statistics formatting and refresh.
- **PR #21 — CSV export:** local session report exporter.
- **PR #22 — Error/security support:** stable capture exit handling and POSIX permission checks.
- **PR #23 — Analysis:** normalized protocol parsing and representative controlled packet tests.
- **PR #24 — End-to-end application:** AnalyzerPipeline, CaptureSession, storage adapter, rolling statistics, CLI commands, architecture checks and generated-PCAP integration tests.
- **PR #25 — Documentation closeout:** updated README, RTM, sprint plan and security/process notes; adds this review/retrospective source document.

**Latest main commit:** `240e9a1dfc4f4120866c89e797cf7ffad9d9f90d` (PR #25 merge).

**Latest verified CI:** [Run 40357674966](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40357674966) — Ruff passed and `pytest -q` reported **81 passed**. Tests use generated packet fixtures and mocks; they do not prove live hardware or target-platform behaviour.

## Sprint 1 closeout decision

The **core Sprint 1 engineering goal is complete**. The implementation and automated integration path are merged; requirements and setup documentation are aligned with the latest code; the final CI run is green.

The following are **carry-over/release-readiness work**, not hidden blockers or falsely completed checks:

| Carry-over | Status/action | Destination |
|---|---|---|
| #10 — live-interface/platform security | Run authorized live-interface startup/permission checks and target OS/driver/security checks; verify Windows ACLs, Wi-Fi mode/BLE support only if the platform is in scope, and Raspberry Pi performance if targeted. | M4 — Release Readiness |
| #16 — repository protection/security controls | Maintainer must enable/verify main-branch PR review, conversation resolution, the observed `Lint and test` check, and available secret-scanning/Dependabot controls. | M4 — Release Readiness |
| Report format | CLI currently exports CSV. Confirm the approved SRS's required report formats; create scoped work for PDF only if required. | Sprint 2/release scope |
| #13 and #14 | Suspicious-activity alerts and concurrent capture backends remain optional stretch issues. | Stretch backlog |

## Sprint 2 focus

Several items originally planned for Sprint 2 were delivered early in PRs #19–#25. Focus new work on manual platform/security verification, any report format confirmed as mandatory, the carry-over settings, and the process improvements below. Do not duplicate completed implementation work.

## Process improvements for Sprint 2

1. **Contract-first cross-layer work.** Before parallel changes in Analysis/Storage/Presentation, write down the boundary contract and decide where the adapter belongs. **Accountable owner: Vikas; review partners: Shivanand and Shivakumara.** Check at the next cross-layer PR.
2. **Earlier integration-test and effort evidence.** For cross-layer tickets, add a generated-fixture end-to-end test before integration and record planned estimate plus actual effort (or explicitly record that actual effort was not captured) at issue close. **Accountable owner: Sanjith for test coordination; Vikas for the closeout checklist.** Check at the next sprint review.

The review/retrospective evidence and limitations are recorded in `Docs/SPRINT_1_REVIEW_RETROSPECTIVE.md`. The record is an asynchronous maintainer closeout from repository evidence, not a claim that a live team meeting or external stakeholder demo occurred.

