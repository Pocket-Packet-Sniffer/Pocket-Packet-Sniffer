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
| #10 | Security/passive-use and portability checks | Vikas + Shivakumara | 5 | **GitHub issue closed; target-environment checks remain unverified in the audit.** Automated POSIX permissions, passive-use constraints and local-only CLI behaviour are covered. Sprint 3 issue #39 tracks any remaining checks required for the supported platform. |
| #11 | Test scaffolding and end-to-end tests | Sanjith; shared | 5 | **Closed for automated fixture coverage.** CI runs lint and tests; generated-PCAP tests exercise Capture → Analysis → Storage → query/statistics/CSV export. |
| #15 | Sprint review/retrospective and process record | Vikas; shared | 2 | **Closed.** PR #26 merged the asynchronous evidence review and two Sprint 2 process actions. Historical actual effort was not captured; the gap is documented without invented values. This is not represented as a synchronous team meeting. |
| #16 | Repository configuration | Vikas | TBD | **GitHub issue closed; verify admin-only controls if still required.** Access, labels, milestones, CODEOWNERS and the existing board are recorded. Main branch protection and available security controls may still need a repository-admin UI action; this is process hardening, not missing application functionality. |

Issues #10 and #16 are currently closed in GitHub, although their descriptions document some manual/admin follow-up. Do not treat closure alone as proof that platform checks or repository settings were verified; Sprint 3 tracker #39 records the relevant completion gate.

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

**Main baseline before the compliance feature branch:** `6fdc3a70871f06ded17ee6c67d96e42fe95fa749` (PR #26 and Sprint 1 closeout documentation included).

**Baseline CI before PR #29:** [Run 40357674966](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40357674966) — Ruff passed and `pytest -q` reported **81 passed**. This is retained as the Sprint 1 baseline; the current main verification is recorded in the 2026-10-27 addendum below.

## Sprint 1 closeout decision

The **core Sprint 1 engineering goal is complete**. The implementation and automated integration path are merged; requirements and setup documentation are aligned with the latest code; the final CI run is green.

The following are **carry-over/release-readiness work**, not hidden blockers or falsely completed checks. PR #29 has since merged the backend SRS-completion work; the platform-specific checks listed here remain open:

| Carry-over | Status/action | Destination |
|---|---|---|
| #10 — live-interface/platform security | Run authorized live-interface startup/permission checks and target OS/driver/security checks; verify Windows ACLs, Wi-Fi mode/BLE support only if the platform is in scope, and Raspberry Pi performance if targeted. | M4 — Release Readiness |
| #16 — repository protection/security controls | If required by the team, maintainer should verify main-branch PR review, conversation resolution, the observed `Lint and test` check, and available secret-scanning/Dependabot controls. The issue is currently closed in GitHub; verify the settings directly before claiming completion. | M4 — Release Readiness / process follow-up |
| Report format | The approved SRS REQ-8 accepts CSV or PDF; main now provides both CSV and PDF export with session-scoped retrieval. | Implemented in PR #29; latest main CI passed (Ruff + 106 tests) |
| #13 and #14 | Both are low-priority stretch requirements in the SRS. Metadata-only alert events and concurrent capture, including synthetic fan-in tests and CLI wiring, are implemented on main. Live Wi-Fi/BLE adapter validation remains separate. | Merged in PR #29; latest main CI passed (Ruff + 106 tests); target-hardware validation pending |

## Sprint 2 focus

Several items originally planned for Sprint 2 were delivered early in PRs #19–#25. Focus new work on manual platform/security verification, any report format confirmed as mandatory, the carry-over settings, and the process improvements below. Do not duplicate completed implementation work.

## Process improvements for Sprint 2

1. **Contract-first cross-layer work.** Before parallel changes in Analysis/Storage/Presentation, write down the boundary contract and decide where the adapter belongs. **Accountable owner: Vikas; review partners: Shivanand and Shivakumara.** Check at the next cross-layer PR.
2. **Earlier integration-test and effort evidence.** For cross-layer tickets, add a generated-fixture end-to-end test before integration and record planned estimate plus actual effort (or explicitly record that actual effort was not captured) at issue close. **Accountable owner: Sanjith for test coordination; Vikas for the closeout checklist.** Check at the next sprint review.

The review/retrospective evidence and limitations are recorded in `Docs/SPRINT_1_REVIEW_RETROSPECTIVE.md`. The record is an asynchronous maintainer closeout from repository evidence, not a claim that a live team meeting or external stakeholder demo occurred.

## Addendum — 2026-10-27 backend SRS completion

PR #29 (`feat: complete SRS backend functionality and demo workflow`) has since been merged into `main` at `cd80e958bf572c32126c3f222579aec638da04b7`. It adds the remaining backend features described in `Docs/IMPLEMENTATION_GAP_AUDIT.md`, including PDF export, session-scoped retrieval, metadata-only heuristic alerts, concurrent capture, and synthetic demo/benchmark tooling.

Latest main CI run [40479490511](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40479490511) passed Ruff and **106 tests in 1.87 seconds**. This is automated evidence only. Live Wi-Fi monitor mode/BLE adapter behavior, Windows ACLs, Raspberry Pi throughput/drop performance, and real simultaneous multi-interface capture remain pending target-environment validation. The web dashboard is still deferred until final backend verification and is tracked in issue #27.


## Sprint 3 — Release readiness and project completion

**Coordinator issue:** [#39 — Sprint 3: Release readiness and project completion](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/39)

**Sprint goal:** close the remaining evidence-based acceptance gaps against SRS v1.3, STP v1.3, SASD Deliverable 3, and the project proposal. Keep Capture → Analysis → Storage → Presentation boundaries intact. Distinguish automated CI evidence from manual target-environment evidence.

### Sprint 3 backlog

| Work item | Scope / acceptance evidence | Priority / dependency |
|---|---|---|
| Parser edge-case regression tests | Finish [issue #37 / PR #38](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/pull/38); confirm current Ubuntu and Windows CI results and independent review before merge. | High; existing carry-over |
| Final backend acceptance gate | Continue [issue #28](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/28). Run authorized passive live-capture start/stop on the agreed target OS/interface and record permission/startup behavior. | High; required for full acceptance |
| Platform/security verification | Verify Windows ACL behavior only if Windows is a supported target. Validate Wi-Fi monitor mode and BLE capture only if those live capabilities will be claimed. Record PASS/FAIL/NOT RUN and exact environment; do not infer hardware support from parser fixtures. | Conditional on supported platform claims |
| Performance verification | If Raspberry Pi performance/no-drop is in scope, run `tools/benchmark_pipeline.py` on the target and separately measure live offered/received packets and available driver/kernel drop counters. Synthetic replay throughput is not proof of zero live packet loss. | Conditional on target/performance claim |
| End-to-end demo | Follow [Docs/DEMO_SCRIPT.md](DEMO_SCRIPT.md) from a clean setup: generate synthetic PCAP, replay/capture, query protocol/address, inspect statistics/alerts, export CSV and PDF, and exercise concurrent replay. Keep all traffic local and synthetic unless live capture is explicitly authorized. | High |
| Final evidence/documentation closeout | Update [Docs/REQUIREMENT_TRACEABILITY.md](REQUIREMENT_TRACEABILITY.md), [Docs/TEST_EXECUTION_REPORT.md](TEST_EXECUTION_REPORT.md), and the implementation-gap audit with actual commands, results, environment, linked CI/PR evidence, and remaining limitations. Review README/setup, safe-use guidance, local-only data handling, and SRS/SASD/STP consistency. | High; after test/demo results |
| Optional web dashboard | [Issue #27](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/issues/27) remains optional/stretch. Only continue after backend acceptance and if the team/instructor requires it. It must reuse existing layers, require explicit capture initiation, bind locally, and never upload packet data externally. | Stretch; not a blocker for the CLI SRS scope |

### Existing issues to close or update

- **#37 / PR #38:** finish review and CI; merge only after required checks pass.
- **#28:** remains the authoritative backend demo and target-environment verification gate. Do not close until agreed checks are completed or the supported scope is formally narrowed and documented.
- **#27:** optional dashboard; do not let it block core CLI acceptance unless explicitly required.
- **#39:** sprint coordinator issue; close only when all required Sprint 3 acceptance criteria have evidence.

### Definition of done

1. Required automated checks pass on the final candidate commit.
2. The synthetic end-to-end demo is reproducible and demonstrates query, statistics/alerts, CSV/PDF export, and concurrent replay.
3. Manual checks are recorded as PASS/FAIL/NOT RUN with OS, interface/adapter, driver, commands and results; no results are fabricated.
4. SRS REQ-1 through REQ-8 have implementation and test evidence; REQ-9/REQ-10 stretch status and hardware limits are explicit.
5. Wi-Fi, BLE, Windows, and Raspberry Pi claims do not exceed recorded verification.
6. Final traceability, test execution report, README and demo instructions agree with the implementation.

**Current known gap:** the repository documentation reports the backend and synthetic demo path merged, with main CI run [40479490511](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40479490511) passing Ruff and 106 tests. Actual live-interface/platform checks remain unverified. Re-check the latest CI and PR state at execution time rather than relying on this historical snapshot.
