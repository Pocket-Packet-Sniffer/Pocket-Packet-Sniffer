# Sprint 1 Review and Retrospective — Closeout Record

**Prepared:** 2026-10-26  
**Review method:** Maintainer-led asynchronous review of merged pull requests, issue status, project documentation, and GitHub Actions evidence.  
**Repository maintainer:** Vikas Kulakarni.  
**Important scope note:** No synchronous team meeting, attendee list, external evaluator feedback, or live-interface demo is recorded in the repository. This closeout does not claim those events occurred.

## 1. Sprint goal

Establish the repository workflow and CI, implement passive raw packet capture and analysis, persist packet data/searchable metadata, and deliver a repeatable end-to-end fixture path.

**Outcome:** the core engineering goal is delivered. PR #24 integrates Capture → Analysis → Storage → CLI and generated-PCAP end-to-end tests. PR #25 updates the implementation and traceability records.

## 2. Verified review evidence

| Delivery | Evidence |
|---|---|
| Capture contract, classic-PCAP replay, passive Scapy backend | PR #17 |
| Workflow/process and traceability baseline | PR #18 |
| PCAP/SQLite storage and query functions | PR #19 |
| Statistics renderer | PR #20 |
| Local CSV session-report exporter | PR #21 |
| Stable capture error handling and POSIX permission checks | PR #22 |
| Packet Analysis parser and controlled protocol tests | PR #23 |
| Application session, Analysis-to-Storage adapter, rolling statistics, CLI, architecture checks and generated-PCAP end-to-end tests | PR #24 |
| Closeout documentation, RTM and this review record | PR #25 |
| Latest CI on main | [Run 40357674966](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40357674966): Ruff passed; pytest reported **81 passed** |

### Demonstration record

- **Automated demonstration evidence:** generated PCAP is processed through Capture → Analysis → Storage, then queried and used for statistics/CSV report output. See `tests/test_session_integration.py` and `tests/test_cli.py`.
- **Live demonstration:** no live-interface demonstration is evidenced by CI or repository records; do not claim one was performed.
- **External/stakeholder feedback:** none is recorded in the repository. This means "not recorded", not proof that no feedback was ever given.
- **Accepted software outcome:** core capture-to-storage and CLI fixture path merged to `main`; current CI is green.
- **Not claimed as verified:** authorized live interface behaviour on every target OS/driver, Windows ACLs, Wi-Fi monitor mode, BLE, Raspberry Pi performance, or PDF report output.

## 3. Work carried forward

- **Issue #10 — Security/portability:** authorized live-interface startup/permission checks and target-platform security/performance verification remain M4 work.
- **Issue #16 — Repository settings:** branch protection, required status check and available security settings remain a repository-admin action in GitHub Settings.
- **Report format:** current CLI implements CSV. Confirm the approved SRS output format before making a PDF-support claim; implement PDF only if it is required.
- **Stretch issues #13/#14:** suspicious-activity alerts and concurrent capture backends remain outside the committed core sprint scope.

## 4. Retrospective findings and assigned improvements

These are the maintainer's closeout decisions based on the work history. They are not presented as votes or comments from teammates who have not left a recorded review.

| Finding | Concrete action for Sprint 2 | Accountable owner | How to verify |
|---|---|---|---|
| The Analysis and Storage record classes have different responsibilities; an explicit application adapter was needed to preserve raw packet bytes without reversing layer dependencies. | Write cross-layer contracts/adapter boundaries before parallel layer changes and record material decisions in an ADR. | Vikas Kulakarni; review partners Shivanand and Shivakumara GP | Next cross-layer PR links a contract/ADR or explains why none is required. |
| Integration proof arrived after separate layer tests; actual effort was not consistently recorded, so Sprint 1 estimate-vs-actual variance cannot be reconstructed. | Add a generated-fixture end-to-end test early for cross-layer work and record planned points plus actual effort (or explicitly record missing actuals) when closing an issue. | Sanjith R for integration-test coordination; Vikas Kulakarni for the closeout checklist | Next sprint's cross-layer ticket includes an e2e test before merge and an effort/variance entry at review. |

## 5. Estimate versus actual effort

The sprint plan recorded story-point estimates for the scoped issues. Historical person-hours/actual effort were not recorded consistently in the repository, so **no reliable estimate-versus-actual variance can be reported for Sprint 1**. No person-hours have been inferred from commit counts.

This is recorded as a process gap, with the second retrospective action above: capture actual effort or explicitly mark it unavailable at issue close starting in Sprint 2.

## 6. Closeout decision

- **Core implementation:** complete and merged to `main`.
- **Automated verification:** latest main CI passed; 81 tests passed.
- **Documentation/traceability:** current in PR #25 on main.
- **Carry-over:** #10 and #16 remain open for release/repository checks. #13/#14 remain stretch; PDF is a follow-up only if required by the approved SRS.
- **Process decision:** use the two maintainer-selected improvements above for Sprint 2 planning. Review partners may revise them at kickoff.
- **Limitations:** this is an asynchronous evidence-based maintainer review; it does not claim a synchronous team meeting or a live-network demo. The lack of actual effort data is explicitly preserved rather than fabricated.
