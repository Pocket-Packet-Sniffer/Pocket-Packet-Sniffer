# Sprint 1 Review and Retrospective — Draft for Team Confirmation

**Prepared:** 2026-10-26  
**Status:** Evidence summary prepared; team review/retrospective not yet confirmed. Do not treat the proposed observations or actions below as team consensus until discussed and accepted.

## 1. Sprint goal

Establish the repository workflow and CI, implement passive raw packet capture and analysis, persist packet data and searchable metadata, and deliver a repeatable end-to-end fixture path.

## 2. Verified delivery

| Delivery | Evidence |
|---|---|
| Capture contract, PCAP replay, passive Scapy backend | PR #17 |
| Process/workflow and traceability baseline | PR #18 |
| PCAP/SQLite Storage and query functions | PR #19 |
| Presentation statistics renderer | PR #20 |
| Local CSV session report export | PR #21 |
| Stable capture error handling and POSIX permission checks | PR #22 |
| Packet Analysis parser and controlled protocol tests | PR #23 |
| Application session, explicit Analysis-to-Storage adapter, traffic statistics, CLI and generated-PCAP end-to-end tests | PR #24 |
| Latest CI on main | [Run 40353363252](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40353363252): Ruff passed; 81 tests passed |

The CI suite uses generated packets and mocks; it does not substitute for a real live-interface, Windows ACL, Wi-Fi monitor-mode, BLE, or Raspberry Pi validation.

## 3. Items carried forward

- **Issue #10:** authorized live-interface and target-platform security/portability verification; Windows ACL and target-hardware performance checks.
- **Issue #16:** enable/verify main branch protection, required successful CI check, conversation resolution and available secret-scanning/Dependabot controls in GitHub Settings.
- **Report format:** current CLI provides CSV. Confirm whether PDF is explicitly required by the approved SRS; implement it only if required.
- **Stretch issues #13 and #14:** remain outside the committed Sprint 1 scope.

## 4. Team review — fill in during the review

- Review/demo date and attendees: **[team to fill in]**
- What the team demonstrated: **[team to confirm; CI evidence above is available]**
- Stakeholder/evaluator feedback: **[team to fill in, or write “none received” if accurate]**
- What was accepted: **[team to confirm]**
- What was not accepted or remains incomplete: **[review and carry-over list above; team to confirm]**

## 5. Retrospective — discussion prompts, not pre-filled team conclusions

These are candidate observations based on repository history. Discuss them as a team before recording them as the retrospective outcome:

- **Candidate improvement A:** agree cross-layer record/interface contracts before parallel layer work; the Analysis and Storage record types required an explicit application adapter.
- **Candidate improvement B:** build one generated-fixture end-to-end test earlier, so integration mismatches are found before the end of the sprint.
- Agreed improvement(s): **[team to choose and edit]**
- Owner(s): **[team to assign]**
- When/how the team will check improvement: **[team to agree]**

## 6. Estimate versus actual

Record actual effort only from the team's own notes or recollection; do not infer person-hours from commit counts.

| Work item | Estimate (points) | Actual effort / variance | Notes |
|---|---:|---|---|
| #1, #3, #4, #5, #9, #10, #11, #15, #16 | See issue/sprint plan | **[team to fill in]** | Use story points and effort units consistently; do not equate them automatically. |

## 7. Closeout decision

- Core implementation: delivered and merged to main; latest main CI passed with 81 tests.
- Sprint review and retrospective: **pending team confirmation**.
- Carry-over: #10 and #16, plus the PDF decision if the approved SRS requires it.
- Do not mark Issue #15 complete until sections 4–6 reflect the actual team discussion.
