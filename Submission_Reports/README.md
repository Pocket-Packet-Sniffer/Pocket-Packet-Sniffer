# Pocket Packet Sniffer — Submission Reports

This index contains the six reports requested for the project submission. The three approved design/requirements documents are preserved in their original PDF form; the three execution/quality reports are maintained as Markdown so GitHub can display and diff them. All files linked here are tracked in this repository. Click a link to view it in GitHub, or use GitHub's **Download raw file** action for a local copy.

## Required six reports

| # | Required report | Project file | Contents / evidence status |
|---:|---|---|---|
| 1 | Software Requirements Specification (SRS) | [Pocket Packet Sniffer SRS v1.3 (PDF)](../Docs/Pocket_Packet_Sniffer_SRS%20.pdf) | Approved requirements baseline. Current verification status and limitations are cross-referenced in the [acceptance report](../tests/docs/ACCEPTANCE_TEST_REPORT.md); the PDF is retained unchanged. |
| 2 | Software Test Plan (STP) | [Pocket Packet Sniffer Software Test Plan v1.3 (PDF)](../Docs/Pocket_Packet_Sniffer_Software_Test_Plan.pdf) | Approved test strategy and cases. A byte-identical copy is retained at `tests/docs/test-plan/`; use the `Docs/` copy as the canonical submission link. |
| 3 | Software Architecture and Design Specification (SASD) | [Pocket Packet Sniffer SASD (PDF)](../Docs/Pocket_Packet_Sniffer_SASD.pdf) | Approved architecture/design document; implementation and test boundaries are summarized in the [architecture overview](../README.md#architecture). |
| 4 | Unit Test Report | [Unit Test Report](../tests/docs/unit/UNIT_TEST_REPORT.md) | 134 focused layer-group tests run: 45 analysis, 42 capture, 25 storage, 22 presentation; all passed. Full-suite totals are reported separately to avoid double counting. |
| 5 | System Test Report | [System and Integration Test Report](../tests/docs/SYSTEM_TEST_REPORT.md) | Backend connected-flow tests, 13 browser tests, cross-platform CI, and an actual authorized Wi-Fi capture with 175/175 packets stored. Explicit hardware limits are included. |
| 6 | Code and Branch Coverage Report | [Code and Branch Coverage Report](../tests/docs/CODE_AND_BRANCH_COVERAGE_REPORT.md) | 79.46% Python statement coverage and 68.29% branch coverage with denominators, lower-coverage modules, follow-up priorities, and limits. |

## Current release evidence

- Merged source revision: `0839abf9d102d0b4c1da4f0f58a205ef6d9a4525` on `main`.
- GitHub Actions [main run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089): success on the merged commit.
- GitHub Actions [PR run #730](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44363778707): success for the reviewed source change before squash merge.
- Windows suite: **171 passed, 2 skipped**; the skipped POSIX mode tests do not establish Windows ACL behavior.
- Dashboard: type-check, optimized build, and **13 Playwright tests passed**.
- Actual authorized Windows Wi-Fi capture: **175 seen, 175 stored, 0 ignored**, clean stop; session query returned 175 records; CSV and PDF exports succeeded.
- Production dashboard: HTTP 200. Capture/API and packet storage remain local to the operator's computer.

## Read this before making claims

These reports support a working passive local sniffer for the verified ordinary Wi-Fi path and exercised software flows. They do not claim full hardware acceptance. Live BLE scanning is not implemented in the current Windows sensor; Wi-Fi monitor mode, Windows ACL verification, Raspberry Pi performance/drop measurements, and simultaneous physical-adapter capture remain unverified. Suspicious-activity alerts are heuristic investigation signals, not proof of malicious activity.

For detailed requirement disposition use the [SRS acceptance report](../tests/docs/ACCEPTANCE_TEST_REPORT.md). For the live-traffic presentation flow use the [demo guide](../Docs/DEMO_SCRIPT.md). For the full project test catalog and run commands use the [test hub](../tests/README.md).
