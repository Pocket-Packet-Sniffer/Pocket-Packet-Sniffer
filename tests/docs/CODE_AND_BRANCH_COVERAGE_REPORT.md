# Code and Branch Coverage Report

**Project:** Pocket Packet Sniffer
**Measurement date:** 2026-11-18
**Source revision:** source tree merged to `main` as `0839abf9d102d0b4c1da4f0f58a205ef6d9a4525`
**Environment:** Windows 11, Python 3.13.1, pytest-cov / coverage.py
**CI:** [main run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) succeeded. CI runs the coverage-enabled Python suite on Ubuntu and Windows.

## Supplemental coverage run — 2026-11-19

After adding risk-focused tests for platform-specific agent startup, the abstract repository contract, live-capture configuration/startup/callback/radio-link handling, and API input/error boundaries, the local Windows suite reported **193 passed, 2 skipped, 0 failed**. This run is against the local working tree based on `main`; these changes have not been committed or run in GitHub CI yet.

| Metric | Covered | Measured | Result |
|---|---:|---:|---:|
| Python statements | 2,006 | 2,390 | **83.93%** |
| Python branch outcomes | 567 | 760 | **74.61%** |
| Partially covered branch points | 167 | — | At least one outcome ran and at least one did not |
| Uncovered branch outcomes | 193 | 760 | **25.39%** |
| Test outcome | 195 passed, 2 skipped | 197 collected | 0 failed |

The two skipped tests are POSIX permission-mode tests, which do not establish Windows ACL behavior. The selected low-coverage modules changed as follows:

| Module | Statements | Branches |
|---|---:|---:|
| `agent.py` | 96.88% (31/32) | 83.33% (5/6) |
| `storage/repository.py` | 100% (23/23) | 100% (4/4) |
| `api.py` | 79.14% (296/374) | 67.65% (69/102) |
| `capture/scapy_live.py` | 85.88% (152/177) | 73.08% (57/78) |
| `presentation/capture_control.py` | 75.15% (124/165) | 58.00% (29/50) |
| `storage/pcap_sqlite_repository.py` | 73.89% (300/406) | 72.88% (86/118) |

Coverage improved, but uncovered API, capture-control, and storage error paths remain. This run is evidence of executed tests, not a claim that every code path or hardware behavior is correct.

## Executive summary

| Metric | Covered | Measured | Result |
|---|---:|---:|---:|
| Python statements | 1,899 | 2,390 | **79.46%** |
| Python branch outcomes | 519 | 760 | **68.29%** |
| Partially covered branch points | 173 | — | At least one outcome ran and at least one did not |
| Uncovered branch outcomes | 241 | 760 | **31.71%** |
| Test outcome | 171 passed, 2 skipped | 173 collected | 0 failed |

The coverage.py combined percentage is displayed as 77% because that combined figure factors in branch opportunities. This report separates statement and branch percentages so the denominators are explicit. The two skipped tests exercise POSIX permission modes and are skipped on Windows; they do not test Windows ACLs.

## Scope and method

Coverage measures execution of the `pocket_packet_sniffer` Python package under this test suite. It does **not** measure frontend JavaScript/TypeScript, requirement completeness, runtime correctness, hardware behavior, security assurance, or whether every meaningful input has been tested. A covered line can still be incorrect; a missed line is a prompt to assess risk and test value, not an automatic defect.

Reproduce from the repository root:

```powershell
python -m pytest -q --cov=pocket_packet_sniffer --cov-branch --cov-report=term-missing --cov-report=xml:coverage.xml
```

The generated `coverage.xml` and `coverage.json` are local/CI measurement artifacts. The checked-in report records the measured snapshot; use the latest CI artifact for a future rerun rather than treating the percentages here as permanent.

## Lower-coverage modules to prioritize

| Module | Statement coverage | Branch coverage | Risk-oriented follow-up |
|---|---:|---:|---|
| `src/pocket_packet_sniffer/agent.py` | 56.25% (18/32) | 33.33% (2/6) | Add isolated tests for process launch, readiness timeout, already-running and cleanup/error paths |
| `src/pocket_packet_sniffer/storage/repository.py` | 60.87% (14/23) | 0% (0/4) | Exercise concrete repository adapter delegation and error/empty-result branches |
| `src/pocket_packet_sniffer/api.py` | 64.44% (241/374) | 45.10% (46/102) | Expand API route tests around startup, missing sessions, invalid input, error translation, and pagination boundaries |
| `src/pocket_packet_sniffer/capture/scapy_live.py` | 68.93% (122/177) | 48.72% (38/78) | Add mocked tests for device selection, permission/startup failures, stop/timeout, and callback exceptions |
| `src/pocket_packet_sniffer/presentation/capture_control.py` | 75.15% (124/165) | 60.00% (30/50) | Exercise request validation, state transitions, process cleanup, and repeated stop/start boundary cases |
| `src/pocket_packet_sniffer/storage/pcap_sqlite_repository.py` | 73.89% (300/406) | 72.88% (86/118) | Add targeted cases for migration/rollback, corrupt index/PCAP pairing, I/O failure cleanup, and boundary filters |

These are the lowest measured modules in the captured report, ordered by statement coverage. Prioritize by failure impact and testability; coverage percentage alone is not a ranking of software quality.

## Exclusions and limits

- No JavaScript/React coverage instrument is configured in this evidence set. The 13 Playwright tests are end-to-end behavior checks and do not provide frontend statement or branch percentages.
- Two Windows skips are POSIX permission-mode checks. Windows ACL behavior remains unverified.
- CI fixtures and mocks do not prove Wi-Fi monitor mode, BLE live scanning, physical multi-adapter capture, Raspberry Pi performance, or zero packet loss.
- Generated coverage artifacts can change when test dependencies or source change. Record revision, environment, command, pass/skip count, and artifact whenever refreshing this report.
- This is a descriptive baseline; no minimum coverage threshold is claimed or enforced by this report.

## Related evidence

- [Unit Test Report](unit/UNIT_TEST_REPORT.md)
- [System and Integration Test Report](SYSTEM_TEST_REPORT.md)
- [Acceptance Test Report](ACCEPTANCE_TEST_REPORT.md)
- [Test Execution Report](TEST_EXECUTION_REPORT.md)
- Legacy single-metric summaries: [statement coverage](CODE_COVERAGE_REPORT.md) and [branch coverage](BRANCH_COVERAGE_REPORT.md)
- Machine-readable local artifacts: `coverage.xml` and `coverage.json` (generated; do not commit as immutable proof without a revision label)
