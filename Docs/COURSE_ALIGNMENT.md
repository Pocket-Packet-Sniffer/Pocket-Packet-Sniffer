# Course material alignment

This note connects the course topics used in the project to the approved SRS, implementation, and checked-in evidence. The original lecture decks are not copied into this public repository; the project SRS and Software Test Plan remain the controlled requirements sources.

## Unit 3 — Computer Networks

The reviewed Unit 3 Part 1 transport-layer material and Part 2 network-layer/IP material inform the packet fields and protocol coverage in the SRS. PocketSniff parses supported TCP, UDP, IPv4, IPv6, ARP, DNS, and related metadata. Tests cover parser behavior and edge cases in `tests/test_analysis_layer.py`, `tests/test_analysis_parser_edge_cases.py`, and `tests/test_session_integration.py`.

The product intentionally displays packet metadata only. It does not inspect or display application payloads or credentials. The project’s privacy boundary in the SRS takes precedence over broader protocol-analysis possibilities.

## Unit 4 — Software Engineering quality and verification

The reviewed Unit 4 material covers software quality metrics, system-testing levels, security/privacy, and validation:

| Course topic | Project evidence |
|---|---|
| Unit, component, integration, system, and acceptance testing | `tests/docs/unit/`, `tests/docs/COMPONENT_TEST_REPORT.md`, `tests/docs/SYSTEM_TEST_REPORT.md`, and this acceptance report |
| Smoke and sanity checks | `tests/docs/SMOKE_TEST_REPORT.md` and `tests/docs/SANITY_TEST_REPORT.md` |
| Regression, security, performance, and usability testing | `tests/docs/REGRESSION_TEST_REPORT.md`, `SECURITY_TEST_REPORT.md`, `PERFORMANCE_TEST_REPORT.md`, and `USABILITY_TEST_REPORT.md` |
| Validation against requirements | `Docs/REQUIREMENT_TRACEABILITY.md` and `tests/docs/VALIDATION_TEST_REPORT.md` |
| Statement and branch coverage | `tests/docs/CODE_COVERAGE_REPORT.md` and `tests/docs/BRANCH_COVERAGE_REPORT.md` |
| Privacy, consent, and safe data handling | `Docs/PRIVACY_GUIDELINES.md` and `tests/docs/SECURITY_TEST_REPORT.md` |

The coverage percentages are measured baselines, not proof of correctness or a minimum quality gate. Automated fixture/replay tests and a local live capture are reported separately; live BLE, Wi-Fi monitor mode, Windows ACL, and Raspberry Pi/drop-rate checks are not claimed unless evidence exists for the relevant hardware.

## Reference files reviewed

- Approved project SRS v1.3 and Software Test Plan v1.3, stored in this repository.
- Unit 3 transport-layer and network-layer/IP lecture material supplied locally for the course.
- Unit 4 Software Engineering lectures on quality metrics, security/privacy, system testing, and security validation supplied locally for the course.

The Unit 3 lecture materials are Computer Networks content; they are not a separate software-testing rubric. The Unit 4 testing taxonomy is reflected in the test hub and individual test reports.
