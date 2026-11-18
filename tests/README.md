# Pocket Packet Sniffer — Test Hub

This is the project’s test source and test evidence index. Executable Python tests remain directly under `tests/` with their established `test_*.py` names; documentation, plans, and screenshots live under `tests/docs/` and are not collected by pytest.

## Run the checks

From the repository root:

```powershell
ruff check --select E4,E7,E9,F,I src tests tools
python -m pytest -q
python -m pytest -q --cov=pocket_packet_sniffer --cov-branch --cov-report=term-missing --cov-report=xml:coverage.xml
```

For the web dashboard:

```powershell
cd web
npm ci
npm run typecheck
npm run build
npm run test:e2e -- --workers=2
```

CI runs lint and the Python suite on Ubuntu and Windows, then type-checks/builds the dashboard and runs its browser tests. The Windows agent release workflow also runs the Windows regression subset, packages the executable, and starts it for an HTTP health smoke check.

## Test levels and types

| Test level/type | Executable evidence | Report/status |
|---|---|---|
| Unit | Parser, analyzer, statistics, capture, repository, and presentation tests | [Unit test report](docs/unit/UNIT_TEST_REPORT.md) |
| Component | Layer/API contracts, repository adapters, capture runner, and architecture boundaries | [Component test report](docs/COMPONENT_TEST_REPORT.md) |
| Integration and system | Capture → analysis → storage → query/report flow; API and CLI flows; dashboard browser flows | [System test report](docs/SYSTEM_TEST_REPORT.md) |
| Acceptance | SRS/STP requirement mapping and dashboard acceptance flows | [Acceptance test report](docs/ACCEPTANCE_TEST_REPORT.md); physical target acceptance remains pending |
| Regression | Fixed defects and repeated Python/browser regressions | [Regression test report](docs/REGRESSION_TEST_REPORT.md) |
| Smoke and sanity | Packaged agent startup/health check; focused post-change checks | [Smoke test report](docs/SMOKE_TEST_REPORT.md), [sanity test report](docs/SANITY_TEST_REPORT.md) |
| Validation and security | Requirement/contract validation, passive-only and local-origin checks | [Validation report](docs/VALIDATION_TEST_REPORT.md), [security test report](docs/SECURITY_TEST_REPORT.md) |
| Coverage | Python statement and decision/branch measurement with pytest-cov | [Code coverage](docs/CODE_COVERAGE_REPORT.md), [branch coverage](docs/BRANCH_COVERAGE_REPORT.md) |
| Performance and usability | Synthetic replay benchmark and responsive/browser behavior | [Performance report](docs/PERFORMANCE_TEST_REPORT.md), [usability report](docs/USABILITY_TEST_REPORT.md); real target performance and user study are not claimed |

## Evidence and source material

- [Test execution report](docs/TEST_EXECUTION_REPORT.md) contains dated run results, CI links, traceability, and explicit limitations.
- [Software Test Plan v1.3](docs/test-plan/Pocket_Packet_Sniffer_Software_Test_Plan.pdf) is the preserved source plan.
- [Unit screenshots](docs/evidence/unit/) are supporting evidence, not substitutes for test output.
- The canonical implementation tests are the `tests/test_*.py` files. Former duplicate capture test copies were identical to the canonical files and have been consolidated.
- Course alignment is summarized in [Docs/COURSE_ALIGNMENT.md](../Docs/COURSE_ALIGNMENT.md). It maps Unit 3 network-layer/transport-layer learning to parser coverage and Unit 4 testing, security, validation, and quality-metric topics to the existing reports. The original course slides are reference material and are not redistributed in this repository; the approved SRS v1.3 and STP v1.3 are checked in as the project requirements and plan.

## Evidence rules

Every report distinguishes **PASS**, **FAIL**, and **NOT RUN**. Fixture/replay coverage does not prove live hardware behavior. Do not mark Wi-Fi monitor mode, BLE radio capture, Windows ACLs, Raspberry Pi performance, packet-loss behavior, or physical live-interface acceptance as passed without environment-specific evidence.
