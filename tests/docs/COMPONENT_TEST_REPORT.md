# Component Test Report

**Evidence revision:** `main` commit `0839abf`; GitHub Actions [run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) passed.
**Full Python result:** 171 passed, 2 skipped, 0 failed. Component suites are included in that total; this report does not add overlapping test counts.

## Objective

Verify each project layer or service at its public boundary: valid inputs, rejected inputs, collaborator interactions, persistence contracts, and error translation between layers.

## Component map

| Component boundary | Executable evidence | Behaviors covered |
|---|---|---|
| Capture source and lifecycle | `tests/test_capture_layer.py`, `tests/test_capture_runner.py`, `tests/test_capture_control.py`, `tests/test_concurrent_capture.py` | Interface/source validation, replay, packet metadata propagation, typed errors, start/stop, cancellation and concurrent-source aggregation |
| Analysis parser/pipeline/statistics | `tests/test_analysis_layer.py`, `tests/test_analysis_parser_edge_cases.py`, `tests/test_analysis_pipeline.py`, `tests/test_analysis_statistics.py`, `tests/test_analysis_alerts.py` | Protocol metadata extraction, unsupported/malformed packets, pipeline dispatch/fallback, statistics and heuristic match/non-match cases |
| Storage repository | `tests/test_storage_query.py` | PCAP/SQLite persistence, relative Windows path behavior, migrations, session queries, address/protocol/time filters, corruption/error handling |
| API / agent | `tests/test_api.py`, `tests/test_agent.py` | HTTP request/response validation, filters/pagination, safe metadata responses, local agent health/configuration and origin checks |
| Presentation and architecture | `tests/test_presentation_dashboard.py`, `tests/test_presentation_report_export.py`, `tests/test_report_pdf.py`, `tests/test_architecture_boundaries.py` | Dashboard render/statistics, CSV/PDF output, layer dependency direction |
| Security contracts | `tests/test_security_contracts.py` | Passive-only source constraints and permission behavior on supported platforms |

## Verification and interpretation

All listed test modules run in the full passing Python suite and merged-main CI. A separately selected backend flow subset reported **34 passed**; details are in the [System Test Report](SYSTEM_TEST_REPORT.md). The focused layer results are in the [Unit Test Report](unit/UNIT_TEST_REPORT.md).

Unit and component tests use fixtures, temporary directories, and controlled collaborators. They verify software contracts but do not validate an OS driver, actual radio capabilities, real Windows ACL policy, physical multi-adapter capture, or target-hardware performance. The actual Windows Wi-Fi session is separate system acceptance evidence, reported in [ACCEPTANCE_TEST_REPORT.md](ACCEPTANCE_TEST_REPORT.md).

## Reproduction

Run all component and integration checks with `python -m pytest -q` at the repository root. Run the coverage variant with:

```powershell
python -m pytest -q --cov=pocket_packet_sniffer --cov-branch --cov-report=term-missing --cov-report=xml:coverage.xml
```

See the [coverage report](CODE_AND_BRANCH_COVERAGE_REPORT.md) for measured percentages and lower-coverage code paths. Coverage does not prove component correctness.
