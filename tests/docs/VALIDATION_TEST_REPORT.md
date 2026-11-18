# Validation Test Report

**Source of requirements:** approved SRS v1.3 and STP v1.3.
**Current implementation:** `main` commit `0839abf`; post-merge CI [run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) succeeded.

## Validation objective

Check that accepted inputs produce the specified packet metadata and outputs, invalid inputs produce controlled errors, and reported test status agrees with the SRS/STP evidence. This report distinguishes code/test validation from target-hardware acceptance.

## Automated validation coverage

| Validation target | Test evidence | Result |
|---|---|---|
| Capture source/interface validation and failures | `tests/test_capture_layer.py`, `test_capture_runner.py`, `test_capture_control.py` | Passed in the full Python suite; actual driver/permission failure was not induced on the acceptance computer |
| Parser input acceptance and rejection | `tests/test_analysis_layer.py`, `test_analysis_parser_edge_cases.py` | Supported protocols/metadata and malformed/unsupported inputs exercised using test packets |
| Storage path, schema, and query validation | `tests/test_storage_query.py` | Relative Windows path regression, missing/invalid data, migration, filters and session lookups exercised |
| CLI and API request validation | `tests/test_cli.py`, `tests/test_api.py` | Invalid options, time/address/protocol parameters, routes and safe metadata behavior exercised |
| Passive-only and origin contracts | `tests/test_security_contracts.py`, API origin test | Automated guards pass as part of CI; not a penetration test |
| SRS requirement disposition | `Docs/REQUIREMENT_TRACEABILITY.md`, `ACCEPTANCE_TEST_REPORT.md` | Every core/stretch requirement has an implementation/evidence status and limits |
| Real supported-path validation | Windows passive Wi-Fi session | 175 real packets seen/stored, 0 ignored; clean stop, 175 queried records, CSV/PDF returned HTTP 200 |

## Results

The full Python suite reported **171 passed, 2 skipped**; the skips are POSIX file-mode checks and do not validate Windows ACLs. The post-merge cross-platform workflow passed. The real capture demonstrates ordinary Wi-Fi operation on one Windows computer, not every adapter or feature described by the original SRS.

## Acceptance boundaries

**NOT RUN / NOT IMPLEMENTED:** Wi-Fi monitor mode on compatible hardware, live BLE scanning (not implemented in the current Windows agent), Windows ACL review, Raspberry Pi throughput and live NIC/kernel drop counters, and simultaneous physical-adapter capture. No user study or formal accessibility audit is recorded. See the [acceptance report](ACCEPTANCE_TEST_REPORT.md) and [SRS gap audit](../../Docs/IMPLEMENTATION_GAP_AUDIT.md).

## Reproduction

Run `python -m pytest -q` at the repository root. For full requirement disposition and evidence IDs, see [Requirement Traceability](../../Docs/REQUIREMENT_TRACEABILITY.md). A passing suite is implementation validation, not a substitute for outstanding target-environment checks.
