# Analysis Layer Unit Test Report

**Evidence revision:** source merged to `main` as `0839abf`
**Focused result:** **45 passed, 0 failed**
**CI:** [run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) passed on the merged source.

## Objective

Check that supported packet inputs become consistent metadata and that pipeline, statistics, and alert components behave correctly for valid, invalid, and incomplete records.

## Test modules and cases

| Test module | Test focus |
|---|---|
| `tests/test_analysis_layer.py` | Protocol and header parsing for supported packet types, address/port/size/timestamp extraction, protocol classification, and malformed/unsupported input behavior |
| `tests/test_analysis_parser_edge_cases.py` | IPv6 TCP/UDP, ICMPv6, generic Ethernet frames, metadata preservation, unknown link types, and empty packet bytes |
| `tests/test_analysis_pipeline.py` | Analyzer ordering/selection, fallback behavior, declined packets, and invalid analyzer configuration |
| `tests/test_analysis_statistics.py` | Packet/byte totals, rate windows, protocol distribution, top talkers, and invalid windows |
| `tests/test_analysis_alerts.py` | ARP conflict and allowlist indicators, missing metadata, alert publishing, observer errors, subscriptions, and allowlist validation |

Some parser inputs describe Wi-Fi/BLE link-layer records supplied as test/PCAP data. This verifies parser behavior only; it does not show the sensor can scan Wi-Fi monitor mode or BLE radios.

## Execution

Run from the repository root on Windows:

```powershell
python -m pytest -q tests/test_analysis_layer.py tests/test_analysis_parser_edge_cases.py tests/test_analysis_pipeline.py tests/test_analysis_statistics.py tests/test_analysis_alerts.py
```

**Observed:** 45 passed in 1.68 seconds; 0 failed. This is a selected unit-group run, overlapping with the full suite (171 passed, 2 skipped); do not add the counts together.

## Evidence

Supporting historical screenshots are stored in `tests/docs/evidence/unit/analysis/`: parser, edge-case, pipeline, statistics, and alert runs. These images are supplementary; the command result and CI are current pass/fail evidence.

## Interpretation and limits

The result verifies the exercised parser and analyzer scenarios. It does not prove protocol completeness or detection of every malicious packet. Alert rules are heuristics, not proof of compromise or safety. See the [coverage report](../CODE_AND_BRANCH_COVERAGE_REPORT.md) for untested Python statements/branches and the [acceptance report](../ACCEPTANCE_TEST_REPORT.md) for hardware limits.
