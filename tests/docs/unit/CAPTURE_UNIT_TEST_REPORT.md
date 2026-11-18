# Capture Layer Unit Test Report

**Evidence revision:** source merged to `main` as `0839abf`
**Focused result:** **42 passed, 0 failed**
**CI:** [run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) passed on Windows and Ubuntu.

## Objective

Verify capture-source contracts and lifecycle without relying on a physical adapter: replay, packet metadata, source validation, typed errors, start/stop, and concurrent fan-in.

## Test modules and cases

| Test module | Test focus |
|---|---|
| `tests/test_capture_layer.py` | Classic PCAP replay, timestamps/link types, packet limits, stop signals, malformed/truncated captures, Scapy backend selection, interface resolution, startup/permission/callback errors, and validation |
| `tests/test_concurrent_capture.py` | Multiple backend fan-in, source metadata, aggregate packet limits, invalid backend configuration, failures, and clean interruption |

## Execution

```powershell
python -m pytest -q tests/test_capture_layer.py tests/test_concurrent_capture.py
```

**Observed:** 42 passed in 1.18 seconds; 0 failed. This focused count is included in the full Python suite and must not be added to it.

## Evidence

Supporting screenshots are stored in `tests/docs/evidence/unit/capture/`. They show selected historical module runs. The current suite/CI result is the authoritative execution evidence.

## Interpretation and limits

Mocked capture tests do not prove a specific adapter, driver, permission level, Wi-Fi monitor mode, live BLE, physical multi-adapter behavior, sustained throughput, or packet-loss performance. The separate real Wi-Fi acceptance run saved 175 of 175 packets on one Windows computer; see the [system report](../SYSTEM_TEST_REPORT.md). Windows permission tests do not establish Windows ACL configuration.
