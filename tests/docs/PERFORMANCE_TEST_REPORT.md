# Performance Test Report

**Current source:** `main` commit `0839abf`; CI [run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) passed.
**Target-hardware performance disposition:** NOT RUN.

## What is measured by the available tool

`tools/benchmark_pipeline.py` replays a generated five-packet PCAP fixture through parsing and local PCAP/SQLite persistence. It is useful for repeatable software-pipeline timing on the computer where it runs. `tests/test_benchmark_pipeline.py` validates benchmark accounting/session guards in the full Python suite.

The benchmark does **not** measure physical NIC receive capacity, packet drops, driver/kernel buffers, live offered traffic, or end-to-end performance on a Raspberry Pi. Its result must not be reported as live capture throughput or zero packet loss.

## Available benchmark command

The verified CLI is:

```powershell
python tools/benchmark_pipeline.py --repeats 1000 --storage-dir benchmark-captures --session-id pps-benchmark-2026-11-18
```

The command was checked with `--help`; a target benchmark was not executed for this report. Use a new session ID and a clean output directory for each run; do not overwrite existing capture data.

## Evidence matrix

| Claim | Status | Evidence / limitation |
|---|---|---|
| Benchmark tool accounting and session guard | **AUTOMATED TESTED** | `tests/test_benchmark_pipeline.py`, part of the full suite and CI #731 |
| Short live Wi-Fi activity | **OBSERVED** | One Windows run reported nonzero rates (14, 32, 4, 7, 30 packets/s) and saved 175/175 packets; this is not a controlled performance test |
| Sustained high-rate capture | **NOT RUN** | No controlled offered-rate/duration/load sweep |
| Raspberry Pi throughput | **NOT RUN** | No board model/OS/storage/driver run or performance result recorded |
| Live NIC/kernel packet-drop counters | **NOT RUN** | No platform counters collected; 175/175 saved does not prove no upstream drops |

## Protocol for a valid target measurement

Record board and OS, Python version, adapter/model and driver, storage media, power/thermal conditions, command, repetition count, elapsed time, offered/observed/stored packet counts, and any NIC/kernel drop counters before making a performance claim. Keep synthetic replay and live measurements in separate tables. See issue #28 and the [acceptance report](ACCEPTANCE_TEST_REPORT.md) for open hardware gates.
