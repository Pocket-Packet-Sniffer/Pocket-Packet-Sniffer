# Performance Test Report

**Available tool:** `tools/benchmark_pipeline.py` measures synthetic PCAP replay through parsing and local persistence on the machine where it runs. `tests/test_benchmark_pipeline.py` verifies benchmark accounting and session guards.

**Result:** benchmark tool behavior is covered by the automated suite. A current Raspberry Pi throughput run, live offered/received packet measurement, and NIC/kernel drop-counter result are **NOT RUN / NOT RECORDED**. Synthetic replay throughput is not evidence of zero live packet loss.

Run the benchmark only on the approved target and record the board, OS, Python version, storage device, command, repetitions, elapsed time, packets stored, and any available live drop counters before making a target-performance claim.
