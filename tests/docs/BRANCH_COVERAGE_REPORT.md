# Branch Coverage Report

**Measurement command:** the full Python suite with pytest-cov `--cov-branch`; see [code coverage report](CODE_COVERAGE_REPORT.md).

**Metric:** executed control-flow outcomes / measured outcomes. This helps find untested decisions that statement coverage can miss; it does not prove every possible runtime path is correct.

**Run:** Windows 11 workspace, Python 3.13.1, 2026-11-17; 171 passed and 2 platform-conditional tests skipped.

**Result:** 68.29% branch outcomes covered (519 / 760). There are 173 partially covered branches and 241 missed branch outcomes in the coverage.py report. This is a measured baseline, not a threshold. CI publishes the terminal summary and XML artifact for subsequent runs.

**Limit:** branch coverage is for `pocket_packet_sniffer` Python source. It does not measure JavaScript/React coverage, hardware behavior, or requirement coverage; use the RTM for requirement traceability.
