# Code Coverage Report

**Measurement command:** `python -m pytest -q --cov=pocket_packet_sniffer --cov-branch --cov-report=term-missing --cov-report=xml:coverage.xml`.

**Metric:** statement coverage (executed statements / measured statements). Coverage describes execution by this suite; it does not establish correctness or requirement acceptance.

**Run:** Windows 11 workspace, Python 3.13.1, 2026-11-17; 171 passed and 2 platform-conditional tests skipped.

**Result:** 79.46% statement coverage (1,899 / 2,390 statements). The combined coverage.py display is 77% because it includes branch outcomes. See the [branch coverage report](BRANCH_COVERAGE_REPORT.md) for decision coverage.

The same command is added to CI so future results are reproducible. This is a measured baseline, not a quality threshold.

**Policy:** no minimum percentage is asserted until the repository has a reviewed baseline and an agreed threshold. Missing/untested code paths remain visible in the generated report.
