# Storage Layer Unit Test Report

**Evidence revision:** source merged to `main` as `0839abf`
**Focused result:** **25 passed, 0 failed**
**CI:** [run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) succeeded on the merged source.

## Objective

Verify that analyzed packet records and raw packet bytes are stored locally, indexed safely, retrieved by query, and handled predictably on invalid/corrupt input.

## Test file and behaviors

Canonical module: `tests/test_storage_query.py`.

- PCAP and SQLite save/query round-trip; metadata schema and migration behavior.
- Session lookup, summaries, protocol/address/time filters, and inclusive time boundaries.
- Multiple link types, capture source metadata, and safe payload separation from SQLite metadata.
- Duplicate records, invalid filters/records, empty results, missing files, truncated PCAP, and malformed indexed rows.
- Relative Windows directory regression: changes CWD to `tmp_path`, creates a repository at `demo-captures`, saves a packet, queries it, and checks the database and PCAP are under the relative storage directory.
- SQLite read/write URI mode retains `mode=rw`; a missing metadata database is not silently recreated.

## Execution

```powershell
python -m pytest -q tests/test_storage_query.py
```

**Observed:** 25 passed in 2.60 seconds; 0 failed. The relative-path test is included in this run. This result is a subset of the full suite and is not an extra 25 tests to add to the overall count.

## Evidence

The historical storage screenshot is at `tests/docs/evidence/unit/storage/screenshots/01_storage_query.png`. Current evidence is the exact focused result above and merged cross-platform CI #731.

## Interpretation and limits

Storage tests use temporary local files; they do not prove Windows ACL configuration or protect files from a user who has access to the computer. Treat PCAP files and exported reports as sensitive. See [privacy guidance](../../../Docs/PRIVACY_GUIDELINES.md) and the [coverage report](../CODE_AND_BRANCH_COVERAGE_REPORT.md).
