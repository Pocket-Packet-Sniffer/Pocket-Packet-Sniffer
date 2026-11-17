# Storage Layer - Unit Testing

## 1. Objective

Unit testing was performed to verify packet persistence, metadata indexing, retrieval, session summaries, validation, and storage error handling.

## 2. Test File

**File:** `tests/test_storage_query.py`

The 25 test executions cover:

- Saving packet records to PCAP files and restoring them through repository queries.
- Protocol, address, session, and inclusive time-window filtering.
- Session listing and summary statistics, including empty sessions.
- Duplicate record rejection and invalid record/filter validation.
- Multiple link types and capture-backend metadata preservation.
- Missing PCAP/metadata files, truncated PCAP data, and malformed indexed metadata.
- Permission failures during reads and writes.
- Keeping packet payload bytes out of SQLite metadata.

## 3. Execution Summary

Command: `pytest tests/test_storage_query.py -v`

- Total test executions: 25
- Passed: 25
- Failed: 0
- Execution time: 2.18 seconds
- Environment: Windows, Python 3.13.15, pytest 8.3.4

## 4. Screenshot Evidence

Expected evidence location: `tests/docs/evidence/unit/storage/`

- `01_storage_query.png`

## 5. Conclusion

All 25 selected Storage Layer test executions passed. The results verify the tested PCAP/SQLite persistence and retrieval behavior, query filters, session summaries, validation, and storage failure handling.
