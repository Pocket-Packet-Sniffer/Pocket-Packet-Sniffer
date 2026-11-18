# Sanity Test Report

**Purpose:** run a small, high-value check after a focused change to confirm its primary path still works. Sanity runs are subsets and overlap with the full test suite; they are not additional unique tests.

## Recorded checks

| Check | Command / environment | Result |
|---|---|---|
| Relative-path persistence/query | `python -m pytest -q tests/test_storage_query.py`, Windows | **25 passed** |
| API routes and validation | `python -m pytest -q tests/test_api.py`, Windows | **10 passed** |
| Dashboard static type-check | `npm run typecheck`, `web/` | **PASS**; TypeScript completed without diagnostics |
| Full Python suite | `python -m pytest -q` with pytest-cov, Windows | **171 passed, 2 skipped** |
| Merged CI | GitHub Actions [run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) | **Success** on merged `main` |

The first two focused runs were recorded during the final documentation/evidence pass. The dashboard type-check, full suite, and coverage run were also repeated for the release candidate before merge. See [Test Execution Report](TEST_EXECUTION_REPORT.md) for complete commands, exact results, and caveats.

## Repeatable commands

```powershell
python -m pytest -q tests/test_storage_query.py
python -m pytest -q tests/test_api.py
```

```powershell
cd web
npm run typecheck
```

## Limits

Sanity checks exercise selected software paths only. They do not prove live adapter operation or cover hardware-specific Wi-Fi monitor mode, BLE radio scanning, Windows ACL behavior, Raspberry Pi performance, or packet-drop rates. The local 175-packet Wi-Fi capture is a separate system acceptance result.
