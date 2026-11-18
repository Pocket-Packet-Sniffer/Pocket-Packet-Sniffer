# Pocket Packet Sniffer — Testing Evidence Report

## Evidence scope
This package contains original terminal/desktop screenshots supplied during the testing rerun, saved as PNG files. The screenshots have been preserved as evidence; they have not been recreated from text output.

## Test results

| Test area | Command / activity | Result |
|---|---|---:|
| Full Python test suite | `python -m pytest -v` | 171 passed, 2 skipped, 1 warning |
| Capture component | `python -m pytest tests/test_capture_layer.py -v` | 37 passed |
| Analysis component | `python -m pytest tests/test_analysis_layer.py tests/test_analysis_pipeline.py tests/test_analysis_statistics.py -v` | 22 passed |
| Storage component | `python -m pytest tests/test_storage_query.py -v` | 25 passed |
| Presentation component | `python -m pytest tests/test_presentation_dashboard.py tests/test_presentation_report_export.py tests/test_report_pdf.py -v` | 22 passed |
| System integration | `python -m pytest tests/test_session_integration.py -v` | 1 passed |
| API and CLI | `python -m pytest tests/test_api.py tests/test_cli.py -v` | 19 passed, 1 warning |
| Sanity — storage | `python -m pytest -q tests/test_storage_query.py` | 25 passed |
| Sanity — API | `python -m pytest -q tests/test_api.py` | 10 passed, 1 warning |
| Frontend TypeScript | `npm run typecheck` in `web` | User confirmed command returned to prompt without diagnostics; screenshot captures command start only |
| White-box / coverage | `python -m pytest -q --cov=pocket_packet_sniffer --cov-branch --cov-report=term-missing --cov-report=xml:coverage.xml` | 171 passed, 2 skipped, 1 warning |
| Statement coverage | Read from `coverage.xml` | 79.46% |
| Branch coverage | Read from `coverage.xml` | 68.29% |
| Frontend production build | `npm run build` in `web` | Compilation, TypeScript, static generation (3/3), and optimization completed successfully |
| Browser end-to-end | `npm run test:e2e -- --workers=2` | 11 passed |
| Ruff lint | `ruff check --select E4,E7,E9,F,I src tests tools` | All checks passed |

## Notes and limitations
- The full Python suite reported 2 skipped tests. The skips concern POSIX permission-mode behavior that does not apply directly on Windows; this run does not establish Windows ACL security behavior.
- The Starlette warning reports that using `httpx` with `starlette.testclient` is deprecated and recommends `httpx2`. It did not cause the displayed tests to fail.
- The frontend typecheck screenshot shows `tsc --noEmit` starting. The user confirmed that the command completed and returned to the PowerShell prompt without errors; the screenshot does not independently show the completion prompt.
- The production-build screenshot shows successful compilation, TypeScript, static page generation, and final optimization, but not the returned shell prompt.
- These results demonstrate the tests that were run in the supplied Windows development environment. They do not by themselves prove live packet capture on every physical adapter, Wi-Fi monitor-mode support, BLE radio capture, performance on Raspberry Pi hardware, or zero packet loss under live traffic.
- Component and sanity test runs overlap with the full test suite; do not add their counts together as a unique total.

## Evidence authenticity
PNG files in this package are copies of the screenshots supplied in this conversation. The report summarizes the visible results and the user's confirmation where noted. No synthetic terminal screenshots have been created.
