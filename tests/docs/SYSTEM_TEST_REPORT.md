# System and Integration Test Report

**Project:** Pocket Packet Sniffer
**Evidence date:** 2026-11-18
**Merged source:** `main` commit `0839abf9d102d0b4c1da4f0f58a205ef6d9a4525` (PR #60)
**Cross-platform CI:** [GitHub Actions run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089), conclusion **success** on the merged commit.

## Objective

System tests verify behavior across connected project boundaries, from capture inputs through analysis, local storage, query/statistics, API/CLI presentation, and report export. Browser end-to-end tests verify user-facing flows. The real-interface acceptance run separately checks that the local Windows sensor can observe and persist authorized Wi-Fi traffic.

## Results summary

| Evidence group | Environment / command | Result | What it proves |
|---|---|---|---|
| Backend system-flow subset | Windows 11, Python 3.13.1; `python -m pytest -q tests/test_session_integration.py tests/test_api.py tests/test_cli.py tests/test_capture_control.py tests/test_capture_runner.py tests/test_agent.py` | **34 passed** in 3.28 s | Connected API, CLI, capture lifecycle, session integration, and agent behavior for controlled test inputs |
| Full Python suite | Windows 11; `python -m pytest -q` with coverage options | **171 passed, 2 skipped** | Full backend regression set; skips are POSIX mode checks and do not verify Windows ACLs |
| Dashboard user-flow suite | Chromium; `npm run test:e2e -- --workers=1` | **13 passed** in 31.5 s | Onboarding/offline states, privacy and capability guidance, capture controls, map-address filtering, packet inspection, replay, CSV/PDF downloads, and mobile layout |
| GitHub CI | Windows + Ubuntu + dashboard job, run #731 | **Success** | CI lint/tests, Python checks on both OSes, frontend type-check/build, and browser tests on the merged source |
| Live interface capture | Windows 11, local sensor with Npcap, connected Wi-Fi adapter | **175 seen / 175 saved / 0 ignored**; clean stop | Ordinary live Wi-Fi capture and local persistence on this specific computer/adapter |
| Live record retrieval and exports | Same isolated local session | **PASS**; 175 records returned; CSV and PDF endpoints HTTP 200 | Session-scoped query and export against the actual saved capture |
| Local service smoke check | `GET http://127.0.0.1:8000/api/health`, dashboard `http://127.0.0.1:5173` | Both HTTP **200** | Local API and dashboard respond; does not replace a fresh adapter check |
| Hosted dashboard smoke check | `https://pocket-packet-sniffer.vercel.app` | HTTP **200**; latest privacy copy present | Production web UI is reachable; it does not host the capture agent or packet data |

The browser tests use controlled/mocked local-agent responses to make UI behavior repeatable. They do not simulate or claim physical packet capture. The separate 175-packet run above used observed network traffic and did not generate or inject packets.

## Connected system flows

| Flow | Main implementation/test evidence | Expected/observed result |
|---|---|---|
| Capture → Analysis → Storage | `tests/test_session_integration.py`, `tests/test_capture_layer.py`, `tests/test_analysis_layer.py`, `tests/test_storage_query.py` | Supported packet metadata is analyzed and saved alongside PCAP data in local storage; the live acceptance session returned all 175 stored records |
| API / local sensor | `tests/test_api.py`, `tests/test_capture_control.py`, `tests/test_capture_runner.py`, `tests/test_agent.py` | Explicit start/stop, health/liveness, query, statistics, replay, and report routes follow API contracts; errors are covered with controlled failure inputs |
| CLI integration | `tests/test_cli.py` | Capture/replay, query, statistics and export commands report expected outcomes and actionable errors |
| Query and dashboard refresh | `tests/test_api.py`, `web/tests/e2e/dashboard.spec.ts` | Address/protocol/session/time filters reach the local API; live statistics and saved packet history are displayed from returned data |
| Report generation | `tests/test_presentation_report_export.py`, `tests/test_report_pdf.py`, live-session export endpoints | CSV and PDF are generated from stored metadata; live acceptance endpoints both returned HTTP 200 |
| Privacy and origin boundary | `tests/test_security_contracts.py`, API/browser tests, `Docs/PRIVACY_GUIDELINES.md` | Local-only capture boundary and configured browser origins are exercised; packet records remain with the local sensor |
| Web deployment | Vercel production URL; `Docs/WEB_DEPLOYMENT.md` | Dashboard is hosted separately from the local capture API; hosted success does not mean cloud capture |

## Live acceptance session record

On 2026-11-18, the operator selected the connected Wi-Fi adapter and started a passive capture through the local sensor. Five reported rate samples were nonzero: **14, 32, 4, 7, and 30 packets/second**. The session finished with **175 packets seen, 175 stored, 0 ignored**, and a clean stop (exit code 0). Session query returned 175 records; CSV and PDF report requests each returned HTTP 200. Data was stored in an isolated local application-data directory. No packet addresses, session identifiers, PCAPs, SQLite files, or exports are committed as evidence.

This is a short, single-machine observation. It establishes that the selected ordinary Wi-Fi path worked for this run. It does not establish a sustained rate, zero packet loss, complete network visibility, or operation on other adapters.

## CI and reproducibility

The merged commit was tested by [CI run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089). The associated pre-merge source verification is [PR run #730](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44363778707); both passed. Run #731 is the canonical current main-branch evidence. The historical screenshots under `tests/docs/evidence/integration/screenshots/` are supplementary records from prior runs and are not represented as screenshots of run #731.

## Not verified by these system tests

- Wi-Fi monitor mode on monitor-capable hardware/driver.
- Live BLE scanning; the current Windows agent does not scan BLE radios. BLE PCAP decoding/replay is a separate capability.
- Simultaneous capture on multiple physical adapters; concurrent fixture tests do not establish physical fan-in behavior.
- Windows filesystem ACL configuration, Raspberry Pi throughput, live NIC/kernel drop counters, or a zero-loss guarantee.
- Human usability-study results or a formal accessibility audit.
- Detection of every malicious packet. Alerts are metadata-based heuristics and should be investigated, not treated as a verdict.

See the [SRS acceptance report](ACCEPTANCE_TEST_REPORT.md), [test execution history](TEST_EXECUTION_REPORT.md), and [requirement traceability matrix](../../Docs/REQUIREMENT_TRACEABILITY.md) for the complete status and remaining acceptance gates.
