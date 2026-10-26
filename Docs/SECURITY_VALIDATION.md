# Security and Portability Validation Record

This document records what is verified by code/tests and what still requires a manual target-environment check. It does not claim that every platform or every SRS requirement has been tested.

## Automated checks

- The Capture Layer uses Scapy's AsyncSniffer for passive listening and has no packet-send, injection, modification, or network-replay call in its implementation.
- The PCAP-file backend reads a local file and invokes the common packet callback; it does not transmit frames.
- Storage writes PCAP and SQLite metadata locally. It does not upload capture data.
- tests/test_security_contracts.py checks on POSIX that the capture directory has no group/other permission bits and that the SQLite database and PCAP files use mode 0600.
- tests/test_capture_runner.py checks that known capture failures return status 2 with a one-line message and no traceback, successful capture returns 0, and Ctrl+C returns 130 after requesting a cooperative stop.
- The CI workflow runs Ruff and the automated test suite on pushes and pull requests.

## Operational safeguards

- Capture only on networks/devices owned by the operator or explicitly authorized for monitoring.
- Use generated PCAP fixtures for automated tests. Do not commit real capture files or sensitive packet payloads.
- The repository .gitignore excludes PCAP/PCAPNG/cap files and SQLite database files.
- No runtime API credentials or external upload integration is configured in the Capture/Storage code currently in main.

## Remaining manual verification

- Live capture must be tested on each intended operating system with its actual capture driver and least-privilege configuration. Unit tests mock Scapy and do not prove hardware support.
- Wi-Fi monitor mode, BLE scanning, and Raspberry Pi performance are not validated by the current CI environment.
- PR #24 wires the CLI through `CaptureSession`, invokes the stable error helper, adapts analyzed metadata plus original frame bytes into Storage, and tests PCAP replay/query/CSV export using generated frames. It is merged to main; Latest main CI run [40357674966](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40357674966) passed with 81 tests. Live-interface behaviour must still be smoke-tested on an authorized target before claiming live deployment readiness.
- The merged CLI/session path was reviewed for local-file-only capture/query/export commands; run a final target-environment security review after live-interface smoke testing, and re-check if external integrations are added.
- Verify Windows file access through ACLs separately; POSIX mode-bit checks do not apply on Windows.
