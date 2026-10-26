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
- The full command-line/session entry point must call run_capture_with_error_handling once the Analysis callback and overall CLI command are integrated. Until then, this helper is a tested integration contract, not proof that the complete application CLI is finished.
- Re-run the security review after the complete CLI/session workflow exists to confirm no unexpected upload or external-service path has been introduced.
- Verify Windows file access through ACLs separately; POSIX mode-bit checks do not apply on Windows.
