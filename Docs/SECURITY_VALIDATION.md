# Security and Portability Validation Record

This document separates automated/code-reviewed safeguards from target-environment tests. It must not be read as proof that every platform or SRS requirement has been physically tested.

## Automated safeguards and tests

- `ScapyCapturer` uses passive listening; the capture code does not call packet-send/injection APIs.
- `PcapFileCapturer` only reads a local classic-PCAP file. Replay never transmits frames.
- PCAP and SQLite artifacts remain local. No external upload integration exists in the CLI.
- POSIX tests check private directory/file modes. Storage uses mode 0700 for capture directories and 0600 for PCAP/SQLite files when supported by the OS.
- Capture-runner tests cover stable exit statuses, one-line known errors and Ctrl+C cleanup.
- Analysis alert events contain packet metadata, not raw captured bytes. Alert detection is a heuristic, not an attack verdict.
- CLI capture/query output and PDF/CSV reports display metadata only; generated-PCAP tests assert packet payload markers are not exposed. Reports use exclusive file creation and refuse overwrite.
- Concurrent capture uses existing capturer strategies, shared cancellation and an aggregate packet callback. Its synthetic tests do not require privileges or live network traffic.

## Required operating controls

- Capture only networks/devices owned by the operator or explicitly authorized for monitoring.
- Use synthetic PCAP fixtures for tests. Never commit real traffic captures or sensitive packet payloads.
- Protect the local storage directory and generated reports. Captured traffic may contain personal or confidential data.
- Do not interpret ARP conflicts or inventory mismatches as proof of malicious intent.

## Manual checks still required

For each completed check, record the test date, OS/version, adapter and driver, interface mode, privilege context, authorized test-traffic source, observed startup/stop result, and packet/drop counts when available. Mark checks **not run** until evidence is collected; do not attach raw capture files to the record.

- Live capture start/stop and permission diagnostics on each target OS, capture driver and adapter.
- Wi-Fi monitor mode with the actual supported adapter/driver.
- BLE advertisement capture with the selected BLE sniffer/HCI adapter; parser fixtures alone do not validate the radio/backend.
- Raspberry Pi-class throughput/drop-rate measurements on representative home/lab traffic; no benchmark is inferred from CI.
- Windows ACL review if Windows is a supported target.
- Final security review on the supported target after hardware smoke tests.

PR #29 merged the backend compliance implementation into `main`. Latest main CI [run 40479490511](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40479490511) passed Ruff and 106 tests in 1.87 seconds. A replay throughput benchmark is available, but this is not evidence of live packet-loss performance. Target-environment checks listed above remain unverified until recorded from the actual device/adapter/OS.
