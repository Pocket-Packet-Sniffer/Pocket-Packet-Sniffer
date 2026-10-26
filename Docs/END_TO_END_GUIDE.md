# End-to-End Development and Demo Guide

## Install

Use Python 3.10 or newer.

```bash
python -m pip install -e .
python -m pip install -r requirements-dev.txt
pocket-packet-sniffer --help
```

You can also run the CLI as a module with `python -m pocket_packet_sniffer`.

## Replay a local PCAP

```bash
pocket-packet-sniffer capture --pcap-file sample.pcap --storage-dir captures --session-id demo-session
```

This reads a classic PCAP, parses supported frames, stores the original bytes and normalized metadata locally, and prints session statistics. File replay does not transmit packets. PCAPNG is not supported.

## Capture an authorized live interface

```bash
pocket-packet-sniffer capture --interface eth0 --storage-dir captures --live-dashboard
```

Use only a network/device you own or have explicit permission to monitor. Live capture depends on the operating system, capture driver, interface and privileges. Ctrl+C requests shutdown and stops the background Scapy sniffer. Verify this on the actual target OS/driver before a demo.

An optional BPF filter can be supplied with `--filter "tcp port 443"` if the driver supports it and permissions are sufficient.

## Query local captures

```bash
pocket-packet-sniffer query --storage-dir captures --protocol TCP --address 192.0.2.10
pocket-packet-sniffer query --storage-dir captures --start 2026-10-26T12:00:00+00:00 --end 2026-10-26T13:00:00+00:00
```

Filters can be combined. Dates must be timezone-aware ISO-8601 values. Query output displays metadata, not raw packet payloads.

## Export a session

```bash
pocket-packet-sniffer export --storage-dir captures --session-id demo-session --output demo-session.csv
```

The export writes local CSV and does not overwrite an existing destination. PDF output is not implemented in this CLI version; confirm whether CSV alone satisfies the agreed report deliverable.

## Test

```bash
ruff check --select E4,E7,E9,F,I src tests
pytest -q
```

CI runs the same checks. Generated-PCAP tests exercise the layers without root/administrator privileges or real network traffic.

## Layer contract

- Capture emits `CapturedPacket` with original raw bytes, timestamp, interface, link type and original length.
- Analysis returns normalized metadata using `PacketParser` or the configurable `AnalyzerPipeline`.
- The application `CaptureSession` maps analyzed metadata plus original raw bytes to the Storage `PacketRecord` contract.
- Storage persists PCAP and indexed metadata in SQLite.
- Presentation renders statistics and exports CSV without parsing packets.
- An architecture test prevents Analysis from importing the concrete Storage implementation.

## Remaining manual checks

- Live-interface and permission/startup smoke tests on each target OS/driver.
- Windows ACL behaviour; POSIX mode-bit tests do not apply to Windows.
- Wi-Fi monitor mode, BLE scanning and Raspberry Pi performance are not validated by CI.
- Repeat security review if external integration paths are introduced.
