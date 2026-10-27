# End-to-End Development and Demo Guide

## Install

Use Python 3.10 or newer.

```bash
python -m pip install -e .
python -m pip install -r requirements-dev.txt -r requirements-capture.txt
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
pocket-packet-sniffer capture --interface eth0 --storage-dir captures --session-id lab-session --live-dashboard
```

Use only a network/device you own or have explicit permission to monitor. Live capture depends on the operating system, capture driver, interface and privileges. The command prints its session ID. Press Ctrl+C or, from another terminal in the same working directory, run:

```bash
pocket-packet-sniffer stop --storage-dir captures --session-id lab-session
```

Both methods request cooperative shutdown. Verify live startup/stop behavior on the actual target OS/driver before a demo.

An optional BPF filter can be supplied with `--filter "tcp port 443"` if the driver supports it and permissions are sufficient.

## List and query saved sessions

```bash
pocket-packet-sniffer sessions --storage-dir captures
pocket-packet-sniffer query --storage-dir captures --session-id lab-session --protocol TCP --address 192.0.2.10
pocket-packet-sniffer query --storage-dir captures --start 2026-10-26T12:00:00+00:00 --end 2026-10-26T13:00:00+00:00
```

Filters can be combined, including protocol, address, session ID and time window. Dates must be timezone-aware ISO-8601 values. Dates must be timezone-aware ISO-8601 values. Query output displays metadata, not raw packet payloads.

## Export a session

```bash
pocket-packet-sniffer export --storage-dir captures --session-id demo-session --output demo-session.csv --format csv
pocket-packet-sniffer export --storage-dir captures --session-id demo-session --output demo-session.pdf --format pdf
```

The export writes a session summary and packet metadata to a local CSV or PDF file. It does not include raw packet payloads and refuses to overwrite an existing destination. Session-scoped retrieval uses the Repository contract.

## Synthetic end-to-end demo

```bash
python -m pip install -r requirements-dev.txt -r requirements-capture.txt
python tools/create_demo_pcap.py demo.pcap
pocket-packet-sniffer capture --pcap-file demo.pcap --storage-dir demo-captures --session-id demo-session
pocket-packet-sniffer query --storage-dir demo-captures --protocol TCP
pocket-packet-sniffer query --storage-dir demo-captures --address 192.0.2.1
pocket-packet-sniffer export --storage-dir demo-captures --session-id demo-session --output demo-session.csv --format csv
pocket-packet-sniffer export --storage-dir demo-captures --session-id demo-session --output demo-session.pdf --format pdf
```

The generated fixture is synthetic, contains TCP, DNS/UDP, ICMP and conflicting ARP claims, and is intended to demonstrate parser/statistics/reporting and a heuristic alert. Replay reads it locally and does not send packets. The generator refuses to overwrite an existing file.

For concurrent fan-in without privileged capture:

```bash
python tools/create_demo_pcap.py demo-a.pcap
python tools/create_demo_pcap.py demo-b.pcap
pocket-packet-sniffer capture-multi --pcap-file demo-a.pcap --pcap-file demo-b.pcap --storage-dir demo-multi-captures --session-id multi-demo --count 6
```

## Test

```bash
ruff check --select E4,E7,E9,F,I src tests tools
pytest -q
```

CI runs the same checks. Generated-PCAP tests exercise the layers without root/administrator privileges or real network traffic.

## Layer contract

- Capture emits `CapturedPacket` with original raw bytes, timestamp, interface, link type and original length.
- Analysis returns normalized metadata using `PacketParser` or the configurable `AnalyzerPipeline`.
- The application `CaptureSession` maps analyzed metadata plus original raw bytes to the Storage `PacketRecord` contract.
- Storage persists PCAP and indexed metadata in SQLite.
- Presentation renders statistics and exports CSV/PDF without parsing packets; it also lists sessions and supports a local cross-terminal stop request.
- An architecture test prevents Analysis from importing the concrete Storage implementation. The compliance branch adds heuristic metadata-only alerts and concurrent capture; those changes require CI plus an independent review before merge.

## Remaining manual checks

- Live-interface and permission/startup smoke tests on each target OS/driver.
- Windows ACL behaviour; POSIX mode-bit tests do not apply to Windows.
- Wi-Fi monitor mode, BLE scanning and Raspberry Pi performance are not validated by CI.
- Repeat security review if external integration paths are introduced.
