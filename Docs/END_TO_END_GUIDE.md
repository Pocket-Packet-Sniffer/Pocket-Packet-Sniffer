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

## List sessions, query and export

~~~bash
pocket-packet-sniffer sessions --storage-dir captures
pocket-packet-sniffer query --storage-dir captures --protocol TCP --address 192.0.2.10
pocket-packet-sniffer query --storage-dir captures --start 2026-10-26T12:00:00+00:00 --end 2026-10-26T13:00:00+00:00
pocket-packet-sniffer export --storage-dir captures --session-id demo-session --output demo-session.csv
~~~

Session listing shows stored sessions and packet/time summaries. Query filters combine by AND. Export writes the requested stored session to local CSV and refuses to overwrite an existing destination. SRS REQ-8 says CSV or PDF, so the existing CSV exporter satisfies the stated format requirement.

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

## Reproducible concurrent demo

Generate synthetic Ethernet and Wi-Fi-beacon classic-PCAP fixtures; the generator writes local files and never transmits packets:

~~~bash
python tools/create_demo_pcaps.py --output-dir demo-data
~~~

Replay both fixtures concurrently through the actual Capture, Analysis, Storage, and Presentation path:

~~~bash
pocket-packet-sniffer capture --multi-pcap-file demo-data/ethernet-demo.pcap demo-data/wifi-beacon-demo.pcap --storage-dir demo-captures --session-id demo-run --alerts --trusted-device 02:00:00:00:00:01 --trusted-ap 02:00:00:00:00:01 --replay-delay 0.25
pocket-packet-sniffer sessions --storage-dir demo-captures
~~~

Use the printed backend-session IDs for query and CSV export. The Ethernet fixture contains a deliberately conflicting ARP sender IP-to-MAC mapping. The Wi-Fi fixture contains a beacon whose BSSID is outside the supplied trusted-AP allowlist. These alerts are heuristic indicators, not definitive attack detection.

For supported real interfaces, concurrent live capture is available with at least two interface names:

~~~bash
pocket-packet-sniffer capture --multi-interface eth0 wlan0 --storage-dir captures --live-dashboard
~~~

Use only authorized interfaces. Every backend gets a separate stored session/PCAP file because classic PCAP stores one link type per file; statistics and alert observers are shared.

## SRS limitations that require an honest claim

- Ethernet/Scapy-supported interface capture is implemented; live capture must still be tested on the actual target OS and driver.
- Wi-Fi monitor-mode availability depends on compatible hardware/driver and has not been verified on target equipment.
- BLE advertisement scanning is not implemented. SRS REQ-1 mentions BLE, while appendix D calls ESP32/BLE scanning a stretch/risk item; do not claim BLE support until implemented and tested using the intended hardware.
- REQ-9 currently uses scoped heuristic rules for ARP sender IP-to-MAC changes, unrecognized source MACs relative to an explicit trusted-device list, and Wi-Fi beacon BSSIDs outside an explicit trusted-AP list.
- REQ-10 concurrent sessions and aggregate stats are implemented on this branch; real multi-interface operation still requires suitable interfaces, drivers, and permissions.
- Raspberry Pi throughput/no-drop claims, Windows ACLs, and live capture permission behavior require manual target-environment evidence.
