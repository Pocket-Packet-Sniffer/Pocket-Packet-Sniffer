# Capture Layer

The Capture Layer implements SRS REQ-1 and REQ-2 and maps to STP TC-CAP-01 and TC-CAP-02. Each backend implements the common `Capturer.capture(on_packet, stop_event, count=None)` interface.

- `PcapFileCapturer`: local classic-PCAP replay using a standard-library reader. It supports microsecond/nanosecond timestamps and both byte orders. PCAPNG is not supported.
- `ScapyCapturer`: passive live capture on one selected interface using Scapy's asynchronous sniffer. The interface and driver must already support the requested link-layer mode; the tool does not enable Wi-Fi monitor mode or install/configure a capture driver.
- `ConcurrentCapturer`: starts two or more independent capturers concurrently and forwards packets through the same callback. It shares cancellation and an optional aggregate packet count and preserves interface/backend/link-type metadata. File replay can be paired with other local PCAP replay sources for an unprivileged demonstration.

## Supported packet context

A captured record carries timezone-aware UTC timestamp, raw link-layer bytes, interface label, PCAP link type, original length and optional capture-backend label. Analysis handles supported Ethernet/IPv4/IPv6/ARP frames and 802.11/BLE link types when those link types are delivered by the capture source. Classic PCAP storage creates separate files per link-layer type and indexes them under the same logical session.

## Safe-use constraints

- Only capture on networks/devices you own or are explicitly authorized to monitor.
- Capture is listen-only: the Capture Layer must not inject, modify or replay packets onto the monitored network.
- PCAP replay reads a local file and never transmits its frames.
- The optional BPF filter applies to live capture only; it is not an authorization control and does not filter local PCAP replay.
- Do not commit real capture files or payloads to the repository.
- Wi-Fi monitor mode requires compatible hardware/driver and operating-system configuration.
- BLE advertisement scanning is a stretch requirement and depends on the BLE sniffer/HCI adapter and OS delivering a supported BLE PCAP link type; the generic parser/test fixtures do not prove a working BLE radio capture path.

## Local checks

```bash
python -m pip install -r requirements-dev.txt -r requirements-capture.txt
ruff check --select E4,E7,E9,F,I src tests
PYTHONPATH=src pytest -q
```

Automated tests use generated PCAP fixtures and mocks and do not need administrator privileges or actual live traffic. Live-interface, driver, permission, Wi-Fi monitor-mode and BLE hardware behavior must be verified separately on the intended target.

## Error handling

Typed subclasses of `CaptureError` identify unavailable interfaces, denied privileges, missing backend dependencies, invalid PCAP input, startup failures and callback errors. The session/presentation helper returns status 0 on success, 2 for known capture errors and 130 after Ctrl+C requests a cooperative stop. The concurrent wrapper propagates backend failures after requesting peers to stop.

## Known limitations

- Classic PCAP only; PCAPNG is unsupported by the replay backend.
- Live support depends on Scapy, OS, capture driver, interface mode and permissions.
- Wi-Fi monitor-mode and BLE live capture are not claimed as hardware-tested.
- Windows ACL behavior and Raspberry Pi loss/throughput measurements remain unverified.
