# Capture Layer

The Capture Layer implements SRS REQ-1 and REQ-2 and maps to STP tests TC-CAP-01 and TC-CAP-02.
It supports two backends through the same `Capturer.capture(on_packet, stop_event, count=None)` interface:

- `PcapFileCapturer`: deterministic replay of classic PCAP files using only the Python standard library. It supports classic PCAP microsecond and nanosecond timestamps in either byte order. PCAPNG is intentionally not supported by this backend yet.
- `ScapyCapturer`: passive live capture from one selected interface. Scapy is loaded lazily and must be installed for this backend. The operating system, capture driver and user permissions must support capture.

Both backends emit a `CapturedPacket` containing a timezone-aware UTC timestamp, raw link-layer bytes, interface/source label, PCAP link type and original packet length. Analysis should consume that contract and should not branch on backend implementation.

## Safe-use constraints

- Use live capture only on networks/devices you own or are explicitly authorized to monitor.
- The Capture Layer only listens; it does not inject, modify, or transmit/replay packets onto the network.
- File replay reads a local PCAP and invokes the same packet callback. It is for test/demo input only and does not send packets.
- Do not commit real traffic captures or sensitive payloads to the repository.

## Local checks

```bash
python -m pip install -r requirements-dev.txt -r requirements-capture.txt
PYTHONPATH=src pytest -q
ruff check --select E4,E7,E9,F,I src tests
```

The automated tests create synthetic PCAP fixtures and mock the live Scapy backend. CI does not require root/administrator privileges or a real network interface. Live capture should be verified separately on an authorized interface with the right driver and permissions.

## Error handling

The module exposes typed subclasses of `CaptureError`: `CaptureInterfaceError`, `CapturePermissionError`, `CaptureBackendUnavailableError`, `CaptureFileError`, `CaptureStartupError` and `CaptureCallbackError`. The Presentation package provides `run_capture_with_error_handling`, returning 0 on success, 2 for a known capture-domain error and 130 for Ctrl+C. The `CaptureSession` application service routes captured packets through Analysis and Storage and invokes this helper; the CLI consumes its result. Tests cover clear failure output and explicitly verify that Ctrl+C stops the background Scapy sniffer. Live-interface startup/permission checks still need a permitted target-environment smoke test.

## Known limitations to validate during integration

- Classic PCAP only; PCAPNG is not yet supported by `PcapFileCapturer`.
- Live capture support depends on installed Scapy, OS, capture library/driver and permissions.
- Link type is resolved from Scapy's layer mapping with Ethernet as fallback; non-Ethernet adapters should be verified on target hardware and may need explicit adapter-specific mapping.
- Wi-Fi monitor mode, BLE scanning and Raspberry Pi performance are not claimed as verified by these unit tests.
