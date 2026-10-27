# Presentation Layer: live statistics display

This module provides the presentation-only portion of PPS-06 (SRS REQ-7,
STP TC-PRE-01). It renders a statistics snapshot and refreshes the display
without parsing raw packets or calculating aggregation counters.

## Snapshot contract

The renderer accepts a mapping with these keys:

- total_packets: cumulative packet count
- total_bytes: cumulative byte count
- packets_per_sec: recent packet rate
- protocols: iterable of (protocol, count) pairs
- top_talkers: iterable of (source endpoint, count) pairs

The shape mirrors the reference implementation's StatsAggregator snapshot.
Analysis owns creation of this snapshot; Presentation owns rendering and the
refresh loop. The refresh interval defaults to two seconds and rejects values
greater than two seconds.

## Current integration

The integrated Capture → Analysis → Storage → Presentation/CLI path is available
in `main` through the existing `CaptureSession`, `TrafficStatistics`, and CLI.
Run `pocket-packet-sniffer capture --interface <authorized-interface> --live-dashboard`
to show active live statistics with a two-second refresh. Stop the session with
Ctrl+C. This is terminal output, not a web dashboard.

Branch PR #31 adds observer alerts, concurrent capture sessions, session listing,
capture-interface persistence, and synthetic multi-PCAP demo support. That branch
passed Ruff and 95 tests in CI run 40477786175, but its changes remain subject to
review and merge.

Live-interface behavior depends on the OS, driver, hardware, and permissions.
Fixture CI does not verify Wi-Fi monitor mode, BLE advertisement scanning, or
Raspberry Pi performance.

## Local verification

Run:

    PYTHONPATH=src pytest -q tests/test_presentation_dashboard.py
    ruff check --select E4,E7,E9,F,I src tests
