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

## Current integration limitation

The current main branch contains the Capture Layer but does not yet contain
the Analysis metadata/statistics interface or a CLI/session entry point. This
PR therefore supplies tested presentation helpers and the snapshot contract;
it does not claim that live dashboard capture is end-to-end wired yet. Complete
integration when the Analysis and session/CLI interfaces are available, then
link the final integrated PR to issue #7.

## Local verification

Run:

    PYTHONPATH=src pytest -q tests/test_presentation_dashboard.py
    ruff check --select E4,E7,E9,F,I src tests
