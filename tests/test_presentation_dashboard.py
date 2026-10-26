from __future__ import annotations

from io import StringIO
from threading import Event

import pytest

from pocket_packet_sniffer.presentation.dashboard import render_stats, run_live_dashboard


def example_snapshot():
    return {
        "total_packets": 8,
        "total_bytes": 1200,
        "packets_per_sec": 4.25,
        "protocols": [("TCP", 6), ("UDP", 2)],
        "top_talkers": [(f"10.0.0.{index}", 10 - index) for index in range(1, 8)],
    }


def test_render_stats_shows_rate_protocol_breakdown_and_max_five_talkers():
    output = render_stats(example_snapshot())

    assert "Packets: 8" in output
    assert "Rate: 4.2 pkt/s" in output
    assert "Protocol breakdown" in output
    assert "TCP" in output and "UDP" in output
    assert "Top talkers" in output
    assert "10.0.0.5" in output
    assert "10.0.0.6" not in output
    assert "10.0.0.7" not in output


def test_render_stats_handles_empty_capture_readably():
    output = render_stats({
        "total_packets": 0,
        "total_bytes": 0,
        "packets_per_sec": 0,
        "protocols": [],
        "top_talkers": [],
    })
    assert "Packets: 0" in output
    assert "(no packets yet)" in output


def test_render_stats_rejects_negative_totals_and_counts():
    with pytest.raises(ValueError, match="non-negative"):
        render_stats({"total_packets": -1})
    with pytest.raises(ValueError, match="protocol counts"):
        render_stats({
            "total_packets": 1,
            "protocols": [("TCP", -1)],
            "top_talkers": [],
        })


def test_dashboard_refreshes_and_stops_with_event():
    stop = Event()
    output = StringIO()
    snapshots = iter([example_snapshot(), example_snapshot(), example_snapshot()])
    calls = []

    def provider():
        calls.append(1)
        result = next(snapshots)
        if len(calls) == 3:
            stop.set()
        return result

    run_live_dashboard(provider, stop, output=output, refresh_interval=0.01)

    assert len(calls) == 3
    assert output.getvalue().count("Protocol breakdown") == 3
    assert "Ctrl+C to stop" in output.getvalue()


@pytest.mark.parametrize("interval", [0, -0.1, 2.01, 3, float("inf"), float("nan")])
def test_dashboard_rejects_invalid_refresh_interval(interval):
    with pytest.raises(ValueError, match="refresh_interval"):
        run_live_dashboard(
            lambda: example_snapshot(),
            Event(),
            output=StringIO(),
            refresh_interval=interval,
        )
