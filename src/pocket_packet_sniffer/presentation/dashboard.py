"""Presentation-only formatting and timed refresh for traffic statistics.

The presentation layer consumes a snapshot produced by the Analysis layer. It
never parses raw packets or performs aggregation itself.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from threading import Event
from typing import Any, TextIO

StatsSnapshot = Mapping[str, Any]


def _human_bytes(value: int) -> str:
    """Format a non-negative byte count using readable binary units."""
    if value < 0:
        raise ValueError("byte count must be non-negative")
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024 or unit == "TB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{value} B"


def render_stats(snapshot: StatsSnapshot, title: str = "Pocket Packet Sniffer") -> str:
    """Render a statistics snapshot as plain text without mutating it.

    Expected keys: total_packets, total_bytes, packets_per_sec, protocols
    (protocol/count pairs), and top_talkers (address/count pairs). The shape
    matches the reference statistics snapshot while remaining independent
    of the concrete Analysis aggregator.
    """
    total_packets = int(snapshot.get("total_packets", 0))
    total_bytes = int(snapshot.get("total_bytes", 0))
    packet_rate = float(snapshot.get("packets_per_sec", 0.0))
    protocols = list(snapshot.get("protocols", ()))
    talkers = list(snapshot.get("top_talkers", ()))[:5]

    if total_packets < 0 or total_bytes < 0 or packet_rate < 0:
        raise ValueError("statistics counts and packet rate must be non-negative")

    lines = [title, "=" * len(title)]
    lines.append(
        f"Packets: {total_packets}   Data: {_human_bytes(total_bytes)}   "
        f"Rate: {packet_rate:.1f} pkt/s"
    )
    lines.extend(("", "Protocol breakdown"))
    if protocols:
        denominator = max(total_packets, 1)
        for protocol, count in protocols:
            count = int(count)
            if count < 0:
                raise ValueError("protocol counts must be non-negative")
            lines.append(
                f"  {str(protocol):<10} {count:>7}  "
                f"{100 * count / denominator:5.1f}%"
            )
    else:
        lines.append("  (no packets yet)")

    lines.extend(("", "Top talkers (by packets sent)"))
    if talkers:
        for address, count in talkers:
            count = int(count)
            if count < 0:
                raise ValueError("talker counts must be non-negative")
            lines.append(f"  {str(address):<40} {count:>7}")
    else:
        lines.append("  (no packets yet)")
    return "\n".join(lines)


def run_live_dashboard(
    snapshot_provider: Callable[[], StatsSnapshot],
    stop_event: Event,
    *,
    output: TextIO,
    refresh_interval: float = 2.0,
    clock: Callable[[], float] = time.monotonic,
    clear_screen: bool = False,
) -> None:
    """Print fresh snapshots until stopped, refreshing at most every 2 seconds.

    snapshot_provider should return a consistent, thread-safe snapshot from
    Analysis. stop_event allows the session owner to stop the display without
    coupling Presentation to a capture backend.
    """
    if not isinstance(refresh_interval, (int, float)) or isinstance(refresh_interval, bool):
        raise ValueError("refresh_interval must be a number greater than zero and at most 2 seconds")
    if not 0 < refresh_interval <= 2.0:
        raise ValueError("refresh_interval must be greater than zero and at most 2 seconds")

    next_refresh = clock()
    while not stop_event.is_set():
        now = clock()
        if now >= next_refresh:
            if clear_screen:
                output.write("\033[2J\033[H")
            output.write(render_stats(snapshot_provider()))
            output.write("\n\n(Ctrl+C to stop)\n\n")
            output.flush()
            next_refresh = now + refresh_interval
        wait_for = max(0.0, next_refresh - clock())
        if stop_event.wait(wait_for):
            break
