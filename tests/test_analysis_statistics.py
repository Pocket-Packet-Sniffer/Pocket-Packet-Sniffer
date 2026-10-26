from datetime import UTC, datetime

from pocket_packet_sniffer.analysis.models import PacketRecord
from pocket_packet_sniffer.analysis.statistics import TrafficStatistics


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def make_record(protocol="TCP", source="192.0.2.1", size=100):
    return PacketRecord(
        timestamp=datetime.now(UTC),
        source=source,
        destination="198.51.100.1",
        protocol=protocol,
        packet_size=size,
        interface="fixture0",
        link_type=1,
        capture_backend="fixture",
    )


def test_packet_rate_uses_rolling_window_but_totals_are_lifetime_counts():
    clock = FakeClock()
    stats = TrafficStatistics(window_seconds=2.0, clock=clock)
    stats.observe(make_record())

    snapshot = stats.snapshot()
    assert snapshot["total_packets"] == 1
    assert snapshot["total_bytes"] == 100
    assert snapshot["packets_per_sec"] == 0.5

    clock.now = 2.1
    later = stats.snapshot()
    assert later["total_packets"] == 1
    assert later["total_bytes"] == 100
    assert later["packets_per_sec"] == 0.0


def test_protocols_and_top_talkers_are_sorted_by_count_then_name():
    clock = FakeClock()
    stats = TrafficStatistics(clock=clock)
    stats.observe(make_record(protocol="UDP", source="192.0.2.2"))
    stats.observe(make_record(protocol="TCP", source="192.0.2.1"))
    stats.observe(make_record(protocol="TCP", source="192.0.2.1"))

    snapshot = stats.snapshot()
    assert snapshot["protocols"] == [("TCP", 2), ("UDP", 1)]
    assert snapshot["top_talkers"][0] == ("192.0.2.1", 2)
