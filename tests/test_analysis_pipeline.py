from datetime import UTC, datetime

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from pocket_packet_sniffer.analysis.models import PacketRecord
from pocket_packet_sniffer.analysis.parser import PacketParser
from pocket_packet_sniffer.analysis.pipeline import AnalyzerPipeline
from pocket_packet_sniffer.capture.models import CapturedPacket


def captured_tcp():
    raw = bytes(Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP())
    return CapturedPacket(
        timestamp=datetime.now(UTC),
        packet_data=raw,
        interface="fixture0",
        link_type=1,
        original_length=len(raw),
    )


class CustomProtocolAnalyzer:
    def parse(self, captured, *, backend=None):
        return PacketRecord(
            timestamp=captured.timestamp,
            source="custom-source",
            destination="custom-destination",
            protocol="CUSTOM",
            packet_size=captured.original_length,
            interface=captured.interface,
            link_type=captured.link_type,
            capture_backend=backend,
        )


class DecliningAnalyzer:
    def parse(self, captured, *, backend=None):
        return None


def test_pipeline_uses_first_analyzer_that_recognizes_packet():
    pipeline = AnalyzerPipeline([CustomProtocolAnalyzer(), PacketParser()])
    result = pipeline.parse(captured_tcp(), backend="fixture")

    assert result is not None
    assert result.protocol == "CUSTOM"
    assert result.capture_backend == "fixture"


def test_pipeline_falls_back_to_default_packet_parser():
    pipeline = AnalyzerPipeline([DecliningAnalyzer(), PacketParser()])
    result = pipeline.parse(captured_tcp(), backend="fixture")

    assert result is not None
    assert result.protocol == "TCP"
    assert result.source == "192.0.2.10"


def test_pipeline_returns_none_when_all_analyzers_decline():
    assert AnalyzerPipeline([DecliningAnalyzer()]).parse(captured_tcp()) is None


def test_pipeline_rejects_empty_analyzer_sequence():
    try:
        AnalyzerPipeline([])
    except ValueError as exc:
        assert "at least one analyzer" in str(exc)
    else:
        raise AssertionError("empty pipeline should be rejected")
