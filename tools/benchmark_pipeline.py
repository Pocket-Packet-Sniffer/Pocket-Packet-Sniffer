"""Benchmark the local replay -> analysis -> PCAP/SQLite storage pipeline.

This measures synthetic file-replay throughput. It does not measure packet loss
on a live network interface and must not be presented as a Raspberry Pi result
unless the command is actually run on that target.
"""
from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from threading import Event
from time import perf_counter
from uuid import uuid4

from scapy.utils import wrpcap

from pocket_packet_sniffer.analysis.parser import PacketParser
from pocket_packet_sniffer.analysis.pipeline import AnalyzerPipeline
from pocket_packet_sniffer.application.session import CaptureSession
from pocket_packet_sniffer.capture import PcapFileCapturer
from pocket_packet_sniffer.storage import PcapSqliteRepository
from tools.create_demo_pcap import build_demo_packets


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Measure synthetic PCAP replay, parsing and local storage throughput. "
            "This is not a live-interface packet-loss test."
        )
    )
    parser.add_argument(
        "--repeats",
        type=_positive_int,
        default=100,
        help="number of repetitions of the five-packet demo fixture (default: 100)",
    )
    parser.add_argument(
        "--storage-dir",
        type=Path,
        default=Path("benchmark-captures"),
        help="local output directory for PCAP/SQLite benchmark results",
    )
    parser.add_argument(
        "--session-id",
        default=f"benchmark-{uuid4()}",
        help="new session ID for this run; it must not already contain packets",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source_packets = build_demo_packets() * args.repeats
    expected_packets = len(source_packets)
    repository = PcapSqliteRepository(args.storage_dir)
    existing_summary = repository.get_session_summary(args.session_id)
    if existing_summary.packet_count:
        print(
            f"error: session {args.session_id!r} already contains packets; use a new session ID",
            file=sys.stderr,
        )
        return 2

    with tempfile.TemporaryDirectory(prefix="pps-pipeline-benchmark-") as temporary_dir:
        pcap_path = Path(temporary_dir) / "synthetic-benchmark.pcap"
        wrpcap(str(pcap_path), source_packets, append=False)
        session = CaptureSession(
            PcapFileCapturer(pcap_path),
            repository,
            session_id=args.session_id,
            analyzer=AnalyzerPipeline([PacketParser()]),
        )
        started = perf_counter()
        result = session.run(Event())
        elapsed = max(perf_counter() - started, 1e-9)

    summary = repository.get_session_summary(args.session_id)
    rate = result.packets_stored / elapsed
    print("Pocket Packet Sniffer replay pipeline benchmark")
    print("mode=synthetic-pcap-replay (not live network capture)")
    print(f"input_packets={expected_packets}")
    print(f"seen={result.packets_seen}")
    print(f"stored={result.packets_stored}")
    print(f"ignored_or_unsupported={result.packets_ignored}")
    print(f"session_packet_count={summary.packet_count}")
    print(f"elapsed_seconds={elapsed:.3f}")
    print(f"stored_packets_per_second={rate:.1f}")
    print(f"storage_dir={repository.directory}")
    print("Interpretation: run this on the target hardware and record its OS, adapter, Python version, repeats, and result.")
    print("This benchmark does not validate live packet drops or Wi-Fi/BLE adapter behavior.")

    if result.exit_code != 0:
        return result.exit_code
    if result.packets_seen != expected_packets:
        print("error: replay did not deliver every generated input packet", file=sys.stderr)
        return 1
    if result.packets_stored + result.packets_ignored != result.packets_seen:
        print("error: packet accounting is inconsistent", file=sys.stderr)
        return 1
    if summary.packet_count != result.packets_stored:
        print("error: persisted session count does not match stored packet count", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
