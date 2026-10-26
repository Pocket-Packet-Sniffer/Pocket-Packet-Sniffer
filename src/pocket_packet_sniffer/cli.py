"""Command-line entry point for capture, querying, and CSV report export."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path
import sys
from threading import Event, Thread

from pocket_packet_sniffer.analysis.pipeline import AnalyzerPipeline
from pocket_packet_sniffer.analysis.parser import PacketParser
from pocket_packet_sniffer.application.session import CaptureSession
from pocket_packet_sniffer.capture import PcapFileCapturer, ScapyCapturer
from pocket_packet_sniffer.presentation import (
    EXIT_SUCCESS,
    ReportExportError,
    export_session_report_csv,
    render_stats,
    run_live_dashboard,
)
from pocket_packet_sniffer.storage import PcapSqliteRepository
from pocket_packet_sniffer.storage.errors import RepositoryError


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("count must be a positive integer")
    return parsed


def _aware_datetime(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected an ISO-8601 datetime") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise argparse.ArgumentTypeError("datetime must include a UTC offset, e.g. 2026-10-26T14:30:00+00:00")
    return result


def build_parser() -> argparse.ArgumentParser:
    """Build the command parser for the public CLI."""
    parser = argparse.ArgumentParser(
        prog="pocket-packet-sniffer",
        description="Passively capture authorized traffic, query local captures, and export CSV reports.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    capture = commands.add_parser("capture", help="capture from a local PCAP file or a supported live interface")
    source = capture.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap-file", type=Path, help="replay a local classic PCAP file (does not transmit packets)")
    source.add_argument("--interface", help="passively listen on this authorized interface")
    capture.add_argument("--filter", dest="bpf_filter", help="optional BPF filter for live capture")
    capture.add_argument("--storage-dir", type=Path, default=Path("captures"))
    capture.add_argument("--session-id", default=None)
    capture.add_argument("--count", type=_positive_int, default=None)
    capture.add_argument("--live-dashboard", action="store_true", help="refresh live statistics while capturing")

    query = commands.add_parser("query", help="query local capture metadata")
    query.add_argument("--storage-dir", type=Path, default=Path("captures"))
    query.add_argument("--protocol")
    query.add_argument("--address")
    query.add_argument("--start", type=_aware_datetime)
    query.add_argument("--end", type=_aware_datetime)

    export = commands.add_parser("export", help="export one local session to CSV")
    export.add_argument("--storage-dir", type=Path, default=Path("captures"))
    export.add_argument("--session-id", required=True)
    export.add_argument("--output", type=Path, required=True)

    return parser


def _run_capture(args: argparse.Namespace) -> int:
    if args.live_dashboard and not args.interface:
        print("error: --live-dashboard requires --interface", file=sys.stderr)
        return 2

    repository = PcapSqliteRepository(args.storage_dir)
    capturer = (
        PcapFileCapturer(args.pcap_file)
        if args.pcap_file is not None
        else ScapyCapturer(args.interface, bpf_filter=args.bpf_filter)
    )
    analyzer = AnalyzerPipeline([PacketParser()])
    session = CaptureSession(
        capturer,
        repository,
        session_id=args.session_id,
        analyzer=analyzer,
    )
    stop_event = Event()
    dashboard_stop = Event()
    dashboard_thread: Thread | None = None

    if args.live_dashboard:
        dashboard_thread = Thread(
            target=run_live_dashboard,
            kwargs={
                "snapshot_provider": session.statistics_snapshot,
                "stop_event": dashboard_stop,
                "output": sys.stdout,
                "refresh_interval": 2.0,
            },
            daemon=True,
        )
        dashboard_thread.start()

    try:
        result = session.run(stop_event, count=args.count)
    finally:
        dashboard_stop.set()
        if dashboard_thread is not None:
            dashboard_thread.join(timeout=2.5)

    print(
        f"session={result.session_id} seen={result.packets_seen} "
        f"stored={result.packets_stored} ignored={result.packets_ignored} "
        f"exit_code={result.exit_code}"
    )
    if not args.live_dashboard:
        print(render_stats(session.statistics_snapshot()))
    return result.exit_code


def _run_query(args: argparse.Namespace) -> int:
    if args.start is not None and args.end is not None and args.start > args.end:
        print("error: --start must not be after --end", file=sys.stderr)
        return 2
    repository = PcapSqliteRepository(args.storage_dir)
    time_window = (args.start, args.end) if args.start is not None or args.end is not None else None
    records = repository.query(protocol=args.protocol, address=args.address, time_window=time_window)
    if not records:
        print("No matching packets.")
        return EXIT_SUCCESS
    for record in records:
        print(
            f"{record.timestamp.isoformat()}\t{record.protocol}\t"
            f"{record.source_address or '-'}\t{record.destination_address or '-'}\t"
            f"{record.original_length}\t{record.session_id}"
        )
    print(f"{len(records)} packet(s)")
    return EXIT_SUCCESS


def _run_export(args: argparse.Namespace) -> int:
    repository = PcapSqliteRepository(args.storage_dir)
    summary = repository.get_session_summary(args.session_id)
    records = [record for record in repository.query() if record.session_id == args.session_id]
    path = export_session_report_csv(summary, records, args.output)
    print(f"exported {summary.packet_count} packet(s) to {path}")
    return EXIT_SUCCESS


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns a process-compatible exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            return _run_capture(args)
        if args.command == "query":
            return _run_query(args)
        if args.command == "export":
            return _run_export(args)
    except (RepositoryError, ReportExportError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
