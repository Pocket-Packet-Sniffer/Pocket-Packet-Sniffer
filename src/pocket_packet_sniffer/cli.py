"""Command-line entry point for capture, querying, and CSV report export."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from threading import Event, Thread

from pocket_packet_sniffer.analysis.alerts import (
    AlertPublisher,
    SuspiciousActivityDetector,
)
from pocket_packet_sniffer.analysis.parser import PacketParser
from pocket_packet_sniffer.analysis.pipeline import AnalyzerPipeline
from pocket_packet_sniffer.application.session import CaptureSession
from pocket_packet_sniffer.capture import PcapFileCapturer, ScapyCapturer
from pocket_packet_sniffer.capture.concurrent import ConcurrentCapturer
from pocket_packet_sniffer.presentation import (
    EXIT_SUCCESS,
    ReportExportError,
    export_session_report_csv,
    render_stats,
    run_live_dashboard,
)
from pocket_packet_sniffer.presentation.capture_control import CaptureControl, CaptureControlError
from pocket_packet_sniffer.presentation.report_pdf import export_session_report_pdf
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
        description="Passively capture authorized traffic, list sessions, query local captures, and export CSV/PDF reports.",
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
    capture.add_argument("--known-device", action="append", default=[], metavar="MAC", help="known device MAC; repeat for an inventory")
    capture.add_argument("--known-access-point", action="append", default=[], metavar="BSSID", help="known Wi-Fi access point; repeat for an allowlist")

    multi = commands.add_parser("capture-multi", help="passively run two or more capture sources together")
    multi.add_argument("--interface", action="append", default=[], help="authorized live interface; repeat for each backend")
    multi.add_argument("--pcap-file", action="append", type=Path, default=[], help="local classic-PCAP replay source; repeat as needed")
    multi.add_argument("--filter", dest="bpf_filter", help="optional BPF filter applied to live interfaces")
    multi.add_argument("--storage-dir", type=Path, default=Path("captures"))
    multi.add_argument("--session-id", default=None)
    multi.add_argument("--count", type=_positive_int, default=None, help="stop after this many packets across all sources")
    multi.add_argument("--live-dashboard", action="store_true", help="refresh aggregate live statistics while capturing")
    multi.add_argument("--known-device", action="append", default=[], metavar="MAC", help="known device MAC; repeat for an inventory")
    multi.add_argument("--known-access-point", action="append", default=[], metavar="BSSID", help="known Wi-Fi access point; repeat for an allowlist")

    query = commands.add_parser("query", help="query local capture metadata")
    sessions = commands.add_parser("sessions", help="list saved capture-session summaries")
    sessions.add_argument("--storage-dir", type=Path, default=Path("captures"))

    stop = commands.add_parser("stop", help="request graceful stop of an active capture")
    stop.add_argument("--storage-dir", type=Path, default=Path("captures"))
    stop.add_argument("--session-id", required=True, help="session ID printed when capture started")

    query.add_argument("--storage-dir", type=Path, default=Path("captures"))
    query.add_argument("--session-id", help="restrict results to one saved session")
    query.add_argument("--protocol")
    query.add_argument("--address")
    query.add_argument("--start", type=_aware_datetime)
    query.add_argument("--end", type=_aware_datetime)

    export = commands.add_parser("export", help="export one local session to CSV")
    export.add_argument("--storage-dir", type=Path, default=Path("captures"))
    export.add_argument("--session-id", required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--format", choices=("csv", "pdf"), default="csv", help="report format (default: csv)")

    return parser


def _make_alert_detector(args: argparse.Namespace) -> SuspiciousActivityDetector:
    """Create metadata-only alert rules and a CLI Observer subscriber."""
    publisher = AlertPublisher()
    publisher.subscribe(
        lambda event: print(
            f"ALERT [{event.severity}] {event.rule_id}: {event.message}",
            file=sys.stderr,
        )
    )
    return SuspiciousActivityDetector(
        publisher,
        known_devices=set(args.known_device),
        known_access_points=set(args.known_access_point),
    )


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
        alert_detector=_make_alert_detector(args),
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


def _run_capture_multi(args: argparse.Namespace) -> int:
    """Capture concurrently from any combination of local PCAP and live sources."""
    if len(args.interface) + len(args.pcap_file) < 2:
        print("error: capture-multi requires at least two --interface/--pcap-file sources", file=sys.stderr)
        return 2

    capturers = [PcapFileCapturer(path) for path in args.pcap_file]
    capturers.extend(ScapyCapturer(name, bpf_filter=args.bpf_filter) for name in args.interface)
    repository = PcapSqliteRepository(args.storage_dir)
    session = CaptureSession(
        ConcurrentCapturer(capturers),
        repository,
        session_id=args.session_id,
        analyzer=AnalyzerPipeline([PacketParser()]),
        alert_detector=_make_alert_detector(args),
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


def _run_sessions(args: argparse.Namespace) -> int:
    """List locally persisted capture-session summaries."""
    repository = PcapSqliteRepository(args.storage_dir)
    summaries = repository.list_sessions()
    if not summaries:
        print("No stored capture sessions.")
        return EXIT_SUCCESS
    print("SESSION_ID\tPACKETS\tFIRST_PACKET\tLAST_PACKET")
    for summary in summaries:
        first = summary.first_packet_at.isoformat() if summary.first_packet_at else "-"
        last = summary.last_packet_at.isoformat() if summary.last_packet_at else "-"
        print(f"{summary.session_id}\t{summary.packet_count}\t{first}\t{last}")
    print(f"{len(summaries)} session(s)")
    return EXIT_SUCCESS


def _run_stop(args: argparse.Namespace) -> int:
    """Request cooperative cancellation for a running capture command."""
    try:
        requested = CaptureControl.request_stop(args.storage_dir, args.session_id)
    except (CaptureControlError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not requested:
        print(f"No active capture session {args.session_id!r} was found.", file=sys.stderr)
        return 2
    print(
        f"Stop requested for session {args.session_id!r}; "
        "capture will exit after the backend observes cancellation."
    )
    return EXIT_SUCCESS


def _run_query(args: argparse.Namespace) -> int:
    if args.start is not None and args.end is not None and args.start > args.end:
        print("error: --start must not be after --end", file=sys.stderr)
        return 2
    repository = PcapSqliteRepository(args.storage_dir)
    time_window = (args.start, args.end) if args.start is not None or args.end is not None else None
    records = repository.query(
        protocol=args.protocol,
        address=args.address,
        time_window=time_window,
        session_id=args.session_id,
    )
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
    records = repository.query_session(args.session_id)
    exporter = export_session_report_pdf if args.format == "pdf" else export_session_report_csv
    path = exporter(summary, records, args.output)
    print(f"exported {summary.packet_count} packet(s) to {path} ({args.format.upper()})")
    return EXIT_SUCCESS


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns a process-compatible exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            return _run_capture(args)
        if args.command == "capture-multi":
            return _run_capture_multi(args)
        if args.command == "sessions":
            return _run_sessions(args)
        if args.command == "stop":
            return _run_stop(args)
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
