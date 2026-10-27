"""Command-line entry point for capture, querying, and CSV report export."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from threading import Event, Thread

from pocket_packet_sniffer.analysis.alerts import AlertBus, SuspiciousActivityDetector
from pocket_packet_sniffer.analysis.parser import PacketParser
from pocket_packet_sniffer.analysis.pipeline import AnalyzerPipeline
from pocket_packet_sniffer.application.multi_session import MultiCaptureSession
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
    source.add_argument(
        "--multi-interface",
        nargs="+",
        metavar="INTERFACE",
        help="passively capture two or more authorized interfaces concurrently",
    )
    source.add_argument(
        "--multi-pcap-file",
        type=Path,
        nargs="+",
        metavar="PCAP",
        help="replay two or more local classic-PCAP files concurrently for safe demos",
    )
    capture.add_argument("--filter", dest="bpf_filter", help="optional BPF filter for live capture")
    capture.add_argument("--storage-dir", type=Path, default=Path("captures"))
    capture.add_argument("--session-id", default=None)
    capture.add_argument("--count", type=_positive_int, default=None)
    capture.add_argument("--replay-delay", type=float, default=0.0, help="seconds between replayed packets; useful for observing statistics")
    capture.add_argument("--live-dashboard", action="store_true", help="refresh live statistics while capturing")
    capture.add_argument("--alerts", action="store_true", help="enable supported heuristic alert rules")
    capture.add_argument("--trusted-device", action="append", default=[], metavar="MAC", help="trusted device MAC; repeat as needed")
    capture.add_argument("--trusted-ap", action="append", default=[], metavar="BSSID", help="trusted Wi-Fi AP BSSID; repeat as needed")

    query = commands.add_parser("query", help="query local capture metadata")
    query.add_argument("--storage-dir", type=Path, default=Path("captures"))
    query.add_argument("--protocol")
    query.add_argument("--address")
    query.add_argument("--start", type=_aware_datetime)
    query.add_argument("--end", type=_aware_datetime)

    sessions = commands.add_parser("sessions", help="list locally stored capture sessions")
    sessions.add_argument("--storage-dir", type=Path, default=Path("captures"))

    export = commands.add_parser("export", help="export one local session to CSV")
    export.add_argument("--storage-dir", type=Path, default=Path("captures"))
    export.add_argument("--session-id", required=True)
    export.add_argument("--output", type=Path, required=True)

    return parser


def _run_capture(args: argparse.Namespace) -> int:
    has_live_source = bool(args.interface or args.multi_interface)
    if args.live_dashboard and not has_live_source:
        print("error: --live-dashboard requires an interface or PCAP capture source", file=sys.stderr)
        return 2
    if args.multi_interface is not None and len(args.multi_interface) < 2:
        print("error: --multi-interface requires at least two interface names", file=sys.stderr)
        return 2
    if args.multi_pcap_file is not None and len(args.multi_pcap_file) < 2:
        print("error: --multi-pcap-file requires at least two PCAP paths", file=sys.stderr)
        return 2
    if args.multi_interface is not None and args.pcap_file is not None:
        print("error: PCAP replay and multi-interface capture are separate modes", file=sys.stderr)
        return 2

    repository = PcapSqliteRepository(args.storage_dir)
    analyzer = AnalyzerPipeline([PacketParser()])
    alert_bus = None
    detector = None
    if not args.alerts and (args.trusted_device or args.trusted_ap):
        print("error: --trusted-device and --trusted-ap require --alerts", file=sys.stderr)
        return 2
    if args.alerts:
        alert_bus = AlertBus()
        alert_bus.subscribe(
            lambda alert: print(
                f"ALERT [{alert.severity}] {alert.rule_id} interface={alert.interface} "
                f"subject={alert.subject or '-'}: {alert.message} "
                f"{alert.evidence or ''}".rstrip(),
                file=sys.stderr,
            )
        )
        detector = SuspiciousActivityDetector(
            trusted_devices=args.trusted_device,
            trusted_aps=args.trusted_ap,
        )

    if args.multi_interface is not None or args.multi_pcap_file is not None:
        if args.multi_interface is not None:
            capturers = [
                ScapyCapturer(interface, bpf_filter=args.bpf_filter)
                for interface in args.multi_interface
            ]
        else:
            capturers = [PcapFileCapturer(path, delay=args.replay_delay) for path in args.multi_pcap_file]
        session = MultiCaptureSession(
            capturers,
            repository,
            session_id=args.session_id,
            analyzer=analyzer,
            alert_bus=alert_bus,
            detector=detector,
        )
    else:
        capturer = (
            PcapFileCapturer(args.pcap_file, delay=args.replay_delay)
            if args.pcap_file is not None
            else ScapyCapturer(args.interface, bpf_filter=args.bpf_filter)
        )
        session = CaptureSession(
            capturer,
            repository,
            session_id=args.session_id,
            analyzer=analyzer,
            alert_bus=alert_bus,
            detector=detector,
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
    if args.multi_interface is not None or args.multi_pcap_file is not None:
        for child in result.sessions:
            print(
                f"backend_session={child.session_id} seen={child.packets_seen} "
                f"stored={child.packets_stored} ignored={child.packets_ignored} "
                f"exit_code={child.exit_code}"
            )
        for error in result.errors:
            print(f"error: concurrent capture session failed: {error}", file=sys.stderr)
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
            f"{record.original_length}\t{record.interface}\t{record.session_id}"
        )
    print(f"{len(records)} packet(s)")
    return EXIT_SUCCESS


def _run_sessions(args: argparse.Namespace) -> int:
    repository = PcapSqliteRepository(args.storage_dir)
    sessions = repository.list_sessions()
    if not sessions:
        print("No stored capture sessions.")
        return EXIT_SUCCESS
    print("session_id\tpackets\tfirst_packet_at\tlast_packet_at")
    for summary in sessions:
        first = summary.first_packet_at.isoformat() if summary.first_packet_at else "-"
        last = summary.last_packet_at.isoformat() if summary.last_packet_at else "-"
        print(f"{summary.session_id}\t{summary.packet_count}\t{first}\t{last}")
    return EXIT_SUCCESS


def _run_export(args: argparse.Namespace) -> int:
    repository = PcapSqliteRepository(args.storage_dir)
    summary = repository.get_session_summary(args.session_id)
    records = repository.query(session_id=args.session_id)
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
        if args.command == "sessions":
            return _run_sessions(args)
        if args.command == "export":
            return _run_export(args)
    except (RepositoryError, ReportExportError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
