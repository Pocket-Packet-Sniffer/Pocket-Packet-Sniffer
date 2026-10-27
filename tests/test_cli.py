from __future__ import annotations

import csv
import struct
from pathlib import Path

from tools.create_demo_pcap import create_demo_pcap

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from pocket_packet_sniffer.cli import main


def write_one_packet_pcap(path: Path) -> None:
    frame = bytes(Ether() / IP(src="192.0.2.5", dst="198.51.100.5") / TCP())
    with path.open("wb") as stream:
        stream.write(b"\xd4\xc3\xb2\xa1")
        stream.write(struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        stream.write(struct.pack("<IIII", 1_700_000_000, 123_456, len(frame), len(frame)))
        stream.write(frame)


def test_cli_capture_query_and_export_using_local_pcap(tmp_path, capsys):
    source = tmp_path / "input.pcap"
    storage = tmp_path / "captures"
    report = tmp_path / "report.csv"
    write_one_packet_pcap(source)

    code = main(
        [
            "capture",
            "--pcap-file",
            str(source),
            "--storage-dir",
            str(storage),
            "--session-id",
            "cli-session",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "stored=1" in captured.out
    assert "TCP" in captured.out

    code = main(["query", "--storage-dir", str(storage), "--protocol", "TCP"])
    query_result = capsys.readouterr()
    assert code == 0
    assert "192.0.2.5" in query_result.out
    assert "1 packet(s)" in query_result.out

    code = main(
        [
            "export",
            "--storage-dir",
            str(storage),
            "--session-id",
            "cli-session",
            "--output",
            str(report),
        ]
    )
    export_result = capsys.readouterr()
    assert code == 0
    assert "exported 1 packet(s)" in export_result.out
    with report.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["protocol"] == "TCP"

    pdf_report = tmp_path / "report.pdf"
    code = main(
        [
            "export",
            "--storage-dir",
            str(storage),
            "--session-id",
            "cli-session",
            "--output",
            str(pdf_report),
            "--format",
            "pdf",
        ]
    )
    pdf_result = capsys.readouterr()
    assert code == 0
    assert "PDF" in pdf_result.out
    assert pdf_report.read_bytes().startswith(b"%PDF-1.4")


def test_cli_concurrent_replay_and_synthetic_alert_demo(tmp_path, capsys):
    source_a = tmp_path / "source-a.pcap"
    source_b = tmp_path / "source-b.pcap"
    create_demo_pcap(source_a)
    create_demo_pcap(source_b)
    storage = tmp_path / "captures"
    code = main(
        [
            "capture-multi",
            "--pcap-file",
            str(source_a),
            "--pcap-file",
            str(source_b),
            "--storage-dir",
            str(storage),
            "--session-id",
            "multi-session",
            "--count",
            "6",
        ]
    )
    result = capsys.readouterr()
    assert code == 0
    assert "stored=6" in result.out
    repository = __import__(
        "pocket_packet_sniffer.storage", fromlist=["PcapSqliteRepository"]
    ).PcapSqliteRepository(storage)
    records = repository.query_session("multi-session")
    assert len(records) == 6
    assert {record.interface for record in records} == {"source-a.pcap", "source-b.pcap"}
    assert {record.capture_backend for record in records} == {"pcap-file"}
    assert {record.link_type for record in records} == {1}


def test_cli_replay_reports_arp_conflict_as_heuristic_alert(tmp_path, capsys):
    source = tmp_path / "suspicious-demo.pcap"
    create_demo_pcap(source)
    storage = tmp_path / "captures"
    code = main(
        [
            "capture",
            "--pcap-file",
            str(source),
            "--storage-dir",
            str(storage),
            "--session-id",
            "alert-session",
        ]
    )
    result = capsys.readouterr()
    assert code == 0
    assert "arp-address-conflict" in result.err
    assert "suspected" in result.err
    assert "stored=5" in result.out


def test_cli_rejects_live_dashboard_for_file_replay(capsys, tmp_path):
    source = tmp_path / "empty.pcap"
    write_one_packet_pcap(source)
    code = main(["capture", "--pcap-file", str(source), "--live-dashboard"])
    output = capsys.readouterr()
    assert code == 2
    assert "--live-dashboard requires --interface" in output.err


def test_cli_query_requires_timezone_aware_dates(tmp_path):
    try:
        main(["query", "--storage-dir", str(tmp_path / "captures"), "--start", "2026-10-26T12:00:00"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("argparse should reject naive timestamps")
