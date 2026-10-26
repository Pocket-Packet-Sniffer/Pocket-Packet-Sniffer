from __future__ import annotations

import csv
import struct
from pathlib import Path

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
