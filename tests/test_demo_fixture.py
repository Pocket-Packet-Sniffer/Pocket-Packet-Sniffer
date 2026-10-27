from __future__ import annotations

import csv
from threading import Event

import pytest

from pocket_packet_sniffer.analysis.alerts import AlertBus, SuspiciousActivityDetector
from pocket_packet_sniffer.application.multi_session import MultiCaptureSession
from pocket_packet_sniffer.capture import PcapFileCapturer
from pocket_packet_sniffer.presentation.report_export import export_session_report_csv
from pocket_packet_sniffer.storage import PcapSqliteRepository
from tools.create_demo_pcaps import TRUSTED_MAC, create_demo_pcaps


def test_generated_demo_pcaps_exercise_multi_capture_alerts_and_csv(tmp_path):
    ethernet_path, wifi_path = create_demo_pcaps(tmp_path / "fixtures")
    repository = PcapSqliteRepository(tmp_path / "captures")
    events = []
    bus = AlertBus()
    bus.subscribe(events.append)
    detector = SuspiciousActivityDetector(
        trusted_devices=[TRUSTED_MAC],
        trusted_aps=[TRUSTED_MAC],
    )
    session = MultiCaptureSession(
        [PcapFileCapturer(ethernet_path), PcapFileCapturer(wifi_path)],
        repository,
        session_id="demo-run",
        alert_bus=bus,
        detector=detector,
    )

    result = session.run(Event())

    assert result.exit_code == 0
    assert result.packets_seen == 5
    assert result.packets_stored == 5
    assert session.statistics_snapshot()["total_packets"] == 5
    assert {event.rule_id for event in events} == {
        "ARP_SPOOFING_HEURISTIC",
        "UNRECOGNIZED_DEVICE",
        "ROGUE_AP_HEURISTIC",
    }
    records = repository.query()
    assert {record.interface for record in records} == {
        ethernet_path.name,
        wifi_path.name,
    }
    assert {record.protocol for record in records} >= {"ARP", "TCP", "DNS", "WIFI-BEACON"}

    ethernet_session = result.sessions[0].session_id
    summary = repository.get_session_summary(ethernet_session)
    report = tmp_path / "demo.csv"
    export_session_report_csv(summary, repository.query(session_id=ethernet_session), report)
    with report.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert rows
    assert all(row["interface"] == ethernet_path.name for row in rows)


def test_demo_generator_refuses_to_overwrite_existing_fixtures(tmp_path):
    paths = create_demo_pcaps(tmp_path / "fixtures")
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        create_demo_pcaps(tmp_path / "fixtures")
    assert all(path.is_file() for path in paths)
