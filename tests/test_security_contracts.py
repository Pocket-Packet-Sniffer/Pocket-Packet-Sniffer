from __future__ import annotations

import ast
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest

from pocket_packet_sniffer.storage import PacketRecord, PcapSqliteRepository


def test_capture_backends_do_not_call_packet_transmission_apis():
    forbidden_apis = {
        "send",
        "sendp",
        "sendpfast",
        "sr",
        "sr1",
        "srp",
        "srp1",
        "srloop",
        "srploop",
    }
    capture_dir = Path(__file__).resolve().parents[1] / "src" / "pocket_packet_sniffer" / "capture"

    for source_path in capture_dir.glob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                function = node.func
                name = function.id if isinstance(function, ast.Name) else function.attr if isinstance(function, ast.Attribute) else None
                assert name not in forbidden_apis, f"{source_path.name} calls prohibited packet API {name}"
            elif isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("scapy"):
                imported_apis = {alias.name for alias in node.names} & forbidden_apis
                assert not imported_apis, f"{source_path.name} imports prohibited packet APIs: {sorted(imported_apis)}"


@pytest.mark.skipif(os.name != "posix", reason="POSIX file-mode checks do not apply to Windows ACLs")
def test_capture_storage_uses_private_directory_and_file_modes(tmp_path):
    capture_dir = tmp_path / "private-captures"
    repository = PcapSqliteRepository(capture_dir)
    repository.save(
        PacketRecord(
            session_id="security-test",
            protocol="TEST",
            source_address="192.0.2.1",
            destination_address="192.0.2.2",
            timestamp=datetime.now(timezone.utc),
            packet_data=b"synthetic-frame",
            link_type=1,
        )
    )

    directory_mode = stat.S_IMODE(capture_dir.stat().st_mode)
    database_mode = stat.S_IMODE(repository.database_path.stat().st_mode)
    pcap_path = next(capture_dir.glob("*.pcap"))
    pcap_mode = stat.S_IMODE(pcap_path.stat().st_mode)

    assert directory_mode & 0o077 == 0
    assert database_mode == 0o600
    assert pcap_mode == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX file-mode checks do not apply to Windows ACLs")
def test_existing_capture_directory_is_tightened_to_private_mode(tmp_path):
    capture_dir = tmp_path / "existing-captures"
    capture_dir.mkdir()
    capture_dir.chmod(0o755)

    PcapSqliteRepository(capture_dir)

    assert stat.S_IMODE(capture_dir.stat().st_mode) == 0o700
