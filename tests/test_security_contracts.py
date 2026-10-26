from __future__ import annotations

import os
import stat
from datetime import datetime, timezone

import pytest

from pocket_packet_sniffer.storage import PacketRecord, PcapSqliteRepository


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
