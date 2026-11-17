from __future__ import annotations

from pathlib import Path

from pocket_packet_sniffer.agent import _configure_environment


def test_agent_configures_dashboard_and_local_origins(monkeypatch, tmp_path):
    monkeypatch.setenv("PPS_STORAGE_DIR", str(tmp_path / "captures"))
    monkeypatch.setenv(
        "PPS_ALLOWED_ORIGINS",
        "https://custom.example,https://pocket-packet-sniffer.vercel.app",
    )

    storage, origins = _configure_environment()

    assert storage == str(tmp_path / "captures")
    assert origins == (
        "https://pocket-packet-sniffer.vercel.app",
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "https://custom.example",
    )
    assert origins.count("https://pocket-packet-sniffer.vercel.app") == 1


def test_agent_defaults_storage_outside_source_checkout(monkeypatch, tmp_path):
    monkeypatch.delenv("PPS_STORAGE_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    storage, _ = _configure_environment()

    assert Path(storage).parts[-2:] == ("PocketPacketSniffer", "captures")
