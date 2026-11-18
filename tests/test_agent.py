from __future__ import annotations

import sys
import types
from pathlib import Path, PurePosixPath

from pocket_packet_sniffer import agent
from pocket_packet_sniffer.agent import _configure_environment
from pocket_packet_sniffer.api import app


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


def test_agent_uses_xdg_storage_on_linux(monkeypatch, tmp_path):
    monkeypatch.setattr(agent.os, "name", "posix")
    monkeypatch.setattr(agent.sys, "platform", "linux")
    monkeypatch.setattr(agent, "Path", PurePosixPath)
    monkeypatch.setattr(PurePosixPath, "home", classmethod(lambda _cls: PurePosixPath("/home/demo")), raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", "/var/lib/demo")

    assert agent._default_storage_directory() == PurePosixPath("/var/lib/demo/PocketPacketSniffer/captures")


def test_agent_uses_application_support_on_macos(monkeypatch, tmp_path):
    monkeypatch.setattr(agent.os, "name", "posix")
    monkeypatch.setattr(agent.sys, "platform", "darwin")
    monkeypatch.setattr(agent, "Path", PurePosixPath)
    monkeypatch.setattr(PurePosixPath, "home", classmethod(lambda _cls: PurePosixPath("/Users/demo")), raising=False)

    assert agent._default_storage_directory() == PurePosixPath("/Users/demo/Library/Application Support/PocketPacketSniffer/captures")


def test_agent_main_starts_loopback_uvicorn_and_prints_storage(monkeypatch, tmp_path, capsys):
    calls = []
    fake_uvicorn = types.SimpleNamespace(run=lambda *args, **kwargs: calls.append((args, kwargs)))
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)
    monkeypatch.setenv("PPS_STORAGE_DIR", str(tmp_path / "captures"))

    assert agent.main() == 0

    assert calls == [((app,), {"host": "127.0.0.1", "port": 8000, "log_level": "info"})]
    output = capsys.readouterr().out
    assert "http://127.0.0.1:8000" in output
    assert str(tmp_path / "captures") in output
