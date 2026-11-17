"""Start the local capture API for the hosted PocketSniff dashboard."""
from __future__ import annotations

import os
import sys
from pathlib import Path

_DASHBOARD_ORIGIN = "https://pocket-packet-sniffer.vercel.app"
_LOCAL_ORIGINS = ("http://127.0.0.1:5173", "http://localhost:5173")


def _default_storage_directory() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "PocketPacketSniffer" / "captures"


def _configure_environment() -> tuple[str, tuple[str, ...]]:
    storage_directory = os.environ.setdefault(
        "PPS_STORAGE_DIR", str(_default_storage_directory())
    )
    configured_origins = [
        origin.strip()
        for origin in os.environ.get("PPS_ALLOWED_ORIGINS", "").split(",")
        if origin.strip()
    ]
    allowed_origins = tuple(
        dict.fromkeys((_DASHBOARD_ORIGIN, *_LOCAL_ORIGINS, *configured_origins))
    )
    os.environ["PPS_ALLOWED_ORIGINS"] = ",".join(allowed_origins)
    return storage_directory, allowed_origins


def main() -> int:
    """Run the loopback-only agent without requiring a project checkout."""
    storage_directory, _ = _configure_environment()

    import uvicorn

    from pocket_packet_sniffer.api import app

    print("Pocket Packet Sniffer local capture agent", flush=True)
    print(f"Dashboard: {_DASHBOARD_ORIGIN}", flush=True)
    print("Keep this window open. Choose an adapter and start capture in the dashboard.", flush=True)
    print("The agent listens only on this computer at http://127.0.0.1:8000.", flush=True)
    print(f"Capture files: {storage_directory}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
