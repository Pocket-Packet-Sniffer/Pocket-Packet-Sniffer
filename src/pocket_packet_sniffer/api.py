"""Local API for dashboard reads and explicit capture start/stop controls."""
from __future__ import annotations

import io
import json
import os
import platform
import subprocess
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from scapy.all import get_if_list
try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    get_windows_if_list = None

from pocket_packet_sniffer.analysis.parser import PacketParser
from pocket_packet_sniffer.analysis.pipeline import AnalyzerPipeline
from pocket_packet_sniffer.application.session import CaptureSession
from pocket_packet_sniffer.capture import PcapFileCapturer, ScapyCapturer
from pocket_packet_sniffer.storage import PcapSqliteRepository

STORAGE_DIR = Path(os.getenv("PPS_STORAGE_DIR", "captures")).expanduser()
app = FastAPI(title="Pocket Packet Sniffer API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:4173", "http://localhost:4173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_capture_lock = threading.RLock()
_capture: dict = {"state": "idle", "session_id": None, "source": None, "interface": None, "started_at": None, "result": None, "error": None, "thread": None, "stop_event": None, "session": None}


class CaptureStart(BaseModel):
    mode: str = Field(default="interface", pattern="^(interface|pcap)$")
    interface: str = Field(default="Wi-Fi", min_length=1, max_length=256)
    pcap_path: str | None = Field(default=None, max_length=2048)
    bpf_filter: str | None = Field(default=None, max_length=2048)
    delay: float = Field(default=0.01, ge=0, le=2)


def get_repository() -> PcapSqliteRepository:
    return PcapSqliteRepository(STORAGE_DIR)


def packet_json(packet):
    return {"id": packet.record_id, "session_id": packet.session_id, "time": packet.timestamp.isoformat(), "protocol": packet.protocol, "source": packet.source_address, "destination": packet.destination_address, "length": len(packet.packet_data), "info": f"{packet.protocol} packet", "interface": packet.interface, "capture_backend": packet.capture_backend}


def capture_status():
    with _capture_lock:
        thread = _capture.get("thread")
        state = _capture["state"]
        if state in ("running", "stopping") and thread is not None and not thread.is_alive():
            # Reconcile the public state with the actual worker lifecycle. In
            # particular, a completed worker must never leave the UI stuck at
            # "stopping" just because the final status update raced a poll.
            if _capture.get("result") is None:
                session = _capture.get("session")
                if session is not None:
                    progress = session.result(0)
                    _capture["result"] = {
                        "session_id": progress.session_id,
                        "packets_seen": progress.packets_seen,
                        "packets_stored": progress.packets_stored,
                        "packets_ignored": progress.packets_ignored,
                        "exit_code": 0,
                    }
            _capture["state"] = "stopped"
            state = "stopped"
        result = _capture["result"]
        session = _capture.get("session")
        if state == "running" and session is not None:
            progress = session.result(0)
            result = {"session_id": progress.session_id, "packets_seen": progress.packets_seen, "packets_stored": progress.packets_stored, "packets_ignored": progress.packets_ignored, "exit_code": None}
        return {"state": state, "session_id": _capture["session_id"], "source": _capture["source"], "interface": _capture["interface"], "started_at": _capture["started_at"], "result": result, "error": _capture["error"]}


def _run_capture(session, stop_event):
    diagnostics = io.StringIO()
    try:
        result = session.run(stop_event, stderr=diagnostics)
        detail = diagnostics.getvalue().strip()
        with _capture_lock:
            _capture["result"] = {"session_id": result.session_id, "packets_seen": result.packets_seen, "packets_stored": result.packets_stored, "packets_ignored": result.packets_ignored, "exit_code": result.exit_code}
            if result.exit_code != 0:
                _capture["state"] = "error"
                _capture["error"] = detail or f"Capture stopped with exit code {result.exit_code}."
            else:
                _capture["state"] = "stopped"
                _capture["error"] = None
    except Exception as exc:
        with _capture_lock:
            _capture["state"] = "error"
            _capture["error"] = str(exc)


@app.get("/api/health")
def health():
    try:
        repository = get_repository()
        return {"status": "ok", "service": "pocket-packet-sniffer", "storage": str(repository.directory)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/capture/status")
def get_capture_status():
    return capture_status()


@app.get("/api/interfaces")
def interfaces():
    """Return capture interface names as Scapy sees them on this host."""
    try:
        raw_names = list(get_if_list())
        details = get_windows_if_list() if get_windows_if_list is not None else []
        def normalize(value):
            return str(value or "").strip().replace("/", "\\\\").casefold()

        # Scapy's Windows helper can expose only NPF names on some installs.
        # Ask Windows for its own adapter inventory and correlate NPF GUIDs.
        windows_by_guid = {}
        if platform.system() == "Windows":
            ps = (
                "$ErrorActionPreference='Stop'; "
                "$a=Get-NetAdapter -IncludeHidden | ForEach-Object { "
                "$ips=@(Get-NetIPAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue | "
                "Where-Object {$_.IPAddress} | ForEach-Object {$_.IPAddress}); "
                "[PSCustomObject]@{Name=$_.Name; InterfaceDescription=$_.InterfaceDescription; "
                "InterfaceGuid=([string]$_.InterfaceGuid); Status=[string]$_.Status; "
                "MacAddress=$_.MacAddress; IPs=$ips} }; "
                "$a | ConvertTo-Json -Depth 4 -Compress"
            )
            try:
                proc = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
                    capture_output=True, text=True, timeout=5, check=True,
                )
                inventory = json.loads(proc.stdout.strip() or "[]")
                if isinstance(inventory, dict):
                    inventory = [inventory]
                for adapter in inventory:
                    guid = str(adapter.get("InterfaceGuid") or "").strip().strip("{}").casefold()
                    if guid:
                        windows_by_guid[guid] = adapter
            except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
                windows_by_guid = {}

        def extract_guid(value):
            value = str(value or "")
            if "{" in value and "}" in value:
                return value[value.find("{") + 1:value.rfind("}")].strip().casefold()
            return value.strip().strip("{}").casefold()

        # Scapy versions differ in whether Windows adapter metadata is keyed
        # by the NPF path, GUID, or friendly name. Index all available forms.
        details_by_guid = {}
        by_name = {}
        for item in details or []:
            item_name = str(item.get("name") or "")
            if item_name:
                by_name[normalize(item_name)] = item
            for key in ("name", "guid", "interface_guid", "netid", "network_name"):
                value = item.get(key)
                if value:
                    details_by_guid[extract_guid(value)] = item

        result = []
        for name in raw_names:
            guid = extract_guid(name) if "NPF_" in name.upper() and "{" in name and "}" in name else ""
            item = details_by_guid.get(guid) or by_name.get(normalize(name), {})
            win = windows_by_guid.get(guid, {})
            ips = item.get("ips") or item.get("ip") or win.get("IPs") or []
            if isinstance(ips, str):
                ips = [ips]
            description = (
                win.get("InterfaceDescription") or win.get("Name")
                or item.get("description") or item.get("network_name") or item.get("name") or name
            )
            friendly_name = win.get("Name") or item.get("network_name") or item.get("name") or description
            status = win.get("Status") or item.get("status") or ("Up" if ips else "Unknown")
            is_pseudo = any(token in f"{description} {friendly_name} {name}".casefold() for token in ("wan miniport", "network monitor", "loopback", "wi-fi direct"))
            ipv4 = any(isinstance(ip, str) and ip.count(".") == 3 and not ip.startswith(("127.", "169.254.")) for ip in ips)
            result.append({
                "name": name,
                "description": description,
                "friendly_name": friendly_name,
                "ips": ips,
                "mac": win.get("MacAddress") or item.get("mac"),
                "status": status,
                "interface_guid": guid or None,
                "capture_candidate": status == "Up" and not is_pseudo,
                "recommended": status == "Up" and not is_pseudo and ipv4,
            })
        return {"interfaces": result}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not enumerate capture interfaces: {exc}") from exc


@app.post("/api/capture/start")
def start_capture(request: CaptureStart):
    with _capture_lock:
        thread = _capture.get("thread")
        if _capture["state"] in ("starting", "running", "stopping") and thread is not None and thread.is_alive():
            raise HTTPException(status_code=409, detail=f"A capture session is already {_capture['state']}. Wait for it to stop before starting another.")
        if _capture["state"] in ("starting", "running", "stopping") and (thread is None or not thread.is_alive()):
            capture_status()
        if request.mode == "pcap":
            if not request.pcap_path or not request.pcap_path.strip():
                raise HTTPException(status_code=422, detail="Provide an absolute path to a local classic PCAP file.")
            pcap_path = Path(request.pcap_path).expanduser()
            if not pcap_path.is_file():
                raise HTTPException(status_code=400, detail=f"PCAP file not found: {pcap_path}")
            capturer = PcapFileCapturer(pcap_path, delay=request.delay)
            source = "pcap"
            interface = str(pcap_path)
        else:
            try:
                available = set(get_if_list())
            except Exception as exc:
                raise HTTPException(status_code=503, detail=f"Could not enumerate Scapy capture interfaces: {exc}") from exc
            if request.interface not in available:
                raise HTTPException(status_code=422, detail="The selected adapter is no longer available. Refresh the interface list and select an active adapter.")
            if platform.system() == "Windows" and get_windows_if_list is not None:
                try:
                    details = get_windows_if_list() or []
                    selected = next((item for item in details if str(item.get("name") or "").strip().casefold() == request.interface.strip().casefold()), {})
                    description = str(selected.get("description") or selected.get("network_name") or "")
                    if any(token in description.casefold() for token in ("wan miniport", "network monitor", "loopback", "wi-fi direct")):
                        raise HTTPException(status_code=422, detail=f"'{description}' is a Windows pseudo-interface, not a normal network adapter. Select your connected Wi-Fi or Ethernet adapter.")
                except HTTPException:
                    raise
                except Exception:
                    pass
            try:
                capturer = ScapyCapturer(request.interface, bpf_filter=request.bpf_filter)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            source = "interface"
            interface = request.interface
        session_id = str(uuid.uuid4())
        stop_event = threading.Event()
        try:
            session = CaptureSession(capturer, get_repository(), session_id=session_id, analyzer=AnalyzerPipeline([PacketParser()]))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Could not initialize capture storage: {exc}") from exc
        thread = threading.Thread(target=_run_capture, args=(session, stop_event), name=f"pps-capture-{session_id[:8]}", daemon=True)
        _capture.update({"state":"running","session_id":session_id,"source":source,"interface":interface,"started_at":__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),"result":None,"error":None,"thread":thread,"stop_event":stop_event,"session":session})
        thread.start()
        return capture_status()


@app.post("/api/capture/stop")
def stop_capture():
    with _capture_lock:
        state = _capture["state"]
        thread = _capture.get("thread")
        if state == "stopping":
            # Idempotent stop: repeated clicks/retries return the same state
            # instead of a misleading 409 while the driver is shutting down.
            return {"state":"stopping","session_id":_capture["session_id"],"stop_requested":True,"worker_alive":bool(thread and thread.is_alive())}
        if state != "running":
            # Reconcile a worker that completed between the UI poll and click.
            if thread is not None and not thread.is_alive():
                capture_status()
                return capture_status()
            raise HTTPException(status_code=409, detail="No capture session is currently running.")
        _capture["state"] = "stopping"
        stop_event = _capture.get("stop_event")
        if stop_event is not None:
            stop_event.set()
        # Never join the driver on the HTTP request thread. The worker closes
        # the sniffer and writes final counters asynchronously.
        return {"state":"stopping","session_id":_capture["session_id"],"stop_requested":True,"worker_alive":bool(thread and thread.is_alive())}


@app.get("/api/sessions")
def sessions():
    try:
        repository = get_repository()
        return [{"session_id": item.session_id, "packet_count": item.packet_count, "first_packet_at": item.first_packet_at.isoformat() if item.first_packet_at else None, "last_packet_at": item.last_packet_at.isoformat() if item.last_packet_at else None} for item in repository.list_sessions()]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/packets")
def packets(session_id: str | None = None, protocol: str | None = None, address: str | None = None, limit: int = Query(default=100, ge=1, le=1000)):
    try:
        records = get_repository().query(session_id=session_id, protocol=protocol, address=address)
        records = list(reversed(records[-limit:]))
        return {"count": len(records), "packets": [packet_json(packet) for packet in records]}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/overview")
def overview():
    try:
        repository = get_repository()
        records = repository.query()
        protocol_counts = {}
        address_counts = {}
        for packet in records:
            protocol_counts[packet.protocol] = protocol_counts.get(packet.protocol, 0) + 1
            for address in (packet.source_address, packet.destination_address):
                if address:
                    address_counts[address] = address_counts.get(address, 0) + 1
        return {"total_packets":len(records),"total_bytes":sum(len(packet.packet_data) for packet in records),"active_sessions":len(repository.list_sessions()),"protocols":protocol_counts,"top_talkers":sorted(address_counts.items(),key=lambda item:item[1],reverse=True)[:5]}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
