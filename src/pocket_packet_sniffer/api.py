"""Local API for dashboard reads and explicit capture start/stop controls."""
from __future__ import annotations

import io
import json
import os
import platform
import subprocess
import threading
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from scapy.all import get_if_list
from scapy.config import conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from starlette.background import BackgroundTask
from starlette.responses import FileResponse, JSONResponse

from pocket_packet_sniffer.analysis.alerts import (
    AlertEvent,
    AlertPublisher,
    SuspiciousActivityDetector,
)

try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    get_windows_if_list = None

from pocket_packet_sniffer.analysis.parser import PacketParser
from pocket_packet_sniffer.analysis.pipeline import AnalyzerPipeline
from pocket_packet_sniffer.application.session import CaptureSession
from pocket_packet_sniffer.capture import (
    ConcurrentCapturer,
    PcapFileCapturer,
    ScapyCapturer,
)
from pocket_packet_sniffer.presentation.report_export import export_session_report_csv
from pocket_packet_sniffer.presentation.report_pdf import export_session_report_pdf
from pocket_packet_sniffer.storage import PcapSqliteRepository

STORAGE_DIR = Path(os.getenv("PPS_STORAGE_DIR", "captures")).expanduser()
_default_origins = "http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:4173,http://localhost:4173"
_allowed_origins = list(dict.fromkeys(
    origin.strip()
    for origin in f"{_default_origins},{os.getenv('PPS_ALLOWED_ORIGINS', '')}".split(",")
    if origin.strip()
))
app = FastAPI(title="Pocket Packet Sniffer API", version="0.2.1")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def validate_browser_origin(request: Request, call_next):
    """Reject cross-site browser writes to the loopback capture agent."""
    origin = request.headers.get("origin")
    if request.method == "POST" and origin and origin not in _allowed_origins:
        return JSONResponse(status_code=403, content={"detail": "This website is not allowed to control the local capture agent."})
    return await call_next(request)

_capture_lock = threading.RLock()
_alerts_lock = threading.Lock()
_alert_history: deque[dict] = deque(maxlen=500)
_capture: dict = {"state": "idle", "session_id": None, "source": None, "interface": None, "started_at": None, "result": None, "error": None, "thread": None, "stop_event": None, "session": None}


class CaptureStart(BaseModel):
    mode: str = Field(default="interface", pattern="^(interface|pcap)$")
    interface: str = Field(default="Wi-Fi", min_length=1, max_length=256)
    interfaces: list[str] | None = Field(default=None, max_length=16)
    pcap_path: str | None = Field(default=None, max_length=2048)
    upload_id: str | None = Field(default=None, max_length=64)
    bpf_filter: str | None = Field(default=None, max_length=2048)
    delay: float = Field(default=0.01, ge=0, le=2)
    known_devices: list[str] | None = Field(default=None, max_length=256)
    known_access_points: list[str] | None = Field(default=None, max_length=256)


def get_repository() -> PcapSqliteRepository:
    return PcapSqliteRepository(STORAGE_DIR)


def packet_json(packet):
    source_mac = destination_mac = None
    source_port = destination_port = None
    transport = None
    tcp_flags = None
    ttl = None
    try:
        link_layer = conf.l2types.get(packet.link_type)
        decoded = link_layer(packet.packet_data) if link_layer else None
        if decoded is not None:
            if decoded.haslayer(Ether):
                source_mac = decoded[Ether].src
                destination_mac = decoded[Ether].dst
            if decoded.haslayer(IP):
                ttl = decoded[IP].ttl
            elif decoded.haslayer(IPv6):
                ttl = decoded[IPv6].hlim
            if decoded.haslayer(TCP):
                layer = decoded[TCP]
                source_port, destination_port = layer.sport, layer.dport
                transport, tcp_flags = "TCP", str(layer.flags)
            elif decoded.haslayer(UDP):
                layer = decoded[UDP]
                source_port, destination_port = layer.sport, layer.dport
                transport = "UDP"
    except Exception:  # noqa: BLE001 - malformed packets remain inspectable by stored metadata.
        pass
    return {
        "id": packet.record_id,
        "session_id": packet.session_id,
        "time": packet.timestamp.isoformat(),
        "protocol": packet.protocol,
        "source": packet.source_address,
        "destination": packet.destination_address,
        "source_mac": source_mac,
        "destination_mac": destination_mac,
        "source_port": source_port,
        "destination_port": destination_port,
        "transport": transport,
        "tcp_flags": tcp_flags,
        "ttl": ttl,
        "length": len(packet.packet_data),
        "original_length": packet.original_length,
        "info": f"{packet.protocol} packet",
        "interface": packet.interface,
        "capture_backend": packet.capture_backend,
    }


def _store_alert(session_id: str, event: AlertEvent) -> None:
    with _alerts_lock:
        _alert_history.appendleft(
            {
                "id": str(uuid.uuid4()),
                "session_id": session_id,
                "rule_id": event.rule_id,
                "severity": event.severity,
                "message": event.message,
                "time": event.timestamp.isoformat(),
                "evidence": dict(event.evidence),
            }
        )


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
    finally:
        with _capture_lock:
            temporary_pcap = _capture.get("temporary_pcap")
            _capture["temporary_pcap"] = None
        if temporary_pcap is not None:
            Path(temporary_pcap).unlink(missing_ok=True)


@app.get("/api/health")
def health():
    try:
        repository = get_repository()
        return {
            "status": "ok",
            "service": "pocket-packet-sniffer",
            "version": app.version,
            "storage": str(repository.directory),
        }
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/capture/status")
def get_capture_status():
    return capture_status()


@app.get("/api/alerts")
def alerts(limit: int = Query(default=100, ge=1, le=500)):
    """Return bounded, metadata-only heuristic alerts from this API process."""
    with _alerts_lock:
        return {"alerts": list(_alert_history)[:limit]}


@app.get("/api/statistics")
def statistics():
    """Return rolling live counters from the active or most recent session."""
    with _capture_lock:
        session = _capture.get("session")
    if session is None:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "packets_per_sec": 0.0,
            "protocols": [],
            "top_talkers": [],
        }
    return session.statistics_snapshot()


@app.post("/api/capture/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Stage an explicitly selected classic PCAP on this computer only."""
    if Path(file.filename or "").suffix.casefold() not in {".pcap", ".cap"}:
        raise HTTPException(status_code=415, detail="Choose a classic PCAP file (.pcap or .cap). PCAPNG is not supported.")
    repository = get_repository()
    upload_directory = repository.directory / ".uploads"
    upload_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    upload_id = uuid.uuid4().hex
    destination = upload_directory / f"{upload_id}.pcap"
    byte_count = 0
    try:
        with destination.open("xb") as output:
            while chunk := await file.read(1024 * 1024):
                byte_count += len(chunk)
                if byte_count > 100 * 1024 * 1024:
                    raise HTTPException(status_code=413, detail="PCAP files must be 100 MB or smaller.")
                output.write(chunk)
        with destination.open("rb") as uploaded:
            magic = uploaded.read(4)
        if magic not in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}:
            raise HTTPException(status_code=415, detail="This file is not a supported classic PCAP capture.")
    except HTTPException:
        destination.unlink(missing_ok=True)
        raise
    except OSError as exc:
        destination.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="The local sensor could not stage that PCAP file.") from exc
    finally:
        await file.close()
    with _capture_lock:
        _capture.setdefault("uploaded_pcaps", {})[upload_id] = destination
    return {"upload_id": upload_id, "filename": Path(file.filename).name, "size": byte_count}


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
            with _capture_lock:
                uploaded_pcaps = _capture.get("uploaded_pcaps", {})
                uploaded_path = uploaded_pcaps.pop(request.upload_id, None) if request.upload_id else None
            if request.upload_id and uploaded_path is None:
                raise HTTPException(status_code=404, detail="That PCAP upload expired. Choose the file again.")
            if not uploaded_path and (not request.pcap_path or not request.pcap_path.strip()):
                raise HTTPException(status_code=422, detail="Choose a local classic PCAP file to replay.")
            pcap_path = Path(uploaded_path or request.pcap_path).expanduser()
            if not pcap_path.is_file():
                raise HTTPException(status_code=400, detail=f"PCAP file not found: {pcap_path}")
            capturer = PcapFileCapturer(pcap_path, delay=request.delay)
            source = "pcap"
            interface = str(pcap_path)
        else:
            interface_names = list(dict.fromkeys(request.interfaces or [request.interface]))
            if not interface_names or any(not name.strip() for name in interface_names):
                raise HTTPException(status_code=422, detail="Choose at least one valid network adapter.")
            try:
                available = set(get_if_list())
            except Exception as exc:
                raise HTTPException(status_code=503, detail=f"Could not enumerate Scapy capture interfaces: {exc}") from exc
            unavailable = [name for name in interface_names if name not in available]
            if unavailable:
                raise HTTPException(status_code=422, detail=f"These adapters are no longer available: {', '.join(unavailable)}. Refresh the adapter list and try again.")
            if platform.system() == "Windows" and get_windows_if_list is not None:
                try:
                    details = get_windows_if_list() or []
                    for interface_name in interface_names:
                        selected = next((item for item in details if str(item.get("name") or "").strip().casefold() == interface_name.strip().casefold()), {})
                        description = str(selected.get("description") or selected.get("network_name") or "")
                        if any(token in description.casefold() for token in ("wan miniport", "network monitor", "loopback", "wi-fi direct")):
                            raise HTTPException(status_code=422, detail=f"'{description}' is a Windows pseudo-interface, not a normal network adapter. Select a connected Wi-Fi or Ethernet adapter.")
                except HTTPException:
                    raise
                except Exception:
                    pass
            try:
                capturers = [ScapyCapturer(name, bpf_filter=request.bpf_filter) for name in interface_names]
                capturer = capturers[0] if len(capturers) == 1 else ConcurrentCapturer(capturers)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            source = "interface" if len(interface_names) == 1 else "concurrent"
            interface = ", ".join(interface_names)
        session_id = str(uuid.uuid4())
        stop_event = threading.Event()
        publisher = AlertPublisher()
        publisher.subscribe(lambda event: _store_alert(session_id, event))
        detector = SuspiciousActivityDetector(
            publisher,
            known_devices={
                item.strip()
                for item in (request.known_devices if request.known_devices is not None else os.getenv("PPS_KNOWN_DEVICES", "").split(","))
                if item.strip()
            },
            known_access_points={
                item.strip()
                for item in (request.known_access_points if request.known_access_points is not None else os.getenv("PPS_KNOWN_ACCESS_POINTS", "").split(","))
                if item.strip()
            },
        )
        try:
            session = CaptureSession(capturer, get_repository(), session_id=session_id, analyzer=AnalyzerPipeline([PacketParser()]), alert_detector=detector)
        except Exception as exc:
            if request.mode == "pcap" and request.upload_id and uploaded_path:
                uploaded_path.unlink(missing_ok=True)
            raise HTTPException(status_code=500, detail=f"Could not initialize capture storage: {exc}") from exc
        thread = threading.Thread(target=_run_capture, args=(session, stop_event), name=f"pps-capture-{session_id[:8]}", daemon=True)
        _capture.update({"state":"running","session_id":session_id,"source":source,"interface":interface,"started_at":datetime.now().astimezone().isoformat(),"result":None,"error":None,"thread":thread,"stop_event":stop_event,"session":session,"temporary_pcap":uploaded_path if request.mode == "pcap" and request.upload_id else None})
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
def packets(
    session_id: str | None = None,
    protocol: str | None = None,
    address: str | None = None,
    search: str | None = Query(default=None, max_length=256),
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0, le=10_000_000),
):
    try:
        for endpoint in (start, end):
            if endpoint is not None and (endpoint.tzinfo is None or endpoint.utcoffset() is None):
                raise HTTPException(status_code=422, detail="Time filters must include a timezone.")
        if start is not None and end is not None and start > end:
            raise HTTPException(status_code=422, detail="The start time must be earlier than the end time.")
        records = get_repository().query(
            session_id=session_id,
            protocol=protocol.upper() if protocol else None,
            address=address,
            time_window=(start, end) if start is not None or end is not None else None,
        )
        if search:
            needle = search.casefold().strip()
            records = [
                record
                for record in records
                if needle in " ".join(
                    (record.record_id, record.session_id, record.protocol,
                     record.source_address or "", record.destination_address or "",
                     record.interface or "", record.capture_backend or "")
                ).casefold()
            ]
        total = len(records)
        newest_first = list(reversed(records))
        page = newest_first[offset : offset + limit]
        return {"total": total, "count": len(page), "limit": limit, "offset": offset, "packets": [packet_json(packet) for packet in page]}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/sessions/{session_id}/report")
def session_report(session_id: str, format: str = Query(default="csv", pattern="^(csv|pdf)$")):
    """Download an explicitly requested metadata-only session report."""
    repository = get_repository()
    try:
        summary = repository.get_session_summary(session_id)
        if summary.packet_count == 0:
            raise HTTPException(status_code=404, detail="No saved capture session has that ID.")
        records = repository.query_session(session_id)
        suffix = format.lower()
        path = repository.directory / f".session-report-{uuid.uuid4().hex}.{suffix}"
        if suffix == "csv":
            export_session_report_csv(summary, records, path)
            media_type = "text/csv"
        else:
            export_session_report_pdf(summary, records, path)
            media_type = "application/pdf"
        return FileResponse(
            path,
            media_type=media_type,
            filename=f"pocket-packet-sniffer-session.{suffix}",
            background=BackgroundTask(lambda: path.unlink(missing_ok=True)),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not export this local capture report: {exc}") from exc


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
