"""Local API for dashboard reads and explicit capture start/stop controls."""
from __future__ import annotations

import os
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

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
_capture: dict = {"state": "idle", "session_id": None, "source": None, "interface": None, "started_at": None, "result": None, "error": None, "thread": None, "stop_event": None}


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
        if state == "running" and thread is not None and not thread.is_alive():
            _capture["state"] = "stopped"
            state = "stopped"
        return {k: _capture[k] for k in ("state", "session_id", "source", "interface", "started_at", "result", "error")}


def _run_capture(session, stop_event):
    try:
        result = session.run(stop_event)
        with _capture_lock:
            _capture["result"] = {"session_id": result.session_id, "packets_seen": result.packets_seen, "packets_stored": result.packets_stored, "packets_ignored": result.packets_ignored, "exit_code": result.exit_code}
            if _capture["state"] != "error":
                _capture["state"] = "stopped"
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


@app.post("/api/capture/start")
def start_capture(request: CaptureStart):
    with _capture_lock:
        thread = _capture.get("thread")
        if _capture["state"] == "running" and thread is not None and thread.is_alive():
            raise HTTPException(status_code=409, detail="A capture session is already running.")
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
        _capture.update({"state":"running","session_id":session_id,"source":source,"interface":interface,"started_at":__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),"result":None,"error":None,"thread":thread,"stop_event":stop_event})
        thread.start()
        return capture_status()


@app.post("/api/capture/stop")
def stop_capture():
    with _capture_lock:
        if _capture["state"] != "running":
            raise HTTPException(status_code=409, detail="No capture session is currently running.")
        _capture["state"] = "stopping"
        stop_event = _capture.get("stop_event")
        if stop_event is not None:
            stop_event.set()
        return {"state":"stopping","session_id":_capture["session_id"]}


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
