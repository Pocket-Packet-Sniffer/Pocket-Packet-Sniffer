import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from pocket_packet_sniffer.storage import PcapSqliteRepository

STORAGE_DIR = Path(os.getenv("PPS_STORAGE_DIR", "captures"))
app = FastAPI(title="Pocket Packet Sniffer API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:4173", "http://localhost:4173"],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)

def get_repository():
    return PcapSqliteRepository(STORAGE_DIR)

def packet_json(packet):
    return {
        "id": packet.record_id,
        "session_id": packet.session_id,
        "time": packet.timestamp.isoformat(),
        "protocol": packet.protocol,
        "source": packet.source_address,
        "destination": packet.destination_address,
        "length": len(packet.packet_data),
        "info": f"{packet.protocol} packet",
        "interface": packet.interface,
        "capture_backend": packet.capture_backend,
    }

@app.get("/api/health")
def health():
    try:
        repository = get_repository()
        return {"status": "ok", "service": "pocket-packet-sniffer", "storage": str(repository.directory)}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.get("/api/sessions")
def sessions():
    try:
        repository = get_repository()
        return [{
            "session_id": item.session_id,
            "packet_count": item.packet_count,
            "first_packet_at": item.first_packet_at.isoformat() if item.first_packet_at else None,
            "last_packet_at": item.last_packet_at.isoformat() if item.last_packet_at else None,
        } for item in repository.list_sessions()]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

@app.get("/api/packets")
def packets(session_id: str | None = None, protocol: str | None = None, address: str | None = None, limit: int = Query(default=100, ge=1, le=1000)):
    try:
        repository = get_repository()
        records = repository.query(session_id=session_id, protocol=protocol, address=address)
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
        return {
            "total_packets": len(records),
            "total_bytes": sum(len(packet.packet_data) for packet in records),
            "active_sessions": len(repository.list_sessions()),
            "protocols": protocol_counts,
            "top_talkers": sorted(address_counts.items(), key=lambda item: item[1], reverse=True)[:5],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
