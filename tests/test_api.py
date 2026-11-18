from __future__ import annotations

import struct
import types
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from pocket_packet_sniffer import api
from pocket_packet_sniffer.storage import PacketRecord, PcapSqliteRepository
from pocket_packet_sniffer.version import __version__


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "STORAGE_DIR", tmp_path / "captures")
    with api._capture_lock:
        api._capture.clear()
        api._capture.update(
            {
                "state": "idle",
                "session_id": None,
                "source": None,
                "interface": None,
                "started_at": None,
                "result": None,
                "error": None,
                "thread": None,
                "stop_event": None,
                "session": None,
                "uploaded_pcaps": {},
                "temporary_pcap": None,
            }
        )
    api._alert_history.clear()
    with TestClient(api.app) as test_client:
        yield test_client


def _packet(
    *,
    record_id: str,
    session_id: str,
    timestamp: datetime,
    protocol: str = "TCP",
    data: bytes = b"opaque-payload-marker",
) -> PacketRecord:
    return PacketRecord(
        record_id=record_id,
        session_id=session_id,
        timestamp=timestamp,
        protocol=protocol,
        source_address="192.0.2.10",
        destination_address="198.51.100.20",
        packet_data=data,
        interface="Ethernet",
        capture_backend="scapy-live",
    )


def test_packet_search_time_filter_pagination_and_safe_transport_metadata(client, tmp_path):
    repository = PcapSqliteRepository(tmp_path / "captures")
    first_time = datetime(2026, 11, 1, tzinfo=timezone.utc)
    tcp_frame = raw(
        Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20")
        / IP(src="192.0.2.10", dst="198.51.100.20", ttl=61)
        / TCP(sport=43123, dport=443, flags="S")
    )
    repository.save(
        _packet(
            record_id="older-tcp",
            session_id="first-session",
            timestamp=first_time,
            data=tcp_frame,
        )
    )
    repository.save(
        _packet(
            record_id="newer-udp",
            session_id="second-session",
            timestamp=first_time + timedelta(seconds=5),
            protocol="UDP",
        )
    )

    response = client.get(
        "/api/packets",
        params={
            "search": "older",
            "protocol": "tcp",
            "session_id": "first-session",
            "start": first_time.isoformat(),
            "end": (first_time + timedelta(seconds=1)).isoformat(),
            "limit": 1,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert [item["id"] for item in body["packets"]] == ["older-tcp"]
    packet = body["packets"][0]
    assert (packet["source_port"], packet["destination_port"]) == (43123, 443)
    assert packet["tcp_flags"] == "S"
    assert packet["ttl"] == 61
    assert packet["source_mac"] == "02:00:00:00:00:10"
    assert "opaque-payload-marker" not in response.text


def test_dashboard_summaries_and_packet_pages_use_saved_capture_records(client, tmp_path):
    repository = PcapSqliteRepository(tmp_path / "captures")
    timestamp = datetime(2026, 11, 2, tzinfo=timezone.utc)
    repository.save(_packet(record_id="first", session_id="live-session", timestamp=timestamp))
    repository.save(
        _packet(
            record_id="second",
            session_id="live-session",
            timestamp=timestamp + timedelta(seconds=1),
            protocol="UDP",
        )
    )

    overview = client.get("/api/overview").json()
    statistics = client.get("/api/statistics").json()
    first_page = client.get("/api/packets", params={"limit": 1}).json()
    second_page = client.get("/api/packets", params={"limit": 1, "offset": 1}).json()
    searched = client.get("/api/packets", params={"search": "first"}).json()

    assert overview["total_packets"] == 2
    assert overview["total_bytes"] == len(b"opaque-payload-marker") * 2
    assert overview["active_sessions"] == 1
    assert overview["protocols"] == {"TCP": 1, "UDP": 1}
    assert statistics["total_packets"] == 2
    assert first_page["total"] == 2
    assert first_page["packets"][0]["id"] == "second"
    assert second_page["packets"][0]["id"] == "first"
    assert searched["total"] == 1
    assert searched["packets"][0]["id"] == "first"


@pytest.mark.parametrize(
    ("params", "detail"),
    [
        ({"start": "2026-11-01T00:00:00"}, "timezone"),
        (
            {
                "start": "2026-11-02T00:00:00+00:00",
                "end": "2026-11-01T00:00:00+00:00",
            },
            "earlier",
        ),
    ],
)
def test_packet_time_filter_rejects_invalid_windows(client, params, detail):
    response = client.get("/api/packets", params=params)

    assert response.status_code == 422
    assert detail in response.json()["detail"]


def test_explicit_pcap_upload_stays_in_local_staging_and_rejects_non_pcap(client, tmp_path):
    pcap_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    accepted = client.post(
        "/api/capture/upload",
        files={"file": ("authorized-capture.pcap", pcap_header, "application/octet-stream")},
    )

    assert accepted.status_code == 200
    body = accepted.json()
    assert body["filename"] == "authorized-capture.pcap"
    staged_path = api._capture["uploaded_pcaps"][body["upload_id"]]
    assert staged_path.parent == tmp_path / "captures" / ".uploads"
    assert staged_path.read_bytes() == pcap_header

    rejected = client.post(
        "/api/capture/upload",
        files={"file": ("traffic.pcapng", b"not-a-classic-pcap", "application/octet-stream")},
    )
    assert rejected.status_code == 415


def test_browser_write_rejects_unapproved_website_origin(client):
    response = client.post(
        "/api/capture/stop",
        headers={"Origin": "https://unexpected.example"},
    )

    assert response.status_code == 403
    assert "not allowed" in response.json()["detail"]


def test_uploaded_pcap_replays_through_analysis_storage_and_cleans_staging_file(client):
    frame = raw(Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=43123, dport=443, flags="S"))
    timestamp = int(datetime(2026, 11, 1, tzinfo=timezone.utc).timestamp())
    pcap = b"".join(
        (
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1),
            struct.pack("<IIII", timestamp, 0, len(frame), len(frame)),
            frame,
        )
    )
    uploaded = client.post(
        "/api/capture/upload",
        files={"file": ("authorized-session.pcap", pcap, "application/octet-stream")},
    )
    upload_id = uploaded.json()["upload_id"]
    staged_path = api._capture["uploaded_pcaps"][upload_id]

    started = client.post(
        "/api/capture/start", json={"mode": "pcap", "upload_id": upload_id, "delay": 0}
    )
    assert started.status_code == 200
    thread = api._capture["thread"]
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert not staged_path.exists()
    packets = client.get("/api/packets", params={"session_id": started.json()["session_id"]})
    assert packets.status_code == 200
    assert packets.json()["total"] == 1
    assert packets.json()["packets"][0]["destination_port"] == 443


def test_multi_adapter_start_uses_the_shared_concurrent_capture_contract(client, monkeypatch):
    created = []

    class IdleCapturer:
        def __init__(self, interface, *, bpf_filter=None):
            self.interface = interface
            self.bpf_filter = bpf_filter
            created.append(self)

        def capture(self, on_packet, stop_event, count=None):
            stop_event.wait(3)

    class ConcurrentProbe:
        def __init__(self, capturers):
            self.capturers = capturers

        def capture(self, on_packet, stop_event, count=None):
            stop_event.wait(3)

    monkeypatch.setattr(api, "platform", type("Platform", (), {"system": staticmethod(lambda: "Linux")})())
    monkeypatch.setattr(api, "get_if_list", lambda: ["wifi0", "eth0"])
    monkeypatch.setattr(api, "ScapyCapturer", IdleCapturer)
    monkeypatch.setattr(api, "ConcurrentCapturer", ConcurrentProbe)

    started = client.post(
        "/api/capture/start",
        json={"mode": "interface", "interface": "wifi0", "interfaces": ["wifi0", "eth0"]},
    )

    assert started.status_code == 200
    assert started.json()["source"] == "concurrent"
    assert started.json()["interface"] == "wifi0, eth0"
    assert [capturer.interface for capturer in created] == ["wifi0", "eth0"]
    client.post("/api/capture/stop")
    api._capture["thread"].join(timeout=5)


def test_session_report_downloads_csv_and_pdf_without_packet_payload(client, tmp_path):
    repository = PcapSqliteRepository(tmp_path / "captures")
    repository.save(
        _packet(
            record_id="report-record",
            session_id="report-session",
            timestamp=datetime(2026, 11, 1, tzinfo=timezone.utc),
        )
    )

    csv_response = client.get("/api/sessions/report-session/report?format=csv")
    pdf_response = client.get("/api/sessions/report-session/report?format=pdf")

    assert csv_response.status_code == 200
    assert "text/csv" in csv_response.headers["content-type"]
    assert b"report-session" in csv_response.content
    assert b"opaque-payload-marker" not in csv_response.content
    assert pdf_response.status_code == 200
    assert pdf_response.content.startswith(b"%PDF-")
    assert b"opaque-payload-marker" not in pdf_response.content


def test_live_statistics_and_dashboard_cors_boundary(client):
    assert client.get("/api/statistics").json() == {
        "total_packets": 0,
        "total_bytes": 0,
        "packets_per_sec": 0.0,
        "protocols": [],
        "top_talkers": [],
    }
    allowed = client.get(
        "/api/health", headers={"Origin": "http://127.0.0.1:5173"}
    )
    blocked = client.get("/api/health", headers={"Origin": "https://untrusted.example"})

    assert allowed.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"
    assert allowed.json()["version"] == __version__ == "1.0.0"
    assert "access-control-allow-origin" not in blocked.headers


@pytest.mark.parametrize(
    ("payload", "status", "detail"),
    [
        ({"mode": "unknown"}, 422, "string should match pattern"),
        ({"mode": "pcap"}, 422, "Choose a local classic PCAP file to replay"),
        ({"mode": "interface", "interfaces": [""]}, 422, "Choose at least one valid network adapter"),
    ],
)
def test_capture_start_rejects_invalid_requests(client, payload, status, detail):
    response = client.post("/api/capture/start", json=payload)

    assert response.status_code == status
    assert detail.lower() in response.text.lower()


def test_capture_start_rejects_missing_pcap_and_unavailable_adapter(client, tmp_path, monkeypatch):
    missing = client.post(
        "/api/capture/start",
        json={"mode": "pcap", "pcap_path": str(tmp_path / "missing.pcap")},
    )
    assert missing.status_code == 400
    assert "PCAP file not found" in missing.json()["detail"]

    monkeypatch.setattr(api, "get_if_list", lambda: ["eth0"])
    unavailable = client.post(
        "/api/capture/start", json={"mode": "interface", "interface": "wlan9"}
    )
    assert unavailable.status_code == 422
    assert "no longer available" in unavailable.json()["detail"]


def test_interface_enumeration_failure_is_reported(client, monkeypatch):
    monkeypatch.setattr(api, "get_if_list", lambda: (_ for _ in ()).throw(OSError("driver stopped")))

    response = client.get("/api/interfaces")

    assert response.status_code == 503
    assert "driver stopped" in response.json()["detail"]


def test_interface_inventory_normalizes_names_and_recommendations(client, monkeypatch):
    monkeypatch.setattr(api, "get_if_list", lambda: ["eth0", "lo", "virtual-wan"])
    monkeypatch.setattr(api, "get_windows_if_list", lambda: [])
    monkeypatch.setattr(api.platform, "system", lambda: "Linux")
    monkeypatch.setattr(api, "get_windows_if_list", None)

    response = client.get("/api/interfaces")

    assert response.status_code == 200
    adapters = response.json()["interfaces"]
    assert adapters[0]["friendly_name"] == "eth0"
    assert adapters[0]["capture_candidate"] is False
    assert adapters[0]["recommended"] is False
    assert adapters[1]["status"] == "Unknown"
    assert adapters[2]["capture_candidate"] is False


def test_interface_inventory_uses_windows_adapter_details(client, monkeypatch):
    guid = "12345678-1234-1234-1234-123456789abc"
    npf = rf"\\Device\\NPF_{{{guid}}}"
    monkeypatch.setattr(api, "get_if_list", lambda: [npf])
    monkeypatch.setattr(
        api,
        "get_windows_if_list",
        lambda: [{"name": npf, "description": "Wi-Fi adapter", "ips": "192.0.2.5", "mac": "02:00:00:00:00:01"}],
    )
    monkeypatch.setattr(api.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        api.subprocess,
        "run",
        lambda *args, **kwargs: types.SimpleNamespace(
            stdout=f'{{"Name":"Wi-Fi","InterfaceDescription":"Wireless Adapter","InterfaceGuid":"{{{guid}}}","Status":"Up","MacAddress":"02:00:00:00:00:02","IPs":["192.0.2.8"]}}'
        ),
    )

    adapter = client.get("/api/interfaces").json()["interfaces"][0]

    assert adapter["friendly_name"] == "Wi-Fi"
    assert adapter["description"] == "Wireless Adapter"
    assert adapter["capture_candidate"] is True
    assert adapter["recommended"] is True
    assert adapter["interface_guid"] == guid


def test_report_and_alert_routes_validate_missing_data_and_bounds(client):
    missing_report = client.get("/api/sessions/unknown/report")
    assert missing_report.status_code == 404
    assert "No saved capture session" in missing_report.json()["detail"]

    invalid_limit = client.get("/api/alerts", params={"limit": 0})
    assert invalid_limit.status_code == 422
