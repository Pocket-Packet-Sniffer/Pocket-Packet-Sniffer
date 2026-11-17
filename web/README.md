# Pocket Packet Sniffer dashboard

The dashboard displays only data received from the real local capture agent. It contains no bundled packet samples or synthetic demo mode. Until the agent is running and a capture or PCAP replay has populated local storage, the dashboard shows an honest empty state.

Vercel hosts the interface only. The Python capture agent, packet files, SQLite index, and analysis remain on the operator's computer. To use a hosted dashboard with the local sensor, configure the exact dashboard origin in `PPS_ALLOWED_ORIGINS` on the sensor and grant the browser's local network access prompt. Keep the capture API bound to loopback and do not expose it publicly.

## Run locally

Requirements: Python 3.10+, Node.js 20.9+, and npm. From the repository root:

```powershell
python -m pip install -e .
cd web
npm ci
npm run dev
```

In another terminal, start the local API from the repository root:

```powershell
python -m uvicorn pocket_packet_sniffer.api:app --reload --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:5173`. Select an active adapter and start live capture, or choose a local PCAP file for replay. Use only an interface and network you own or are authorized to monitor.

## Deploy

The `Deploy dashboard to Vercel` GitHub Actions workflow deploys the tested `main` commit after CI succeeds. Configure GitHub Actions secrets `VERCEL_TOKEN`, `VERCEL_ORG_ID`, and `VERCEL_PROJECT_ID` for the linked Vercel project. Vercel hosts only the dashboard; capture and stored packet data remain local.
