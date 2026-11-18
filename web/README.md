# Pocket Packet Sniffer dashboard

The dashboard displays only data received from the real local capture agent. It contains no bundled packet samples or synthetic demo mode. Until the agent is running and a capture or PCAP replay has populated local storage, the dashboard shows an honest empty state.

Vercel hosts the interface only. The capture agent, packet files, SQLite index, and analysis remain on the operator's computer. The packaged Windows agent automatically allows the production dashboard origin, binds only to loopback, and uses the user's local application data directory. The browser may ask for local network access when the HTTPS dashboard connects to the agent.

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

Vercel's GitHub integration creates pull request previews and deploys production when the configured production branch is updated. GitHub Actions runs the backend and frontend CI checks. Vercel hosts only the dashboard; capture and stored packet data remain local.

The Settings page links to the portable Windows capture agent ZIP in GitHub Releases. Friends can download and run that executable without cloning the project or installing Python. Windows live capture requires Npcap, and browser local-network access must be allowed. A hosted browser page cannot sniff a remote computer without its local agent. Create and push an `agent-v*` tag to build and publish a new Windows release. The 1.0.0 agent is the current stable release; the dashboard still recognizes the 0.2.1 and 0.2.2 agents and offers an update notice.
