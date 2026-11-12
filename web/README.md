# Pocket Packet Sniffer dashboard

The dashboard uses Next.js App Router and has two deliberately separate modes:

- **Local mode** connects to the FastAPI service on this computer and can control explicitly requested passive capture or local PCAP replay.
- **Hosted demo mode** is a static export with a fixed synthetic dataset. It makes no API requests and cannot access a network interface or local files.

The hosted demo is not a remote capture service. Live capture, packet bytes, SQLite indexes, and reports stay on the operator's computer.

## Run local mode

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

Open `http://127.0.0.1:5173`. The API binds to loopback. Use only an interface and network you own or are authorized to monitor.

## Build the hosted synthetic demo locally

```powershell
cd web
$env:NEXT_PUBLIC_DEMO_MODE = "true"
$env:NEXT_BASE_PATH = "/Pocket-Packet-Sniffer"
npm ci
npm run build
```

Next.js writes the static site to `out/`. The demo build includes synthetic records only. Its capture panel is hidden and its frontend does not request the local API.

## Deployment

`.github/workflows/deploy-dashboard.yml` builds and publishes the static demo to GitHub Pages after main-branch CI succeeds. The repository must have Pages configured to use **GitHub Actions** under **Settings → Pages → Build and deployment**. The workflow does not deploy the Python API or any capture data.

See [`Docs/WEB_DEPLOYMENT.md`](../Docs/WEB_DEPLOYMENT.md) for the hosting decision, provider alternatives, and deployment boundary.
