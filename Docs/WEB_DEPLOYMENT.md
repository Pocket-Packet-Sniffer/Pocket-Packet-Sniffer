# Dashboard hosting and deployment boundary

## Hosting choice

The dashboard is deployed through Vercel's GitHub integration. Vercel creates preview deployments for pull requests and production deployments for the configured production branch. GitHub Actions CI runs the Python lint/tests and frontend type check/build on pull requests and pushes. Require those CI checks before merging to the production branch so production CD runs only for checked commits.

Vercel Hobby is free for personal, non-commercial use. If the project is used commercially, choose a plan/provider that permits that use before production deployment. Vercel's GitHub integration is connected to this repository and has created a Ready preview for this change.

## Capture architecture

The cloud host serves only the web interface. It cannot see or capture traffic from an operator's computer. The Python API, packet capture, PCAP files, SQLite index, and reports remain on the operator's machine. The API should bind to `127.0.0.1` and must not be exposed to the public Internet.

For a hosted dashboard to communicate with the local agent, set `PPS_ALLOWED_ORIGINS` on the local sensor to the exact comma-separated dashboard origin(s), including scheme and hostname. Browsers may also require explicit local-network access permission for a public HTTPS page to reach loopback. If the browser blocks this connection, run the dashboard locally at `http://127.0.0.1:5173` alongside the local API.

Friends do not need a source checkout or Python environment. The Settings page links to a portable Windows agent ZIP published from `agent-v*` tags. Each Windows PC still needs Npcap installed for live adapter capture; the cloud page cannot capture another computer's network interface by itself. The agent binds to loopback and stores PCAP/SQLite data under that user's local application data directory.

## CI and CD flow

1. Pull requests run Python lint/tests, frontend type-check/build, and browser checks for capture, replay, search, reports, and mobile layout.
2. Vercel builds pull request previews through its GitHub integration.
3. Merge to the configured production branch triggers Vercel's production deployment.
4. The production site serves the dashboard only; no packet data or capture API is uploaded.

No packet data, demo traffic, or local capture API is uploaded during deployment.

## Friend / hosted-dashboard flow

Open `https://pocket-packet-sniffer.vercel.app` in a browser. To see a private network, download the Windows capture agent from the page, install Npcap for live capture, and run the agent on that same computer. The browser asks the agent at `127.0.0.1`; the agent permits only configured dashboard origins for browser write requests. Choose an adapter or select a local classic PCAP. Captures, database records, and reports stay on that computer. Ordinary Wi-Fi mode may show only traffic visible to that adapter; monitor mode requires compatible hardware and drivers. No synthetic packets are presented as live activity.
