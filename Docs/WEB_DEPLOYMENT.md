# Dashboard hosting and deployment boundary

## Hosting choice

The dashboard is deployed through Vercel's GitHub integration. Vercel creates preview deployments for pull requests and production deployments for the configured production branch. GitHub Actions CI runs the Python lint/tests and frontend type check/build on pull requests and pushes. Require those CI checks before merging to the production branch so production CD runs only for checked commits.

Vercel Hobby is free for personal, non-commercial use. If the project is used commercially, choose a plan/provider that permits that use before production deployment. Vercel's GitHub integration is connected to this repository and has created a Ready preview for this change.

## Capture architecture

The cloud host serves only the web interface. It cannot see or capture traffic from an operator's computer. The Python API, packet capture, PCAP files, SQLite index, and reports remain on the operator's machine. The API should bind to `127.0.0.1` and must not be exposed to the public Internet.

For a hosted dashboard to communicate with the local agent, set `PPS_ALLOWED_ORIGINS` on the local sensor to the exact comma-separated dashboard origin(s), including scheme and hostname. Browsers may also require explicit local-network access permission for a public HTTPS page to reach loopback. If the browser blocks this connection, run the dashboard locally at `http://127.0.0.1:5173` alongside the local API.

## CI and CD flow

1. Pull requests run Python lint/tests and the frontend type check/build.
2. Vercel builds pull request previews through its GitHub integration.
3. Merge to the configured production branch triggers Vercel's production deployment.
4. The production site serves the dashboard only; no packet data or capture API is uploaded.

No packet data, demo traffic, or local capture API is uploaded during deployment.
