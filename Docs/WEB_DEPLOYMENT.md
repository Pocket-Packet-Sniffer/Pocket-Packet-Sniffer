# Dashboard hosting and deployment boundary

## Hosting choice

The dashboard is a static Next.js export deployed to Vercel by GitHub Actions after the `CI` workflow succeeds on `main`. Pull requests run frontend type checking and a production build; only the tested main-branch commit is deployed. The deployment workflow expects GitHub Actions secrets `VERCEL_TOKEN`, `VERCEL_ORG_ID`, and `VERCEL_PROJECT_ID`.

Vercel Hobby is free for personal, non-commercial use. If the project is used commercially, choose a plan/provider that permits that use before production deployment. The hosting account must be linked and the three deployment secrets configured before the workflow can publish.

## Capture architecture

The cloud host serves only the web interface. It cannot see or capture traffic from an operator's computer. The Python API, packet capture, PCAP files, SQLite index, and reports remain on the operator's machine. The API should bind to `127.0.0.1` and must not be exposed to the public Internet.

For a hosted dashboard to communicate with the local agent, set `PPS_ALLOWED_ORIGINS` on the local sensor to the exact comma-separated dashboard origin(s), including scheme and hostname. Browsers may also require explicit local-network access permission for a public HTTPS page to reach loopback. If the browser blocks this connection, run the dashboard locally at `http://127.0.0.1:5173` alongside the local API.

## CI and CD flow

1. Pull requests run Python lint/tests and the frontend type check/build.
2. A successful `CI` run on `main` starts the Vercel deployment workflow.
3. The workflow builds the same tested commit and deploys its prebuilt static output.
4. A deploy cannot succeed until the Vercel project is linked and the required GitHub secrets are set.

No packet data, demo traffic, or local capture API is uploaded during deployment.
