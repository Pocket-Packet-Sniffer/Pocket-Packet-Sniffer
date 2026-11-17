# Dashboard hosting and deployment boundary

## What is hosted

The cloud deployment is a static Next.js export in **synthetic demo mode**. It does not include the FastAPI capture service. Its bundled sample packets use documentation-only IP ranges and are labeled synthetic throughout the UI. Capture controls are hidden and the build does not call the API.

Real capture remains on the operator's computer. The local API should bind to `127.0.0.1`; PCAP/SQLite files and exports stay local. Do not expose this capture API to the public Internet or point a public demo build at a real capture API.

## Chosen platform: GitHub Pages

The repository is public, so GitHub Pages is available on GitHub Free. It also uses the existing GitHub account and Actions pipeline, avoiding a separate hosting account, cloud credentials, or deploy secrets. GitHub Pages serves static files, which fits the Next.js `output: "export"` build without adding a cloud database or server runtime.

The existing Pages workflow is enabled and has completed a successful production deployment. The public dashboard is at [pocket-packet-sniffer.github.io/Pocket-Packet-Sniffer](https://pocket-packet-sniffer.github.io/Pocket-Packet-Sniffer/). On future changes, the workflow builds with `NEXT_PUBLIC_DEMO_MODE=true` and the repository base path, then publishes only after main-branch CI succeeds. It can also be started manually from GitHub Actions.

GitHub documents a 1 GB published-site limit and a soft 100 GB/month bandwidth limit. Pages is not intended for commercial SaaS or online-business hosting; recheck GitHub's current policy if the project's purpose changes.

## Free static alternatives

| Provider | Fit for this dashboard | Current constraint to consider |
|---|---|---|
| Cloudflare Pages | Strong alternative for static Next.js export output, branch previews, and custom domains. | Free plan currently allows 500 builds/month, one concurrent build, 20,000 files, and 25 MiB per asset. |
| Vercel Hobby | Convenient static export hosting with automatic Git previews. | Hobby is limited to non-commercial personal use; avoid it if the project is used for commercial purposes. |

GitHub Pages is the selected host for this project. Cloudflare Pages is a possible alternative if branch preview deployments or a different CDN become a priority. None of these static hosts should receive packet captures or host the live capture API in this design.

## CI and CD flow

1. Pull requests run the backend CI matrix and frontend dependency/type-check/build job.
2. Merge to `main` only after required checks pass and review is complete.
3. A change to `web/**` or the deployment workflow triggers the Pages deployment workflow on `main`.
4. The workflow installs from `web/package-lock.json`, builds the Next.js static export with synthetic-only mode enabled, and publishes `web/out`.
5. Review the resulting hosted site and the workflow run in GitHub Actions.

The first implementation deploys production after merge; it does not yet create per-PR cloud previews. PR preview deployments can be added later if review feedback shows they are needed. The normal CI build already validates each PR without publishing it.
