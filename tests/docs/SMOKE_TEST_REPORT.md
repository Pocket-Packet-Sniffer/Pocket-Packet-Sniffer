# Smoke Test Report

**Purpose:** quickly establish that a built deliverable starts and responds before deeper use.

**Packaged agent:** the `agent-v0.2.2` Windows release workflow built the portable executable, started it in a hidden process, polled `GET /api/health`, and stopped it after success. Result: **PASS**, GitHub Actions run [44140452688](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44140452688).

**Hosted dashboard:** production URL returned HTTP 200 after PR #60 merged to `main` as `0839abf9d102d0b4c1da4f0f58a205ef6d9a4525`; served HTML included the updated privacy-guidance text. GitHub Actions [run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) succeeded on that commit. This checks hosted-page availability/content only; it does not test a user's local capture sensor.

**Local services:** the Windows API health endpoint and local dashboard both returned HTTP 200 during the same release-readiness check. The actual capture start/stop/query/export result is documented separately in the [system test report](SYSTEM_TEST_REPORT.md).

**Limit:** smoke checks do not replace functional or hardware acceptance tests.
