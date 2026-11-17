# Smoke Test Report

**Purpose:** quickly establish that a built deliverable starts and responds before deeper use.

**Packaged agent:** the `agent-v0.2.2` Windows release workflow built the portable executable, started it in a hidden process, polled `GET /api/health`, and stopped it after success. Result: **PASS**, GitHub Actions run [44140452688](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44140452688).

**Hosted dashboard:** production URL returned HTTP 200 and its served JavaScript contained the updated dashboard marker during the 2026-11-17 verification. This is an availability/deployment smoke check; it does not test the user's local capture sensor.

**Limit:** smoke checks do not replace functional or hardware acceptance tests.
