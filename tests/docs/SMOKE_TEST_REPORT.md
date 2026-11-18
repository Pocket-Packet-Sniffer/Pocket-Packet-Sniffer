# Smoke Test Report

**Purpose:** quickly establish that a built deliverable starts and responds before deeper use.

**Packaged agent:** the `agent-v0.2.2` Windows release workflow built the portable executable, started it in a hidden process, polled `GET /api/health`, and stopped it after success. Result: **PASS**, GitHub Actions run [44140452688](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44140452688).

**Hosted dashboard:** production URL returned HTTP 200 on 2026-11-18. This is an availability/deployment smoke check for the current production build; it does not test the user's local capture sensor or imply that the unmerged release-readiness candidate is deployed.

**Limit:** smoke checks do not replace functional or hardware acceptance tests.
