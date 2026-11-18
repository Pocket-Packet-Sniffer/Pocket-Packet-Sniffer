# Usability Test Report

**Current UI source:** merged `main` commit `0839abf`.
**Automated browser result:** **13 Playwright tests passed**; the dashboard job passed in [GitHub Actions run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089).

## What was evaluated

The browser suite (`web/tests/e2e/dashboard.spec.ts`) checks scripted user tasks including offline/setup guidance, privacy and responsible-use messaging, sensor connection/capture controls, packet activity visualization, observed-address navigation, packet filters/details, local PCAP selection, CSV/PDF downloads, and a mobile viewport. API responses are controlled in these browser tests so outcomes are repeatable.

## Results and evidence boundary

All 13 browser tests passed in the current verification run. Frontend type-check and production build also passed. This supports the tested interaction flows and mobile layout. It does **not** provide a user satisfaction score, task-completion rate from real participants, assistive-technology compatibility audit, or independent WCAG conformance result.

## Human evaluation status

**NOT RUN:** no moderated/unmoderated study with non-technical users, sample size, participant characteristics, task success timing, questionnaire, or qualitative feedback is recorded. Do not describe automated Playwright checks as a human usability study.

## Recommended presentation tasks

For a future observed usability session, ask a participant to: (1) choose the active adapter, (2) explain what “watching” means, (3) start/stop an authorized capture, (4) find a source/destination address and port, (5) explain where PCAP data is stored, and (6) export a report. Record completion, confusion points, accessibility needs, and consent; do not capture a participant's real traffic without explicit authorization.

See the [live-traffic presentation guide](../../Docs/DEMO_SCRIPT.md), [privacy guidelines](../../Docs/PRIVACY_GUIDELINES.md), and [System Test Report](SYSTEM_TEST_REPORT.md).
