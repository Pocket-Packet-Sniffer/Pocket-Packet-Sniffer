# Pocket Packet Sniffer — SRS v1.4 Change Proposal

**Status:** Draft for project-team review; not yet approved.

**Baseline:** Approved SRS v1.3, plus implementation evidence in `IMPLEMENTATION_GAP_AUDIT.md`, `REQUIREMENT_TRACEABILITY.md`, and GitHub issues #13, #14, #27, and #28.

This proposal records features added after SRS v1.3 and establishes a safe scope for the dashboard and cloud release. It does not replace or silently amend the approved SRS. Once reviewed, accepted changes should be incorporated into a formally versioned SRS and the traceability matrix.

## 1. Purpose and scope of changes

Keep SRS v1.3 requirements REQ-1 through REQ-8 as the original baseline. Add the two implemented stretch requirements (suspicious-activity alerts and concurrent capture) to the maintained requirements set, and specify the Next.js dashboard, its local API boundary, and a cloud-hosted demonstration mode.

Cloud hosting is for the static dashboard and synthetic demonstration data. Packet capture, packet bytes, indexes, and reports remain on the operator's computer. A cloud service must not receive live capture traffic or control a capture process.

## 2. Proposed functional requirements

### REQ-9 — Suspicious-activity review alerts

The Analysis layer shall publish metadata-only alert events for supported suspicious patterns. Initial rules include conflicting ARP IP-to-MAC claims and optional unfamiliar-device or access-point checks against operator-provided allowlists. The Presentation layer shall expose the matched rule and reason so an operator can review the record.

Alerts are heuristic review signals. A match is not proof of an attack, and no match is not proof that traffic is safe. Access-point checks require decodable Wi-Fi beacon metadata; inventory checks require an operator-supplied allowlist.

### REQ-10 — Concurrent capture sources

The Capture layer shall support concurrent instances of supported capture backends through the common capture contract. It shall coordinate stop/count behavior and preserve source metadata while leaving downstream Analysis, Storage, and Presentation independent of the selected backend.

Synthetic multi-PCAP coverage is automated evidence. Claims about simultaneous physical interfaces require validation on the target adapters, OS, drivers, and permissions.

### REQ-11 — Local dashboard

The system shall provide a responsive browser dashboard for local capture sessions, packet metadata, statistics, session history, filtering, and local report export. The dashboard shall reuse the existing Capture → Analysis → Storage path through a local API; it shall not duplicate packet parsing or persistence.

Live capture shall require an explicit operator action and interface selection. PCAP replay shall require an explicit local file selection/path. The dashboard shall show backend connectivity, capture state, errors, empty states, and whether displayed data is synthetic or locally captured.

### REQ-12 — Hosted demonstration mode

The project may publish a static dashboard demonstration using clearly labelled synthetic data. In hosted demonstration mode, capture controls and local-system access shall be unavailable, and the page shall not call a capture API or transmit packet records. A user shall be able to distinguish synthetic demonstration data from locally captured data at all times.

## 3. Proposed non-functional and security requirements

- **NFR-11 — Local capture boundary:** the capture API shall bind to loopback by default and shall not be deployed as a public cloud capture service.
- **NFR-12 — Data locality:** captured packet bytes, metadata indexes, and generated reports shall remain local unless the operator explicitly exports them. The hosted demonstration shall contain synthetic records only.
- **NFR-13 — Web/API boundary:** the local dashboard/API connection shall use an explicit origin policy and typed request validation. File replay requests shall be restricted to local files selected by the operator; the API shall not be exposed to untrusted remote origins.
- **NFR-14 — Delivery:** pull requests shall run backend lint/tests and frontend install/type-check/build checks. Production static hosting shall deploy only from the protected `main` branch after required checks succeed. Any preview deployments must use synthetic demo data and must not receive production capture data or credentials.
- **NFR-15 — Accessibility and responsive use:** primary navigation and capture/query/report actions shall be keyboard-operable, have accessible names and visible focus, communicate status without color alone, and remain usable on mobile and desktop viewport sizes.

## 4. Explicit exclusions

- Public cloud packet capture, remote interface selection, or remote control of the local capture process.
- Uploading packet payloads, PCAP files, SQLite indexes, or reports to a hosted dashboard by default.
- Packet injection, traffic alteration, or replay onto a network.
- Claims of validated Wi-Fi monitor mode, BLE radio support, Windows ACL security, Raspberry Pi throughput/no-drop performance, or physical multi-adapter capture without target-environment evidence.
- Optional Zeek integration until a separate requirement, scope, and acceptance criteria are approved.

## 5. Proposed acceptance evidence

| Requirement group | Evidence required |
|---|---|
| REQ-9 alerts | Automated match/non-match tests; synthetic demo showing rule and reason; documented heuristic limitations. |
| REQ-10 concurrent sources | Automated synthetic fan-in, stop/error, and mixed-link-type tests; separate live multi-adapter record if claimed. |
| REQ-11 local dashboard | Responsive UI review; API/session lifecycle checks; local capture and PCAP replay demo; query/filter and report export evidence; accessibility review. |
| REQ-12 hosted demo | Inspect deployed build/network behavior to confirm synthetic-only data, no capture controls, no API calls, and clear demo labeling. |
| NFR-11 through NFR-14 | Inspect bind address, CORS/origin policy, request validation, GitHub Actions gates, deployment branch/environment settings, and production build configuration. |
| Original SRS hardware claims | Record exact OS, hardware, adapter, driver, permissions, test procedure, offered/received traffic, and available drop counters. CI and synthetic replay do not satisfy these checks. |

## 6. Delivery order

1. Review and approve this SRS change proposal; then publish the controlled SRS revision and update the SRS-to-test traceability matrix.
2. Finalize the hosting boundary: GitHub Pages is the initial static-host candidate for a synthetic demo only; all real capture stays local. Record this as an architecture decision.
3. Finish the local dashboard UX and explicit local-vs-demo modes; resolve responsive layout, loading/empty/error states, accessibility, and clear capture safety messaging.
4. Harden and validate the local API boundary before connecting or packaging the dashboard for real capture.
5. Extend CI to install frontend dependencies from the lockfile and run backend lint/tests plus frontend type-check/build and API/UI checks.
6. Add CD: production static deploy from `main` only after CI passes. Add PR preview deployments later if needed, restricted to synthetic demo mode. Keep local capture API and data out of cloud deployment.
7. Run the release acceptance checklist, record target-hardware checks or explicitly narrow support claims, then update the SRS audit, traceability, demo guide, and release notes.

## 7. Decisions needed for approval

- Approve REQ-9 and REQ-10 as maintained product requirements rather than stretch goals.
- Approve a hosted static synthetic demo while requiring real capture to remain local.
- Confirm intended target OS/hardware for the live-capture, Wi-Fi, BLE, Windows ACL, and Raspberry Pi acceptance checks.
- Confirm GitHub Pages as the initial free static-hosting provider, or choose Cloudflare Pages; provider choice does not change the local-only capture boundary.
