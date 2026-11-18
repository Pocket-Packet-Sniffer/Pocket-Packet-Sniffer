# Pocket Packet Sniffer — SRS v1.4 Change Proposal

**Status:** Draft for project-team review; not yet approved.

**Baseline:** Approved SRS v1.3, plus implementation evidence in `IMPLEMENTATION_GAP_AUDIT.md`, `REQUIREMENT_TRACEABILITY.md`, and GitHub issues #13, #14, #27, and #28.

This proposal records features added after SRS v1.3 and establishes a safe scope for the dashboard and cloud release. It does not replace or silently amend the approved SRS. Once reviewed, accepted changes should be incorporated into a formally versioned SRS and the traceability matrix.

## 1. Purpose and scope of changes

Keep SRS v1.3 requirements REQ-1 through REQ-8 as the original baseline. Add the two implemented stretch requirements (suspicious-activity alerts and concurrent capture) to the maintained requirements set, and specify the Next.js dashboard, its local API boundary, and a cloud-hosted demonstration mode.

Cloud hosting serves the dashboard interface only. The browser may connect to an explicitly installed loopback sensor on the same computer; the cloud service itself receives no capture traffic and cannot capture a remote computer. Packet files, indexes, and reports remain on the operator's computer. The production page has honest empty/offline states and does not invent synthetic packet activity.

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

### REQ-12 — Hosted dashboard and local sensor boundary

The project may host the dashboard over HTTPS. When the local sensor is unavailable, the page shall show setup guidance and no fabricated packet records. When the sensor is available, explicit capture and selected local-file replay controls shall communicate only with the user's loopback sensor. A user shall be able to distinguish stored local records from an empty state; the hosted website shall never receive packet records.

## 3. Proposed non-functional and security requirements

- **NFR-11 — Local capture boundary:** the capture API shall bind to loopback by default and shall not be deployed as a public cloud capture service.
- **NFR-12 — Data locality:** captured packet bytes, metadata indexes, and generated reports shall remain local unless the operator explicitly exports them. The hosted dashboard shall contain no packet records; it shows real records only after an explicit connection to the operator's local sensor. Generated fixtures are limited to automated tests and are not presented as live or demo traffic.
- **NFR-13 — Web/API boundary:** the local dashboard/API connection shall use an explicit origin policy and typed request validation. File replay requests shall be restricted to local files selected by the operator; the API shall not be exposed to untrusted remote origins.
- **NFR-14 — Delivery:** pull requests shall run backend lint/tests and frontend install/type-check/build checks. Production static hosting shall deploy only from the protected `main` branch after required checks succeed. Preview deployments shall not contain packet records or production credentials; the dashboard stays empty until a user explicitly connects a local sensor. Generated packet fixtures are restricted to automated tests/CI and are never presented as live or demo traffic.
- **NFR-15 — Accessibility and responsive use:** primary navigation and capture/query/report actions shall be keyboard-operable, have accessible names and visible focus, communicate status without color alone, and remain usable on mobile and desktop viewport sizes.

## 4. Explicit exclusions

- Public cloud packet capture, remote interface selection, or remote access to the capture API.
- Uploading packet payloads, SQLite indexes, or reports to the hosted website. Explicit PCAP file selection transfers the chosen file only to the user's local loopback sensor for replay.
- Packet injection, traffic alteration, or replay onto a network.
- Claims of validated Wi-Fi monitor mode, BLE radio support, Windows ACL security, Raspberry Pi throughput/no-drop performance, or physical multi-adapter capture without target-environment evidence.
- Optional Zeek integration until a separate requirement, scope, and acceptance criteria are approved.

## 5. Proposed acceptance evidence

| Requirement group | Evidence required |
|---|---|
| REQ-9 alerts | Automated match/non-match tests; synthetic demo showing rule and reason; documented heuristic limitations. |
| REQ-10 concurrent sources | Automated synthetic fan-in, stop/error, and mixed-link-type tests; separate live multi-adapter record if claimed. |
| REQ-11 local dashboard | Responsive UI review; API/session lifecycle checks; local capture and PCAP replay demo; query/filter and report export evidence; accessibility review. |
| REQ-12 hosted UI | Browser checks confirm honest offline state, local-agent-only data flow, explicit local replay, no packet-data requests to the hosted origin, and clear capture/privacy messaging. |
| NFR-11 through NFR-14 | Inspect bind address, CORS/origin policy, request validation, GitHub Actions gates, deployment branch/environment settings, and production build configuration. |
| Original SRS hardware claims | Record exact OS, hardware, adapter, driver, permissions, test procedure, offered/received traffic, and available drop counters. CI and synthetic replay do not satisfy these checks. |

## 6. Delivery order

1. Review and approve this SRS change proposal; then publish the controlled SRS revision and update the SRS-to-test traceability matrix.
2. Hosting boundary: Vercel serves the HTTPS dashboard; each user runs a loopback capture sensor. Real capture stays local. Record this as an architecture decision.
3. Finish the dashboard UX, responsive layout, loading/empty/error states, accessibility, and clear capture safety messaging.
4. Harden and validate the local API boundary before connecting or packaging the dashboard for real capture.
5. Extend CI to install frontend dependencies from the lockfile and run backend lint/tests plus frontend type-check/build and API/UI checks.
6. Add CD: production dashboard deploy from `main` only after CI passes. Keep the local capture API and packet data out of cloud deployment.
7. Run the release acceptance checklist, record target-hardware checks or explicitly narrow support claims, then update the SRS audit, traceability, demo guide, and release notes.

## 7. Decisions needed for approval

- Approve REQ-9 and REQ-10 as maintained product requirements rather than stretch goals.
- Confirm the hosted interface remains empty/offline until a user explicitly connects their local sensor; generated fixtures remain CI/test inputs only.
- Confirm intended target OS/hardware for the live-capture, Wi-Fi, BLE, Windows ACL, and Raspberry Pi acceptance checks.
- Confirm GitHub Pages as the initial free static-hosting provider, or choose Cloudflare Pages; provider choice does not change the local-only capture boundary.
