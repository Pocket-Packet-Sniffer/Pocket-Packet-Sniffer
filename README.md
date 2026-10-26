# Pocket Packet Sniffer

Pocket Packet Sniffer is a Software Engineering project for authorized, passive network traffic monitoring. It captures packets from supported interfaces, extracts metadata, stores captures, and presents traffic statistics and query/report functions.

## Architecture

The design follows the four-layer architecture defined by the SRS and SASD:

1. **Capture** — captures raw packets through a common Capturer interface.
2. **Analysis** — parses packets, extracts required metadata, and runs protocol analyzers.
3. **Storage** — persists PCAP data and indexed metadata through a Repository interface.
4. **Presentation** — provides the primary CLI for capture control, live statistics, queries, and reports.

WiFi, Ethernet, and BLE remain represented in the requirements. Backend availability depends on hardware, drivers, operating system, and permissions. BLE, suspicious-activity detection, concurrent multi-backend capture, Zeek integration, and the web dashboard are stretch/optional work until implemented and validated.

## Requirements and project documents

The approved project documents currently live under Docs:
- Project proposal
- Software Requirements Specification (SRS) v1.3
- Software Test Plan (STP) v1.3
- Software Architecture and Design Specification (SASD)

The SRS is the source of functional and non-functional requirements. The STP defines the verification approach and test mapping. The SASD explains the design and component boundaries. Implementation decisions should be traceable to these documents.

## Engineering workflow

- Use one branch per issue: feat/PPS-number-short-name, fix/PPS-number-short-name, or docs/PPS-number-short-name.
- Create an issue before starting work and include acceptance criteria and SRS/STP traceability.
- Open a pull request into main; link the issue using Closes #number.
- A different team member should review changes. Do not merge failing checks or unreviewed work.
- Update tests, docs, and the Requirement Traceability Matrix where appropriate.
- Do not mark work Done until acceptance criteria pass and evidence is recorded.

See CONTRIBUTING.md for the detailed working agreement.

## Team engineering resources

- [GitHub operating guide](Docs/GITHUB_OPERATING_GUIDE.md) — issue labels, milestones, branching, reviews, merge rules, releases, and repository settings.
- [Project process](Docs/PROJECT_PROCESS.md) — requirements authority, layer responsibilities, prioritization, and quality gates.
- [Architecture Decision Record template](Docs/adr/0000-template.md) — record important design choices and their trade-offs.
- [Contributing guide](CONTRIBUTING.md) — the expected issue-to-PR workflow.
- [Security and safe use](SECURITY.md) — passive-only scope and sensitive capture-data handling.

## Safe use

Only capture traffic on networks/devices you own or are explicitly authorized to monitor. This tool is intended to be passive: it must not inject, alter, or replay network traffic. Capture files may contain sensitive information; keep them local and protect them with suitable file permissions. The CLI must not silently upload captured data.

## Current implementation status

Do not infer implementation status from the design documents alone. Requirements and stretch goals should only be marked complete after the relevant code is merged and tests or demonstration evidence support the claim.