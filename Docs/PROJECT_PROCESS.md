# Project Process and Management

## Source-of-truth hierarchy

1. **SRS v1.3** defines scope, functional requirements REQ-1 through REQ-10, and non-functional requirements.
2. **STP v1.3** defines test scope, test strategy, environment, and traceability to test case IDs.
3. **SASD Deliverable 3** explains component responsibilities, design patterns, internal interfaces, sequence flows, risks, and security.
4. **Project proposal** defines original team responsibilities and intended delivery order.

If implementation and documentation disagree, do not silently change the requirement. Open an issue, discuss it with the team, and record the approved decision and updated traceability.

## Development model

Use small, issue-based iterations. Each issue should represent one coherent outcome that can be reviewed and demonstrated. Plan a small sprint goal, estimate work before commitment, review progress during the sprint, and record what actually shipped and what remains.

## Traceability

Each feature issue and PR should refer to the SRS requirement and STP test case where applicable. Keep the RTM updated as source filenames, tests, and design references become stable. Test IDs from the STP should not be changed casually.

## Layer responsibilities

- **Capture:** acquire authorized raw traffic using supported interfaces/backends and report interface/permission failures.
- **Analysis:** parse packets, extract the required metadata, classify protocols, and provide an extensible analyzer pipeline.
- **Storage:** persist PCAP and indexed metadata and expose query functions through the Repository interface.
- **Presentation:** CLI start/stop, live statistics, saved-capture queries, report export, and optional event display.
- **Cross-cutting:** passive-only behaviour, authorized use, local file protection, testability, maintainability, and performance on Raspberry Pi-class hardware.

## Backlog priority

Core capture, metadata parsing, storage/query, CLI statistics, report export, and their error paths come before optional features. Suspicious-activity detection, concurrent multi-backend capture, BLE where hardware is not available, Zeek, and a web dashboard remain explicitly stretch/optional.

## Review and quality gates

- Issue has acceptance criteria, priority, estimate, traceability, owner suggestion, and dependencies.
- Feature branch is based on current main.
- PR is linked to an issue and reviewed by someone other than its author.
- Tests validate the requirement; end-to-end tests use controlled PCAP fixtures and do not require capturing real traffic.
- CI runs lint/tests once the application tree has been integrated.
- Protect main with a review and required checks after the CI job names are verified.
- Mark an item Done only after merged code and test evidence support it.

## Team ownership

The project proposal assigns Vikas Kulakarni to Capture, Shivanand to Analysis, Shivakumara GP to Storage/Query, and Sanjith R to Presentation. Integration, architecture review, QA coordination, and final documentation are shared responsibilities.