# Contributing

This is a small team project, so the process should be lightweight but repeatable. The SRS, STP, and SASD are the authority for scope, testing, and architecture.

## 1. Before coding

1. Find or create a GitHub Issue for the work.
2. Check the issue's acceptance criteria, requirement ID(s), test case mapping, dependencies, priority, and estimate.
3. Confirm the work fits the responsible layer. If the design or SRS needs to change, discuss it with the team and record the decision before implementation.
4. Keep stretch features separate from core requirements.

## 2. Branches and commits

Create a branch from an up-to-date main:
- feat/PPS-number-short-description for a feature
- fix/PPS-number-short-description for a bug fix
- docs/PPS-number-short-description for documentation
- test/PPS-number-short-description for test-only work
- chore/PPS-number-short-description for maintenance

Use short, descriptive commits. Conventional Commit-style prefixes are encouraged, for example feat(capture): add pcap replay backend or test(storage): cover empty query results.

## 3. Pull requests

- Target main; do not push feature work directly to main.
- Use the pull request template.
- Link the issue with Closes #issue-number.
- Explain what changed, why it changed, the layers affected, the requirements addressed, tests run, and remaining limitations.
- Keep a PR focused on one coherent issue where practical.
- Request a review from a teammate who did not author the change.

## 4. Testing and quality

Before requesting review, run the relevant tests and checks locally. Record the exact commands and results in the PR. Add regression tests for bugs and tests for acceptance criteria.

The intended CI pipeline should run linting, unit tests, architecture checks, and a controlled end-to-end test using generated/sample PCAP data. CI must not depend on capturing real network traffic or requiring root permissions.

## 5. Architecture boundaries

- Capture owns interface/backend interaction and emits raw packets.
- Analysis parses packets and produces the common packet record.
- Storage owns persistence and query implementation behind a Repository interface.
- Presentation owns CLI interaction, display, and report invocation.
- Do not let Analysis open SQLite/PCAP stores directly or let Presentation depend on a specific capture backend.
- Do not add external services, network uploads, packet injection, modification, or replay unless the SRS is formally revised and the change is approved (the current tool remains passive).

## 6. Definition of Ready

An item is ready when it has a clear outcome, acceptance criteria, requirement/test traceability, a suggested owner, priority, estimate, and known dependencies.

## 7. Definition of Done

- All acceptance criteria pass.
- Relevant automated tests pass and evidence is recorded.
- A peer has reviewed the PR.
- CI is green once enabled for that component.
- Documentation and traceability are updated where needed.
- No known security or layer-boundary regression is introduced.
- Any remaining limitations are stated honestly.

## 8. Team feature ownership

Based on the project proposal:
- Vikas Kulakarni — Capture Layer
- Shivanand — Analysis Layer
- Shivakumara GP — Storage and Query
- Sanjith R — Presentation Layer

Integration, architecture review, testing, and final documentation are shared responsibilities. Assign GitHub Issues to actual GitHub usernames once the team members' logins are confirmed; do not assume their login names from their real names.