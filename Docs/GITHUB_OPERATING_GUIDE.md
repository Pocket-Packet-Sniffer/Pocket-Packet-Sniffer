# GitHub Operating Guide

This guide defines the team's working agreement for issues, milestones, pull requests, reviews, releases, and repository settings. Keep the process lightweight: use the controls that add visibility or prevent avoidable mistakes, and do not enable checks that have not been implemented and verified.

## 1. One source of truth for work

- Use GitHub Issues for bugs, features, tests, documentation, and engineering tasks.
- Every implementation issue should state a clear outcome, observable acceptance criteria, SRS/STP traceability where relevant, priority, owner, estimate, dependencies, and test evidence.
- Use the existing organization Project board if the team decides to use it; do not create a duplicate board just to follow this guide.
- Keep stretch work separate from core requirements. REQ-9 alerts and REQ-10 concurrent capture remain stretch work unless the team formally reprioritizes them.
- Do not close an issue just because a branch was pushed. Close it when the linked PR is merged and the accepted outcome is delivered.

## 2. Recommended labels

Create this label taxonomy in the repository's **Issues → Labels** page. The GitHub integration used for this setup can manage issue assignments and add existing labels, but does not expose label creation; a repository maintainer must create these labels in the GitHub UI.

### Type
- `type:feature`
- `type:bug`
- `type:task`
- `type:docs`
- `type:test`
- `type:security`
- `type:quality`

### Priority
- `priority:P0` — immediate blocker or serious security/reliability concern
- `priority:P1` — high priority for the current milestone
- `priority:P2` — normal planned work
- `priority:P3` — low priority or nice-to-have

### Layer
- `layer:capture`
- `layer:analysis`
- `layer:storage`
- `layer:presentation`
- `layer:cross-cutting`

### Workflow and scope
- `status:blocked`
- `status:needs-triage`
- `status:needs-review`
- `scope:stretch`
- `good first issue`
- `skip-changelog`

Keep labels consistent: one type, one priority, zero or one layer, plus workflow/scope labels only when useful. Do not use labels as a substitute for assignees or milestones.

## 3. Recommended milestones

Create milestones from **Issues → Milestones → New milestone**. Do not invent due dates; agree them during sprint planning. Suggested grouping:

1. **M0 — Repository foundation**: PR #2 governance baseline, repository setup, interface and integration plan.
2. **M1 — Capture foundation**: issue #3 raw packet capture, issue #9 interface and permission errors.
3. **M2 — Packet pipeline and storage**: issue #4 analysis, issue #5 PCAP/metadata storage.
4. **M3 — Query and live CLI**: issue #6 filtering/query, issue #7 live statistics.
5. **M4 — Release readiness**: issue #8 reports, issue #10 security/portability, issue #11 test coverage, issue #12 docs/demo. Add the integration work needed for a demonstrable end-to-end application.
6. **Stretch — Optional capabilities**: issue #13 suspicious-activity alerts and issue #14 concurrent capture. Only pull these into a milestone after core requirements are on track.

Issue #15 is an ongoing process record. Assign it to a time-boxed sprint/milestone only if the team finds that useful. These are proposed planning groups, not a claim that any issue is complete.

## 4. Branch and commit rules

- Never develop directly on `main`.
- Use one short-lived branch per issue, for example `feat/PPS-03-packet-analysis`, `fix/PPS-08-permission-error`, `docs/PPS-12-demo-guide`, or `test/PPS-11-pcap-fixtures`.
- Make small, descriptive commits. Conventional Commit-style prefixes are recommended: `feat`, `fix`, `test`, `docs`, `chore`, `refactor`.
- Pull the latest `main` before starting a new branch. Avoid unrelated file changes in a PR.
- Use controlled sample data and generated PCAP fixtures in tests. Do not commit real packet captures, credentials, tokens, or confidential traffic.

## 5. Pull request and review policy

- Open a PR into `main` for every issue-based change; use the PR template.
- Link the relevant issue using `Closes #N` when the PR fully delivers it.
- Request at least one review from a teammate who did not author the change.
- The reviewer checks acceptance criteria, tests, interfaces, security constraints, and unintended scope.
- Address review comments on the same branch; pushing new commits updates the existing PR.
- Resolve review conversations and ensure relevant checks pass before merging.
- Prefer **Squash and merge** for small issue-based PRs to keep the main history readable. Preserve descriptive commit/PR titles.
- Do not mark work complete until it is merged and evidence supports the acceptance criteria.

## 6. Main-branch protection

The end-to-end application is now merged to `main` and the CI workflow has passed (81 tests on commit c55b116de6465849e6c7d9cbeb6d692ee6bf84c4). The branch-protection/rulesets endpoint was observed as empty, so `main` is still not confirmed protected. A repository administrator should open **Settings → Rules → Rulesets** (or **Branches**, depending on the available GitHub UI) and create an active rule targeting `main` with:

- Require a pull request before merging.
- Require at least one approval from someone other than the author.
- Require conversation resolution.
- Require the verified CI status checks.
- Block force pushes and deletion of `main`.

Do **not** require CI checks until the workflow exists and its exact check names have been observed on a successful PR. Otherwise, the team may accidentally make `main` impossible to update. Keep administrator bypass settings deliberate and minimal.

## 7. CI, testing, and dependency hygiene

The application CI is now active. It runs Ruff checks and the test suite on pushes and pull requests; the latest main run reported 81 passing tests using generated PCAP data. Keep controlled integration tests non-privileged and use coverage reporting only if freshly measured; do not invent a coverage percentage or threshold.

Once package manifests and lockfiles are in the repository, enable Dependabot security updates and configure ecosystem-appropriate version updates. Review dependency changes through PRs. Never store credentials in repository files; use GitHub Actions secrets only when genuinely needed.

## 8. Ownership and code review

The agreed layer owners are:
- Capture: `@vikaskulakarni`
- Analysis: `@Shivanandgc`
- Storage/query: `@shivakumara-gp`
- Presentation: `@sanjithramanjaneya-source`

Add `.github/CODEOWNERS` only after the source folder paths and module boundaries are confirmed. A Code Owners file with guessed paths can silently fail to request the right reviews.

Every PR should be reviewed by a non-author, including small documentation changes. Rotate cross-layer reviews where practical so the team learns the architecture.

## 9. Releases and project records

- Use GitHub Releases and Git tags for demonstrable checkpoints.
- Use Semantic Versioning when the software has a stable public interface; before that, use a clearly identified pre-1.0 version such as `v0.1.0`.
- Each release should summarize user-visible changes, known limitations, test evidence, and setup/demo instructions. The repository's `.github/release.yml` groups generated notes by label; create the labels listed above for those categories to work as intended.
- Record material architecture decisions as short ADRs under `Docs/adr/`: context, decision, alternatives, consequences, and date. Update the SRS/SASD/RTM through an agreed review when requirements or architecture change.
- At each sprint end, record completed work, incomplete work, demo evidence, blockers, and one process improvement. Do not claim planned or stretch features as delivered until they are merged and validated.

## 10. Repository settings checklist

A maintainer should complete these UI-level settings after code and CI are ready:

- [x] Create the recommended labels and milestones; assign the existing issues to the current milestone plan.
- [x] Confirm the four contributors' repository access (Vikas: admin; Shivanand, Shivakumara and Sanjith: write).
- [ ] Enable a main-branch pull-request/review rule and conversation-resolution requirement.
- [ ] Require the observed `Lint and test` CI check only after confirming its exact status-check selector in Settings.
- [ ] Enable secret scanning/push protection and Dependabot alerts/security updates where available to this repository/organization.
- [x] Add and verify initial `.github/CODEOWNERS` mappings for Capture, Analysis, Storage, Presentation, tests and Docs.
- [x] Keep the existing Project_Pocket-Packet-Sniffer board as the single source of truth.
- [x] Keep release notes and demo evidence aligned with merged code; latest main CI passed with 81 tests.

The GitHub integration available for this project does not expose project-board item/field mutation or repository branch-protection/security-setting writes. Issue states and milestones can be updated here; the maintainer must verify the board's custom Status/Assignees fields and repository settings in the GitHub UI.

## 11. Current limitations of this setup

PR #24 merged the CLI/session integration, PR #25 merged the Sprint 1 documentation closeout, and PR #29 merged backend SRS completion. Current main commit `cd80e958bf572c32126c3f222579aec638da04b7` passed CI run [40479490511](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40479490511): Ruff passed and 106 tests passed in 1.87 seconds. Remaining repository-level tasks are UI-only: confirm branch protection/required checks and enable available secret-scanning/push-protection and Dependabot controls. The connected GitHub integration can read these settings but cannot write them.
