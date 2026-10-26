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

The `main` branch is currently not protected. After the application source tree is integrated and a real CI workflow has passed, a repository administrator should open **Settings → Rules → Rulesets** (or **Branches**, depending on the available GitHub UI) and create an active rule targeting `main` with:

- Require a pull request before merging.
- Require at least one approval from someone other than the author.
- Require conversation resolution.
- Require the verified CI status checks.
- Block force pushes and deletion of `main`.

Do **not** require CI checks until the workflow exists and its exact check names have been observed on a successful PR. Otherwise, the team may accidentally make `main` impossible to update. Keep administrator bypass settings deliberate and minimal.

## 7. CI, testing, and dependency hygiene

After code is integrated, add GitHub Actions for the actual language and project layout to run formatting/lint checks, unit tests, and controlled integration tests. Use a PCAP fixture; CI must not require root privileges or capture real network traffic. Add coverage reporting if the test setup supports it, but agree a realistic threshold based on measured coverage rather than inventing one.

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

- [ ] Create the recommended labels.
- [ ] Create milestones and assign relevant issues.
- [ ] Confirm all four contributors have accepted the organization invite and can push branches.
- [ ] Enable a main-branch PR/review rule.
- [ ] Add required CI checks only after observing successful check names.
- [ ] Enable secret scanning and push protection if available for the repository/organization plan.
- [ ] Enable Dependabot alerts/security updates; add version updates once package manifests are present.
- [ ] Add Code Owners after verifying the source paths.
- [ ] Use a single agreed project board rather than creating duplicates.
- [ ] Keep generated release notes and demo evidence aligned with merged code.

## 11. Current limitations of this setup

The working PR establishes process documentation and forms. It does not yet add application CI, CODEOWNERS, or branch protections because the source tree and its validated checks are not yet in `main`. GitHub labels, milestones, repository rules, and organization-level security settings need a maintainer action in the GitHub UI; this integration does not expose write operations for those settings.
