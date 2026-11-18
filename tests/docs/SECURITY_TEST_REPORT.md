# Security Test Report

**Evidence revision:** merged `main` commit `0839abf`; CI [run #731](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/44364160089) passed.
**Disposition:** automated security-contract tests pass as part of the Python suite; this is not a penetration test or independent security audit.

## Security objectives and evidence

| Objective | Automated/code evidence | Result and limit |
|---|---|---|
| Passive-only capture | `tests/test_security_contracts.py`; source-level capture contracts | Automated regression checks enforce the listen-only design. They do not assess the OS driver or all future code changes. |
| Browser write-origin control | `tests/test_api.py::test_browser_write_rejects_unapproved_website_origin` and API tests | Rejected-origin path is tested. Configure `PPS_ALLOWED_ORIGINS` narrowly for any hosted dashboard. |
| Minimal packet detail exposure | API safe-metadata tests, report exporter tests, `web/tests/e2e/dashboard.spec.ts` | App presents packet metadata and reports omit raw payload content by design; packet capture files can still contain sensitive data. |
| Local data storage | `tests/test_storage_query.py`, `Docs/PRIVACY_GUIDELINES.md` | PCAP, SQLite, and exports remain on the sensor computer. POSIX mode tests are platform conditional. |
| Error handling and explicit capture control | capture/API/CLI tests and browser capture controls | Controlled permission/source failure paths are tested; actual denied Windows driver permission was not induced in acceptance. |
| Production boundary | `Docs/WEB_DEPLOYMENT.md`; local-only API design | Vercel serves the UI only. Do not expose the local capture API publicly. |

## Current suite result

The merged Python CI suite passed **171 tests with 2 platform skips**. The skipped POSIX mode tests do not verify Windows ACLs. Ruff also passed on the source/test/tool scope; see [Test Execution Report](TEST_EXECUTION_REPORT.md). The separate live Wi-Fi acceptance run was passive and kept captured records local; this is not adversarial/security testing.

## Required handling guidance

- Capture only networks/devices you own or have explicit permission to inspect.
- Treat PCAPs and packet metadata as sensitive; review and sanitize before sharing.
- Bind the local sensor to loopback and configure exact dashboard origins.
- Do not describe heuristic alert events as proof of an attack or absence of an attack.

## Not assessed / not run

- Formal threat model review, third-party penetration test, dependency vulnerability audit, or adversarial fuzzing campaign.
- Windows ACL verification on stored files.
- Live BLE radio security, Wi-Fi monitor-mode behavior, Raspberry Pi or packet-drop behavior, and physical multi-adapter capture.
- Security of a publicly exposed API; public exposure is outside the supported deployment design.

See [Security Validation](../../Docs/SECURITY_VALIDATION.md), [Privacy Guidelines](../../Docs/PRIVACY_GUIDELINES.md), and the [SRS acceptance report](ACCEPTANCE_TEST_REPORT.md) for system boundaries and open checks.
