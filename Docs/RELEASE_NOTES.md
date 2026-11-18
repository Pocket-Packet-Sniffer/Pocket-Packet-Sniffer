# Pocket Packet Sniffer 1.0.0

Pocket Packet Sniffer 1.0.0 is the first stable release of the documented local packet-capture and metadata-analysis workflow.

## Included

- Passive packet capture from supported local Wi-Fi and Ethernet interfaces through the installed capture driver.
- Local PCAP and SQLite storage, packet/session search, protocol and endpoint summaries, and CSV/PDF session reports.
- A dashboard that connects to the local sensor and displays captured packet metadata, traffic activity, and rule-based review signals.
- A portable Windows capture-agent archive published with this release. The dashboard also remains available as a hosted interface; capture and packet storage stay on the operator's computer.
- Existing 0.2.1 and 0.2.2 sensors remain recognized by the dashboard and receive an update notice.

## Install and run the Windows sensor

1. Install Npcap on the Windows computer and select the installation options required for ordinary adapter capture.
2. Download `pocket-packet-sniffer-agent-windows.zip` from this release and extract it.
3. Run `pocket-packet-sniffer-agent.exe` and keep its window open.
4. Open the dashboard, allow its local-network connection to `127.0.0.1` if prompted, select an active adapter, and explicitly start capture.

The sensor listens only on loopback. Captures and metadata remain local. Use it only on a network you own or are authorized to monitor.

## Scope and limitations

- The stable scope covers the implemented local capture, PCAP replay, metadata analysis, storage, and dashboard workflows. Adapter and driver support still varies by operating system and hardware.
- Live BLE radio scanning is not implemented. BLE metadata can be decoded from supported capture files; that is not live BLE acquisition.
- Wi-Fi monitor mode depends on a compatible adapter and driver and is not claimed as validated by this release.
- No Raspberry Pi throughput, zero-loss, or NIC/kernel drop-counter guarantee is claimed. A short capture storing all packets it observed does not prove that the adapter or operating system dropped none upstream.
- Rule-based activity signals are prompts for investigation, not proof of malicious activity. No detected signal does not establish that a network is safe.
- The Vercel-hosted dashboard does not capture remote visitors' traffic; each computer requires its own local sensor.

## Verification

The release tag runs the Windows-agent lint, focused regression tests, executable startup/health smoke test, and archive packaging workflow. The merged 1.0.0 source is also covered by the repository's Linux/Windows CI and dashboard build/browser checks. See the latest [GitHub Actions run](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions) and the [acceptance report](../tests/docs/ACCEPTANCE_TEST_REPORT.md) for measured results and hardware checks that remain unverified.
