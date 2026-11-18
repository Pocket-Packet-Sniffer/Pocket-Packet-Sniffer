# PocketSniff live-traffic presentation guide

This is the presentation flow for showing **real traffic from an authorized adapter**. The dashboard does not bundle, generate, or display sample packet activity. Automated fixtures are used only by the test suite and CI; never present them as live capture.

## Before presenting

1. Use a computer and network you own or are explicitly authorized to monitor.
2. On Windows, install Npcap and start the current `pocket-packet-sniffer-agent.exe` from the [latest agent release](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/releases/latest). Keep its window open. The agent stores captures under the current user's local application data folder and listens only on `127.0.0.1`.
3. Open the [PocketSniff dashboard](https://pocket-packet-sniffer.vercel.app). Allow the browser's local-network permission when prompted, then connect to the sensor.
4. Confirm the dashboard says **Sensor Ready** and lists a connected Ethernet or Wi-Fi adapter. If the browser cannot reach the agent, use the local dashboard and local API together, as described in `Docs/WEB_DEPLOYMENT.md`.

## Live demonstration

1. On Overview, explain that the dashboard displays real packet metadata from the selected local sensor. Capture is passive: it does not inject or alter network traffic.
2. Select the connected adapter you are authorized to monitor. Leave the optional capture filter blank to see all supported traffic, or use a narrow filter such as `tcp port 443` if you want to focus the view.
3. Click **Start watching**. Generate ordinary activity on this computer, such as loading a page you choose. Do not use a packet generator or fabricated traffic for the presentation.
4. Point out the actual packet rate, session count, saved traffic, protocol breakdown, address rankings, activity chart, and source/destination ports in Packets. Click an address in the network map to open the matching saved packets.
5. Explain any review signals as rule-based prompts. They are not proof of an attack, and no signal does not prove a network is safe. Do not attempt an attack or create suspicious traffic for this demo.
6. Click **Stop watching**. Open Sessions to show the real saved session and download its CSV or PDF metadata report. Explain that capture files and reports stay on this computer and should be treated as sensitive.

## Explain capability limits clearly

- Ordinary Wi-Fi shows what the adapter and driver provide; it commonly shows this computer's own traffic.
- Wi-Fi monitor mode needs a compatible adapter and driver configured for that mode. PocketSniff does not enable radio modes, and this setup has not been validated with a monitor-mode adapter.
- The current Windows sensor does not perform live Bluetooth LE scanning. Supported BLE PCAP link types can be decoded from a selected capture file, but that is not a live BLE radio capture.
- Classic `.pcap` and `.cap` replay is supported. PCAPNG is not supported. A selected replay file is sent only to the local sensor on the same computer.
- Raspberry Pi throughput/drop rates, Windows ACLs, and simultaneous physical adapters have not been verified for this presentation build.

## Troubleshooting

- **Sensor offline:** keep the packaged agent running, reconnect from the dashboard, and allow browser access to the local network.
- **No connected adapter:** confirm the adapter is up, install Npcap on Windows, and refresh the dashboard. Use only the adapter you are authorized to monitor.
- **No packets appear:** generate normal activity on the selected computer, check the optional capture filter, and confirm the selected adapter is the active one.
- **Capture permission error:** check Npcap installation and the permission requested by the OS. Do not change to an unapproved network to get a result.
- **Unexpected alert:** open its rule and metadata evidence; describe it as a signal to investigate, not a confirmed threat.

## Post-presentation engineering verification

Run automated checks separately from the live demonstration:

```powershell
ruff check --select E4,E7,E9,F,I src tests tools
python -m pytest -q
cd web
npm ci
npm run typecheck
npm run build
npm run test:e2e -- --workers=1
```

These tests use generated packet fixtures and mocked browser responses as test inputs only. They verify code paths and user flows; they are not evidence of live traffic. See [the SRS acceptance report](../tests/docs/ACCEPTANCE_TEST_REPORT.md) for measured results and outstanding target-hardware gates.
