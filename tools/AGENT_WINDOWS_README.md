# Pocket Packet Sniffer for Windows

This portable agent connects the hosted PocketSniff dashboard to the network adapters on this Windows computer. It does not require a source-code checkout or Python installation.

## Start the agent

1. Install [Npcap](https://npcap.com/#download) with the default options. Live adapter capture requires its driver.
2. Extract this ZIP and run `pocket-packet-sniffer-agent.exe`. Windows may ask for network-capture permissions when you start a capture.
3. Keep the agent window open and visit [PocketSniff](https://pocket-packet-sniffer.vercel.app).
4. Allow the browser's local-network access prompt, select the connected adapter, and choose **Start capture**.

Capture data is saved under `%LOCALAPPDATA%\PocketPacketSniffer\captures`. The agent binds only to `127.0.0.1`; packet data stays on this computer. Close the agent window to stop the service.

Use only networks and adapters you own or are authorized to monitor. Alerts are metadata-based investigation indicators, not proof of malicious activity.
