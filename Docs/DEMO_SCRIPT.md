# Pocket Packet Sniffer — End-to-End Demo Script

This script demonstrates the backend implementation for SRS v1.3 using synthetic traffic. It does not require administrator privileges or an active network interface. It complements, rather than replaces, target-hardware smoke tests.

## 1. Prepare the environment

Use Python 3.10 or newer and run the following from the repository root:

```powershell
python -m pip install -e .
python -m pip install -r requirements-dev.txt -r requirements-capture.txt
```

Generate a new synthetic classic-PCAP file. The generator refuses to overwrite an existing file, so choose a fresh filename or remove the old demo file first.

```powershell
python tools/create_demo_pcap.py demo.pcap
```

Expected outcome: a message that a synthetic PCAP with five packets was created. It contains controlled TCP, DNS/UDP, ICMP, and two conflicting ARP claims. It contains no live user traffic.

## 2. Replay through the full pipeline

```powershell
pocket-packet-sniffer capture --pcap-file demo.pcap --storage-dir demo-captures --session-id demo-session
```

Expected results:
- The CLI prints the session identifier and final counters.
- The fixture should report five packets seen and five stored with no ignored packets.
- A metadata-only ARP address-conflict alert is printed to standard error. It is a heuristic investigation signal, not proof of an attack.
- Real PCAP data is written locally and indexed in `demo-captures/metadata.sqlite3`.

This command replays a local file. It does not transmit packets to a network.

## 3. List sessions and query stored metadata

```powershell
pocket-packet-sniffer sessions --storage-dir demo-captures
pocket-packet-sniffer query --storage-dir demo-captures --session-id demo-session --protocol TCP
pocket-packet-sniffer query --storage-dir demo-captures --session-id demo-session --address 192.0.2.1
pocket-packet-sniffer query --storage-dir demo-captures --session-id demo-session --start 2026-10-27T10:00:00+00:00 --end 2026-10-27T10:00:04+00:00
```

Expected outcomes:
- The session list includes `demo-session` with five stored packets.
- The TCP query returns the fixture's matching TCP metadata.
- The address query returns ARP metadata for the synthetic address `192.0.2.1`.
- Query results show timestamps, normalized protocol, source/destination metadata, size, and session ID. Raw packet payloads are not printed.

## 4. Export local reports

```powershell
pocket-packet-sniffer export --storage-dir demo-captures --session-id demo-session --output demo-session.csv --format csv
pocket-packet-sniffer export --storage-dir demo-captures --session-id demo-session --output demo-session.pdf --format pdf
```

Expected outcome: both files are written locally and contain the session summary and packet metadata, not raw payloads. Export fails rather than overwriting an existing destination. Use a new filename for a repeat demo.

## 5. Demonstrate concurrent capture safely

Generate two independent synthetic fixtures:

```powershell
python tools/create_demo_pcap.py demo-a.pcap
python tools/create_demo_pcap.py demo-b.pcap
pocket-packet-sniffer capture-multi --pcap-file demo-a.pcap --pcap-file demo-b.pcap --storage-dir demo-multi-captures --session-id multi-demo --count 6
```

Expected outcome: the concurrent capturer delivers six total packets from two sources, records source/backend metadata, and combines the statistics. Both input sources are local files, so this demonstration does not need live interfaces or elevated capture permissions.

## 6. Run automated verification

```powershell
ruff check --select E4,E7,E9,F,I src tests tools
pytest -q
```

The latest GitHub Actions run for PR #29 passed Ruff and reported 104 passing tests: [CI run 40472573188](https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/actions/runs/40472573188). The PR must still receive independent review before merge.

## 7. Optional authorized live-capture check

Only use a device/network you own or are explicitly authorized to monitor. Confirm the interface name and capture driver for your OS before running:

```powershell
pocket-packet-sniffer capture --interface <YOUR_AUTHORIZED_INTERFACE> --storage-dir live-captures --session-id live-check --live-dashboard
```

Stop with Ctrl+C, or from another terminal using the same storage directory:

```powershell
pocket-packet-sniffer stop --storage-dir live-captures --session-id live-check
```

Record the operating system, interface/adapter, driver, permission context, start/stop result, and any errors. Do not claim that Wi-Fi monitor mode, BLE scanning, Windows ACL behavior, or Raspberry Pi throughput/drop rate passed unless it was tested on the corresponding target hardware.

## Troubleshooting

- **A demo file already exists:** choose a new filename. The generator and report exporters deliberately refuse silent overwrites.
- **CLI command not found:** activate the intended Python environment, then rerun `python -m pip install -e .`.
- **Scapy is missing:** install `requirements-capture.txt` as shown above.
- **No packets match a filter:** verify the session ID, protocol/address, or time range using `sessions` and a broader `query`.
- **Live interface unavailable or permission denied:** check the interface name, OS capture driver, adapter state, and approved permissions. The generated-PCAP demo remains available without privileged capture.
- **PDF/CSV destination exists:** use a new destination; overwrite is intentionally disabled.
- **Wi-Fi/BLE behavior differs by machine:** this is platform/hardware-dependent and must be documented as unverified until tested on the intended adapter/driver.
