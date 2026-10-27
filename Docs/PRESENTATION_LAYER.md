# Presentation Layer

The Presentation Layer provides the CLI for capture control, live statistics, stored-record queries and report export. It consumes application/session, statistics and repository interfaces; it does not parse raw packets or calculate aggregation counters.

## Live statistics

The renderer consumes a snapshot containing:

- `total_packets`: cumulative successfully analyzed/stored packet count
- `total_bytes`: cumulative original packet bytes
- `packets_per_sec`: recent packet rate
- `protocols`: protocol/count pairs
- `top_talkers`: up to five source endpoint/count pairs

The current CLI supports `capture --interface ... --live-dashboard` and `capture-multi ... --live-dashboard`. The refresh loop is configured for two seconds. The file-replay command prints a final statistics snapshot; replay is finite and does not pretend to be live monitoring.

## Query and reports

- `query` accepts protocol, address and timezone-aware inclusive time-window filters. Multiple filters use AND semantics.
- `export --format csv` writes session summary and packet metadata as CSV.
- `export --format pdf` writes the same summary and metadata as a local PDF.
- Exports use the storage repository's session-scoped retrieval method and refuse to overwrite an existing output.
- Report output never contains the raw packet payload.

## Stretch: Observer alerts

The Analysis layer exposes `AlertPublisher`, `AlertEvent` and `SuspiciousActivityDetector`. Presentation subscribes using a callback; the CLI prints only a concise alert event summary. Supported rules are deliberately heuristic: ARP IP/MAC conflict; unrecognized source MAC when a device allowlist is configured; and unrecognized 802.11 beacon BSSID when an AP allowlist is configured. These are investigatory signals, not proof of an attack. AP rule needs actual decoded Wi-Fi beacon frames.

## Verification and limitations

```bash
ruff check --select E4,E7,E9,F,I src tests
pytest -q
```

The feature branch `feat/PPS-28-srs-compliance` is being validated through CI and requires independent review before merge. Automated generated-PCAP tests do not prove live-interface throughput, Wi-Fi monitor mode, BLE hardware support, Windows ACLs, or Raspberry Pi packet-loss performance. The browser dashboard is deferred; the SRS names CLI as the primary interface and web dashboard as a stretch goal.
