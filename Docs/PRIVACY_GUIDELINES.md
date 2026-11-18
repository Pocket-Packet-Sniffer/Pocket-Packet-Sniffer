# PocketSniff privacy and responsible-use guidelines

PocketSniff is a passive network-monitoring tool. These guidelines explain the operator's responsibilities and where captured data goes.

## Capture only with authorization

- Capture only networks and devices you own or are explicitly authorized to monitor.
- Select only the network adapters needed for the task and stop capture when it is complete.
- PocketSniff listens to traffic. It is not a tool for injecting, changing, or disrupting network traffic.
- A signal in the dashboard is a rule-based prompt to investigate, not proof of malicious activity. A lack of signals does not prove a network is safe.

## Understand what is visible and stored

- Network adapters expose different traffic. Ordinary Wi-Fi commonly shows this computer's own traffic; visibility of other devices depends on adapter mode, drivers, and network configuration.
- The dashboard presents packet metadata such as addresses, ports, protocol, time, and size. It does not display raw packet message contents.
- Local PCAP capture files may contain sensitive traffic. Treat them, the local packet database, and any selected replay file as private data.
- Session CSV and PDF reports contain packet metadata. Review them before sharing because addresses and timestamps can still identify devices or activity.

## Keep data local and protected

- The capture sensor, PCAP files, searchable database, and generated reports operate on the user's computer.
- A hosted dashboard serves the interface; it does not receive packet captures. The local sensor API should remain bound to loopback (`127.0.0.1`) and must not be exposed publicly.
- When an operator explicitly chooses a PCAP for replay, the browser sends that file to the sensor on the same computer over loopback. It is not uploaded to the hosted website.
- Protect the capture folder with appropriate operating-system access controls. Delete captures and reports when they are no longer needed, following any applicable retention requirements.
- Before sharing a screenshot, report, or capture file, inspect it for addresses, timestamps, device identifiers, and other sensitive details.

## Limitations

PocketSniff cannot determine whether an operator has permission to monitor a network. Its local-only design and metadata-focused dashboard do not remove the need to follow organizational policies, applicable law, and the network owner's instructions.
