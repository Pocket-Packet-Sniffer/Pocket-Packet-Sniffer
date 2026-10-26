# Security and Safe Use

Pocket Packet Sniffer is intended only for passive traffic monitoring on networks and devices the operator owns or is explicitly authorized to monitor.

## Non-negotiable constraints
- The application must not inject, alter, or replay traffic.
- Captured information must not be silently uploaded or sent to external services.
- Capture files can contain sensitive data and should be protected with appropriate local file permissions.
- Logs and test fixtures must not unnecessarily disclose packet payloads, credentials, or personal information.
- Report only supported detection results; do not present heuristic alerts as verified incidents without evidence.

## Reporting a problem
For a suspected security issue, notify the project team privately rather than publishing sensitive capture data or exploit details in a public issue. Include the affected version/commit, a minimal reproducible description, and impact where safe to share. Do not upload real captures containing personal or confidential traffic.