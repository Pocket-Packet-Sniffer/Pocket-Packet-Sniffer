# Pocket Packet Sniffer — Dashboard UI preview

This is the first frontend shell for visual iteration. It is deliberately labelled **Preview mode** and uses synthetic sample data only. It does not open a network interface, read a PCAP, call the Python backend, or claim that live packet capture is working.

## Run locally

Requirements: Node.js 20+ and npm.

From the repository root:

\`\`\`powershell
cd web
npm install
npm run dev
\`\`\`

Open the local URL printed by Vite (normally http://127.0.0.1:5173).

Create a production build:

\`\`\`powershell
npm run build
\`\`\`

## Current scope

- Responsive navigation and dashboard layout.
- Clearly marked synthetic sample session.
- Preview-only stream control and packet table filtering.
- Client-side CSV export of the visible sample records.
- No backend or capture connection yet.

## Important

The preview UI is not evidence of a functioning capture session. The next integration step must connect these controls to a local API that reuses the existing Python Capture → Analysis → Storage code. Do not remove the preview warning until live API connectivity and real session data are verified.