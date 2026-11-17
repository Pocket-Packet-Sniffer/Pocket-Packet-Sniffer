"use client";

import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  Check,
  ChevronDown,
  Download,
  FileText,
  Filter,
  HardDrive,
  LayoutDashboard,
  Menu,
  Network,
  Play,
  Radio,
  Search,
  Settings,
  ShieldCheck,
  Square,
  Wifi,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

type Packet = {
  id: string | number;
  session_id: string;
  time: string;
  timestamp: number;
  protocol: string;
  source: string;
  destination: string;
  length: number;
  info: string;
};
type Overview = {
  total_packets: number;
  total_bytes: number;
  active_sessions: number;
  protocols: Record<string, number>;
  top_talkers: [string, number][];
};
type Session = {
  session_id: string;
  packet_count: number;
  first_packet_at: string | null;
  last_packet_at: string | null;
};
type CaptureStatus = {
  state: string;
  session_id: string | null;
  source: string | null;
  interface: string | null;
  started_at: string | null;
  result: {
    packets_seen: number;
    packets_stored: number;
    packets_ignored: number;
    exit_code: number | null;
  } | null;
  error: string | null;
};
type CaptureInterface = {
  name: string;
  description: string;
  friendly_name?: string;
  ips: string[];
  mac: string | null;
  status?: string;
  capture_candidate?: boolean;
  recommended?: boolean;
};
type Alert = {
  id: string;
  session_id: string;
  rule_id: string;
  severity: string;
  message: string;
  time: string;
  evidence: Record<string, string>;
};

const API = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
const nav = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Packets", icon: Activity },
  { label: "Alerts", icon: AlertTriangle },
  { label: "Sessions", icon: Radio },
  { label: "Settings", icon: Settings },
];
const emptyOverview: Overview = {
  total_packets: 0,
  total_bytes: 0,
  active_sessions: 0,
  protocols: {},
  top_talkers: [],
};
const idleCapture: CaptureStatus = {
  state: "idle",
  session_id: null,
  source: null,
  interface: null,
  started_at: null,
  result: null,
  error: null,
};

function formatDate(value: string | null) {
  return value ? new Date(value).toLocaleString() : "—";
}

function exportCsv(rows: Packet[]) {
  const csv = [
    ["ID", "Time", "Session", "Protocol", "Source", "Destination", "Length", "Info"],
    ...rows.map((packet) => [
      packet.id,
      packet.time,
      packet.session_id,
      packet.protocol,
      packet.source,
      packet.destination,
      packet.length,
      packet.info,
    ]),
  ]
    .map((row) => row.map((value) => `"${String(value).replace(/"/g, '""')}"`).join(","))
    .join("\r\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "pocket-packet-sniffer.csv";
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function App() {
  const [page, setPage] = useState("Overview");
  const [rows, setRows] = useState<Packet[]>([]);
  const [overview, setOverview] = useState<Overview>(emptyOverview);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [capture, setCapture] = useState<CaptureStatus>(idleCapture);
  const [captureMode, setCaptureMode] = useState<"interface" | "pcap">("interface");
  const [iface, setIface] = useState("");
  const [interfaces, setInterfaces] = useState<CaptureInterface[]>([]);
  const [interfaceError, setInterfaceError] = useState("");
  const [pcapPath, setPcapPath] = useState("");
  const [captureBusy, setCaptureBusy] = useState(false);
  const [online, setOnline] = useState(false);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("All protocols");
  const [menuOpen, setMenuOpen] = useState(false);
  const [toast, setToast] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function loadInterfaces() {
      try {
        const response = await fetch(`${API}/api/interfaces`, { cache: "no-store" });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Could not load network adapters.");
        if (cancelled) return;
        const available = (data.interfaces || []) as CaptureInterface[];
        const candidates = available.filter(
          (item) =>
            item.capture_candidate !== false &&
            !/wan miniport|network monitor|loopback|wi-fi direct/i.test(
              [item.description, item.friendly_name, item.name].join(" "),
            ),
        );
        setInterfaces(candidates);
        const hasUsableAddress = (item: CaptureInterface) =>
          item.ips?.some(
            (ip) =>
              /^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip) &&
              !ip.startsWith("127.") &&
              !ip.startsWith("169.254."),
          );
        const best =
          candidates.find((item) => item.recommended && item.status === "Up") ||
          candidates.find((item) => item.status === "Up" && hasUsableAddress(item)) ||
          candidates.find((item) => item.status === "Up");
        setIface((current) =>
          candidates.some((item) => item.name === current) ? current : best?.name || "",
        );
        setInterfaceError(
          candidates.length ? "" : "No suitable adapters found. Check Npcap and adapter state.",
        );
      } catch (cause) {
        if (!cancelled) {
          setInterfaceError(
            cause instanceof Error ? cause.message : "Could not load network adapters.",
          );
        }
      }
    }
    void loadInterfaces();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function refresh() {
      try {
        const response = await fetch(`${API}/api/health`, { cache: "no-store" });
        if (!response.ok) throw new Error(`Capture agent health check failed (HTTP ${response.status}).`);
        const health = await response.json();
        if (health.status !== "ok") throw new Error("Capture agent did not report a healthy state.");
        if (cancelled) return;
        setOnline(true);
        setError("");
      } catch (cause) {
        if (cancelled) return;
        setOnline(false);
        setError(cause instanceof Error ? cause.message : "Could not reach the local capture agent.");
        return;
      }

      const results = await Promise.allSettled([
        fetch(`${API}/api/overview`, { cache: "no-store" }),
        fetch(`${API}/api/packets?limit=250`, { cache: "no-store" }),
        fetch(`${API}/api/sessions`, { cache: "no-store" }),
        fetch(`${API}/api/alerts?limit=100`, { cache: "no-store" }),
      ]);
      if (cancelled) return;
      const [summary, packetResult, sessionResult, alertResult] = results;
      if (summary.status === "fulfilled" && summary.value.ok) {
        try {
          setOverview(await summary.value.json());
        } catch {
          // Preserve the last complete summary if a response is malformed.
        }
      }
      if (packetResult.status === "fulfilled" && packetResult.value.ok) {
        try {
          const data = await packetResult.value.json();
          setRows(
            (data.packets || []).map((packet: Record<string, unknown>) => ({
              id: packet.id as string | number,
              session_id: String(packet.session_id || ""),
              time: formatDate(String(packet.time || "")),
              timestamp: Date.parse(String(packet.time || "")),
              protocol: String(packet.protocol || "OTHER"),
              source: String(packet.source || "—"),
              destination: String(packet.destination || "—"),
              length: Number(packet.length || 0),
              info: String(packet.info || `${packet.protocol || "Packet"} packet`),
            })),
          );
        } catch {
          // Preserve the last complete packet list if a response is malformed.
        }
      }
      if (sessionResult.status === "fulfilled" && sessionResult.value.ok) {
        try {
          setSessions((await sessionResult.value.json()) || []);
        } catch {
          // Preserve the last complete session list.
        }
      }
      if (alertResult.status === "fulfilled" && alertResult.value.ok) {
        try {
          const data = await alertResult.value.json();
          setAlerts(data.alerts || []);
        } catch {
          // Preserve the last complete alert list.
        }
      }
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 2500);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const response = await fetch(`${API}/api/capture/status`, { cache: "no-store" });
        if (!response.ok) throw new Error("Capture status request failed.");
        const status = (await response.json()) as CaptureStatus;
        if (!cancelled) {
          setCapture((current) => {
            const currentActive = ["starting", "running", "stopping"].includes(current.state);
            if (current.state === "starting" && !status.session_id && status.state === "idle") {
              return current;
            }
            if (currentActive && current.session_id && current.session_id !== status.session_id) {
              return current;
            }
            if (current.state === "error" && !status.session_id && status.state === "idle") {
              return current;
            }
            return status;
          });
        }
      } catch {
        // The health request owns the connection state shown in the header.
      }
      if (!cancelled) {
        const active = ["starting", "running", "stopping"].includes(capture.state);
        timer = window.setTimeout(poll, active ? 350 : 1500);
      }
    };
    void poll();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [capture.state, capture.session_id]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(""), 3200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const filtered = useMemo(
    () =>
      rows.filter(
        (packet) =>
          (!query ||
            [
              packet.protocol,
              packet.source,
              packet.destination,
              packet.info,
              String(packet.id),
              packet.session_id,
            ].some((value) => value.toLowerCase().includes(query.toLowerCase()))) &&
          (protocol === "All protocols" || packet.protocol.toUpperCase() === protocol),
      ),
    [rows, query, protocol],
  );
  const protocols = Object.entries(overview.protocols).sort((left, right) => right[1] - left[1]);
  const maxTalker = Math.max(...overview.top_talkers.map((item) => item[1]), 1);
  const activityBins = useMemo(() => {
    const times = rows.map((packet) => packet.timestamp).filter(Number.isFinite);
    const buckets = Array.from({ length: 18 }, () => 0);
    if (!times.length) return buckets;
    const start = Math.min(...times);
    const span = Math.max(Math.max(...times) - start, 17_000);
    for (const time of times) buckets[Math.min(17, Math.floor(((time - start) / span) * 18))] += 1;
    return buckets;
  }, [rows]);
  const maxActivity = Math.max(...activityBins, 1);
  const title = page === "Overview" ? "Network overview" : page;
  const captureActive = ["running", "starting", "stopping"].includes(capture.state);

  async function startCapture() {
    setCaptureBusy(true);
    setCapture({
      ...idleCapture,
      state: "starting",
      source: captureMode,
      interface: captureMode === "interface" ? iface : pcapPath,
    });
    try {
      const response = await fetch(`${API}/api/capture/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(
          captureMode === "interface"
            ? { mode: "interface", interface: iface.trim() }
            : { mode: "pcap", pcap_path: pcapPath.trim(), delay: 0 },
        ),
        cache: "no-store",
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Could not start capture (HTTP ${response.status}).`);
      setCapture(data);
      setToast(captureMode === "interface" ? "Live capture started." : "PCAP replay started.");
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Capture could not start.";
      setCapture((current) => ({ ...current, state: "error", error: message }));
      setToast(message);
    } finally {
      setCaptureBusy(false);
    }
  }

  async function stopCapture() {
    setCaptureBusy(true);
    try {
      const response = await fetch(`${API}/api/capture/stop`, { method: "POST", cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not stop capture.");
      setCapture((current) => ({ ...current, state: data.state || "stopping" }));
      setToast("Stop requested. Final packet counts are updating.");
    } catch (cause) {
      setToast(cause instanceof Error ? cause.message : "Capture could not stop.");
    } finally {
      setCaptureBusy(false);
    }
  }

  return (
    <div className="app-shell">
      {menuOpen && <button className="scrim" onClick={() => setMenuOpen(false)} aria-label="Close navigation" />}
      <aside className={`sidebar ${menuOpen ? "open" : ""}`}>
        <div className="brand">
          <div className="brand-icon"><Network size={20} /></div>
          <div><strong>pocket<span>sniff</span></strong><small>NETWORK DEFENSE CONSOLE</small></div>
          <button className="icon-btn side-close" onClick={() => setMenuOpen(false)} aria-label="Close navigation"><X size={17} /></button>
        </div>
        <div className="workspace">
          <div className="work-icon"><ShieldCheck size={17} /></div>
          <div><strong>Local sensor</strong><small>Capture stays on this device</small></div>
          <span className={`connection-dot ${online ? "connected" : ""}`} />
        </div>
        <nav aria-label="Main navigation">
          <div className="nav-caption">MONITOR</div>
          {nav.slice(0, 4).map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={`nav-item ${page === label ? "active" : ""}`}
              onClick={() => { setPage(label); setMenuOpen(false); }}
            >
              <Icon size={17} /><span>{label}</span>
              {label === "Packets" && <small>{overview.total_packets.toLocaleString()}</small>}
              {label === "Alerts" && alerts.length > 0 && <small className="alert-count">{alerts.length}</small>}
            </button>
          ))}
          <div className="nav-caption manage">SYSTEM</div>
          <button className={`nav-item ${page === "Settings" ? "active" : ""}`} onClick={() => { setPage("Settings"); setMenuOpen(false); }}>
            <Settings size={17} /><span>Settings</span>
          </button>
        </nav>
        <div className="sidebar-bottom">
          <div className="privacy-card"><ShieldCheck size={17} /><div><strong>Payloads stay private</strong><small>Metadata-first analysis</small></div><Check size={15} /></div>
          <div className="operator"><div className="avatar">PS</div><div><strong>Local operator</strong><small>Authorized capture only</small></div></div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <button className="icon-btn menu-btn" onClick={() => setMenuOpen(true)} aria-label="Open navigation"><Menu size={20} /></button>
          <div className="crumb">Workspace <span>/</span> <strong>{title}</strong></div>
          <label className="global-search"><Search size={16} /><input value={query} onChange={(event) => { setQuery(event.target.value); if (event.target.value) setPage("Packets"); }} placeholder="Search captured traffic" /><kbd>CTRL K</kbd></label>
          <div className="top-actions"><span className={`connection-pill ${online ? "online" : "offline"}`}><i />{online ? "SENSOR CONNECTED" : "SENSOR OFFLINE"}</span></div>
        </header>

        <div className="content">
          {!online && (
            <section className="connection-banner" role="status">
              <div className="banner-icon"><Radio size={18} /></div>
              <div><strong>Connect your local capture sensor</strong><p>{error || "Start the Pocket Packet Sniffer agent on this computer to see real packet data."}</p></div>
              <code>.\run-local.ps1</code>
            </section>
          )}
          {online && error && <div className="inline-error" role="alert">{error}</div>}

          <div className="page-heading">
            <div><div className="eyebrow"><span /> LIVE NETWORK TELEMETRY</div><h1>{title}<em>.</em></h1><p>Observe authorized traffic, inspect packet metadata, and investigate heuristic alerts.</p></div>
            <div className="heading-buttons"><button className="btn secondary" onClick={() => exportCsv(filtered)} disabled={!filtered.length}><ArrowDownToLine size={16} /> Export CSV</button><button className="btn primary" onClick={() => setPage("Packets")}><Search size={16} /> Explore packets</button></div>
          </div>

          {(page === "Overview" || page === "Packets") && (
            <section className="capture card">
              <div className="capture-head">
                <div className="capture-title"><div className="capture-symbol"><Radio size={19} /></div><div><h2>Capture control</h2><p>Start a passive capture on an adapter you’re authorized to monitor, or replay a local PCAP.</p></div></div>
                <span className={`status ${capture.state}`}><i />{capture.state === "running" ? "Capturing" : capture.state === "starting" ? "Starting" : capture.state === "stopping" ? "Stopping" : capture.state === "error" ? "Needs attention" : capture.state === "stopped" ? "Stopped" : "Ready"}</span>
              </div>
              <div className="capture-row">
                <div className="mode-switch"><button className={captureMode === "interface" ? "selected" : ""} disabled={captureActive || captureBusy} onClick={() => setCaptureMode("interface")}><Wifi size={15} /> Live interface</button><button className={captureMode === "pcap" ? "selected" : ""} disabled={captureActive || captureBusy} onClick={() => setCaptureMode("pcap")}><FileText size={15} /> PCAP replay</button></div>
                {captureMode === "interface" ? (
                  <label className="field"><small>NETWORK ADAPTER</small><span className="select-wrap"><select value={iface} onChange={(event) => setIface(event.target.value)} disabled={!online || captureActive || captureBusy || !interfaces.length}><option value="">Select an active adapter</option>{interfaces.map((item) => <option key={item.name} value={item.name}>{item.friendly_name || item.description || item.name}{item.recommended ? " · Recommended" : ""}</option>)}</select><ChevronDown size={15} /></span><span className="adapter-hint">{interfaceError || interfaces.find((item) => item.name === iface)?.description || "Choose Wi-Fi or Ethernet connected to your authorized network."}</span></label>
                ) : (
                  <label className="field"><small>LOCAL PCAP FILE</small><input className="pcap-input" value={pcapPath} onChange={(event) => setPcapPath(event.target.value)} placeholder="C:\\captures\\session.pcap" disabled={captureActive || captureBusy} /></label>
                )}
                <div className="capture-action">{capture.state === "running" || capture.state === "stopping" ? <button className="btn danger" disabled={captureBusy} onClick={() => void stopCapture()}><Square size={14} fill="currentColor" /> Stop capture</button> : <button className="btn primary" disabled={!online || captureBusy || (captureMode === "interface" ? !iface : !pcapPath.trim())} onClick={() => void startCapture()}><Play size={14} fill="currentColor" />{captureMode === "pcap" ? "Replay capture" : "Start capture"}</button>}<small><ShieldCheck size={13} /> Sensor remains local</small></div>
              </div>
              {capture.result && <p className="capture-result">{capture.state === "running" ? "Live progress" : "Last session"}: {capture.result.packets_seen.toLocaleString()} seen · {capture.result.packets_stored.toLocaleString()} stored · {capture.result.packets_ignored.toLocaleString()} ignored</p>}
              {capture.error && <p className="capture-error" role="alert">{capture.error}</p>}
            </section>
          )}

          {page === "Overview" && (
            <>
              <section className="metrics">
                <Metric title="Packets captured" value={overview.total_packets.toLocaleString()} sub="Stored packet records" icon={<Activity size={17} />} color="purple" />
                <Metric title="Captured volume" value={`${(overview.total_bytes / 1048576).toFixed(2)} MB`} sub="Data observed by local sensor" icon={<HardDrive size={17} />} color="blue" />
                <Metric title="Heuristic alerts" value={alerts.length.toLocaleString()} sub="Signals requiring human review" icon={<AlertTriangle size={17} />} color="amber" />
                <Metric title="Capture sessions" value={String(overview.active_sessions)} sub="Recorded locally" icon={<Network size={17} />} color="teal" />
              </section>

              <section className="network-grid">
                <div className="flow-panel card">
                  <div className="section-head"><div><span className="section-kicker">OBSERVED TRAFFIC</span><h2>Network flow</h2><p>Source and destination addresses from captured packets</p></div><span className="result-count">{rows.length.toLocaleString()} recent records</span></div>
                  <div className="flow-canvas">
                    <div className="flow-column"><span className="flow-label">SOURCES</span>{Array.from(new Set(rows.map((packet) => packet.source))).slice(0, 4).map((address) => <div className="flow-node source-node" key={address}><i />{address}</div>)}{!rows.length && <div className="flow-empty">No captured sources yet</div>}</div>
                    <div className="flow-middle"><div className="flow-lines"><i /><i /><i /><i /></div><div className="flow-core"><Network size={23} /><span>LOCAL<br />SENSOR</span></div><div className="flow-footnote">METADATA ONLY</div></div>
                    <div className="flow-column destination-column"><span className="flow-label">DESTINATIONS</span>{Array.from(new Set(rows.map((packet) => packet.destination))).slice(0, 4).map((address, index) => <div className={`flow-node destination-node flow-tone-${index % 4}`} key={address}><i />{address}</div>)}{!rows.length && <div className="flow-empty">Waiting for real traffic</div>}</div>
                  </div>
                </div>
                <div className="analytics-side">
                  <div className="card protocol-card"><div className="section-head"><div><h2>Protocol mix</h2><p>Classification of stored packets</p></div></div><div className="protocol-total"><strong>{overview.total_packets.toLocaleString()}</strong><span>recorded packets</span></div><div className="stacked">{protocols.map(([name, count], index) => <i key={name} className={["purple", "blue", "teal", "amber", "gray"][index % 5]} style={{ width: `${overview.total_packets ? (count / overview.total_packets) * 100 : 0}%` }} />)}</div><div className="protocol-list">{protocols.map(([name, count], index) => <div className="protocol-row" key={name}><i className={["purple", "blue", "teal", "amber", "gray"][index % 5]} /><span>{name}</span><strong>{count.toLocaleString()}</strong><small>{overview.total_packets ? `${((count / overview.total_packets) * 100).toFixed(1)}%` : "0%"}</small></div>)}{!protocols.length && <p className="quiet-empty">Protocol data appears when capture starts.</p>}</div></div>
                  <div className="card talker-card"><div className="section-head"><div><h2>Top talkers</h2><p>Most frequently observed addresses</p></div></div>{overview.top_talkers.map(([address, count], index) => <div className="talker" key={address}><span className={`rank ${index === 0 ? "first" : ""}`}>{String(index + 1).padStart(2, "0")}</span><div className="talker-info"><strong>{address}</strong><small>Observed endpoint</small><div className="bar"><i style={{ width: `${(count / maxTalker) * 100}%` }} /></div></div><b>{count.toLocaleString()}</b></div>)}{!overview.top_talkers.length && <p className="quiet-empty">No addresses observed yet.</p>}</div>
                </div>
              </section>

              <section className="activity-grid">
                <div className="card activity-card"><div className="section-head"><div><h2>Traffic activity</h2><p>Distribution across the latest captured records</p></div><span className="live-sample"><i />{rows.length.toLocaleString()} observed</span></div><div className="activity-chart" role="img" aria-label={rows.length ? "Packet counts across chronological buckets" : "No captured traffic yet"}><div className="activity-y"><span>HIGH</span><span>MED</span><span>LOW</span></div><div className="activity-bars">{activityBins.map((count, index) => <div className="activity-column" key={index} title={`${count} captured packets`}><i style={{ height: `${count ? Math.max(5, (count / maxActivity) * 100) : 2}%` }} /><span>{String(index + 1).padStart(2, "0")}</span></div>)}</div></div><div className="activity-foot"><span><i className="legend-dot purple-dot" />Captured packet records</span><span>Only locally observed traffic is shown</span></div></div>
                <div className="card signal-card"><div className="section-head"><div><h2>Sensor health</h2><p>Current local collector state</p></div><span className={`health-indicator ${capture.state === "running" ? "health-running" : ""}`}><i />{capture.state === "running" ? "Live" : capture.state === "error" ? "Error" : capture.state === "stopped" ? "Stopped" : online ? "Ready" : "Offline"}</span></div><div className="signal-main"><div className="signal-icon"><Radio size={21} /></div><div><strong>{capture.state === "running" ? "Collecting real packets" : capture.state === "stopping" ? "Stopping sensor" : capture.state === "error" ? "Capture needs attention" : capture.state === "stopped" ? "Last capture stopped" : online ? "Ready for authorized capture" : "Sensor not connected"}</strong><p>{capture.interface || "Select an adapter or replay a local PCAP"}</p></div></div><div className="signal-stats"><div><small>Seen</small><strong>{capture.result?.packets_seen?.toLocaleString() ?? "—"}</strong></div><div><small>Stored</small><strong>{capture.result?.packets_stored?.toLocaleString() ?? "—"}</strong></div><div><small>Ignored</small><strong>{capture.result?.packets_ignored?.toLocaleString() ?? "—"}</strong></div></div></div>
              </section>

              <section className="lower"><div className="card recent-card"><div className="section-head"><div><h2>Recent packets</h2><p>Latest records from the local sensor</p></div><button className="link-button" onClick={() => setPage("Packets")}>Open explorer <span>→</span></button></div><PacketTable rows={rows.slice(0, 8)} /></div><AlertPreview alerts={alerts} onOpen={() => setPage("Alerts")} /></section>
            </>
          )}

          {page === "Packets" && <section className="card explorer"><div className="section-head"><div><h2>Packet explorer</h2><p>Search real captured metadata. Payload contents are not displayed.</p></div><span className="result-count">{filtered.length.toLocaleString()} records</span></div><div className="filters"><label className="searchbox"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search address, protocol, session" /></label><label className="protocol-select"><Filter size={15} /><select value={protocol} onChange={(event) => setProtocol(event.target.value)}><option>All protocols</option>{Array.from(new Set(rows.map((packet) => packet.protocol.toUpperCase()))).sort().map((name) => <option key={name}>{name}</option>)}</select><ChevronDown size={14} /></label><button className="btn secondary" onClick={() => { setQuery(""); setProtocol("All protocols"); }}><X size={14} /> Clear</button></div><PacketTable rows={filtered} empty={online ? "No packets captured yet. Start an authorized capture to populate this table." : "Connect the local sensor to inspect captured packets."} /><div className="table-bottom"><span>Metadata only · raw packet payloads are not shown</span><button className="btn secondary" onClick={() => exportCsv(filtered)} disabled={!filtered.length}><ArrowDownToLine size={15} /> Export rows</button></div></section>}

          {page === "Alerts" && <section className="card explorer alerts-page"><div className="section-head"><div><span className="section-kicker">INVESTIGATION QUEUE</span><h2>Suspicious activity signals</h2><p>Rule-based indicators from packets captured by this local sensor.</p></div><span className="result-count">{alerts.length} alerts</span></div><div className="heuristic-note"><ShieldCheck size={17} /><span>Alerts are heuristics for analyst review, not proof of malicious activity. No packet payloads are retained in alert evidence.</span></div><AlertTable alerts={alerts} /></section>}

          {page === "Sessions" && <section className="card explorer"><div className="section-head"><div><h2>Capture sessions</h2><p>Sessions recorded by local storage.</p></div><span className="result-count">{sessions.length} sessions</span></div><div className="table-wrap"><table><thead><tr><th>Session ID</th><th>Packets</th><th>First packet</th><th>Last packet</th></tr></thead><tbody>{sessions.length ? sessions.map((session) => <tr key={session.session_id}><td className="id-cell">{session.session_id}</td><td>{session.packet_count.toLocaleString()}</td><td>{formatDate(session.first_packet_at)}</td><td>{formatDate(session.last_packet_at)}</td></tr>) : <tr><td colSpan={4} className="empty">No capture sessions recorded yet.</td></tr>}</tbody></table></div></section>}

          {page === "Settings" && <section className="card settings"><div className="section-head"><div><h2>Sensor settings</h2><p>Local collection and privacy boundaries.</p></div><Settings size={19} /></div><div className="agent-download-card"><div className="agent-download-icon"><Download size={19} /></div><div><strong>Use PocketSniff on another PC</strong><p>Download the portable Windows sensor. No source checkout or Python setup required. Npcap is required for live adapter capture.</p></div><a className="btn primary" href="https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/releases/latest/download/pocket-packet-sniffer-agent-windows.zip" target="_blank" rel="noreferrer"><Download size={15} /> Download agent</a></div><Setting icon={<Radio size={18} />} title="Local capture API" value={API} status={online ? "CONNECTED" : "OFFLINE"} /><Setting icon={<HardDrive size={18} />} title="Packet storage" value="PCAP and SQLite files stay on this device." status="LOCAL" /><Setting icon={<ShieldCheck size={18} />} title="Analysis mode" value="Metadata-based rules; no payload inspection." status="PRIVATE" /><Setting icon={<AlertTriangle size={18} />} title="Device allowlists" value="Set PPS_KNOWN_DEVICES and PPS_KNOWN_ACCESS_POINTS on the local sensor to enable inventory-based indicators." status="OPTIONAL" /></section>}

          <footer className="footer"><div><Network size={14} /><strong>POCKET PACKET SNIFFER</strong><span>·</span> Live local network analysis</div><div><ShieldCheck size={14} /> Authorized capture only <span>Payload privacy preserved</span></div></footer>
        </div>
      </main>
      {toast && <div className="toast" role="status"><Check size={16} /><span>{toast}</span><button onClick={() => setToast("")} aria-label="Dismiss notification"><X size={15} /></button></div>}
    </div>
  );
}

function Metric({ title, value, sub, icon, color }: { title: string; value: string; sub: string; icon: React.ReactNode; color: string }) {
  return <div className="metric card"><div className="metric-head"><span>{title}</span><i className={color}>{icon}</i></div><div className="metric-number">{value}</div><div className="metric-sub"><i />{sub}</div></div>;
}

function PacketTable({ rows, empty = "No captured packet records." }: { rows: Packet[]; empty?: string }) {
  return <div className="table-wrap"><table><thead><tr><th>ID</th><th>Time</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Length</th><th>Interface</th></tr></thead><tbody>{rows.length ? rows.map((packet) => <tr key={packet.id}><td className="id-cell">{packet.id}</td><td className="time-cell">{packet.time}</td><td><span className={`proto-tag proto-${packet.protocol.toLowerCase()}`}>{packet.protocol}</span></td><td className="ip">{packet.source}</td><td className="ip">{packet.destination}</td><td className="length">{packet.length} B</td><td className="info">{packet.info}</td></tr>) : <tr><td colSpan={7} className="empty">{empty}</td></tr>}</tbody></table></div>;
}

function AlertPreview({ alerts, onOpen }: { alerts: Alert[]; onOpen: () => void }) {
  return <div className="card alert-preview"><div className="section-head"><div><h2>Recent signals</h2><p>Heuristic indicators from real captures</p></div><button className="link-button" onClick={onOpen}>Review all <span>→</span></button></div><AlertList alerts={alerts.slice(0, 4)} empty="No suspicious activity indicators have fired." /></div>;
}

function AlertTable({ alerts }: { alerts: Alert[] }) {
  return <div className="alert-table"><AlertList alerts={alerts} empty="No alerts yet. Start a real capture to monitor observed traffic." /></div>;
}

function AlertList({ alerts, empty }: { alerts: Alert[]; empty: string }) {
  return alerts.length ? <div className="alert-list">{alerts.map((alert) => <article className="alert-row" key={alert.id}><span className={`alert-mark ${alert.severity.toLowerCase()}`}><AlertTriangle size={16} /></span><div className="alert-copy"><div className="alert-title"><strong>{alert.message}</strong><span>{alert.severity}</span></div><p>{alert.rule_id.replaceAll("-", " ")} · session {alert.session_id.slice(0, 8)}</p><small>{formatDate(alert.time)}</small></div></article>)}</div> : <div className="empty alert-empty"><AlertTriangle size={20} /><span>{empty}</span></div>;
}

function Setting({ icon, title, value, status }: { icon: React.ReactNode; title: string; value: string; status: string }) {
  return <div className="setting-row"><div className="setting-icon">{icon}</div><div><strong>{title}</strong><p>{value}</p></div><span>{status}</span></div>;
}
