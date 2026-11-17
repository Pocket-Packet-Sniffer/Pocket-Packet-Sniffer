"use client";

import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  Check,
  ChevronDown,
  Clock3,
  Download,
  FileDown,
  FileUp,
  Filter,
  HardDrive,
  HelpCircle,
  LayoutDashboard,
  LockKeyhole,
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
import { useEffect, useMemo, useRef, useState } from "react";
import { BrandLogo } from "./components/BrandLogo";
import { NetworkMap } from "./components/NetworkMap";

type PageName = "Overview" | "Packets" | "Alerts" | "Sessions" | "Settings";
type Packet = {
  id: string | number;
  session_id: string;
  time: string;
  timestamp: number;
  protocol: string;
  source: string;
  destination: string;
  source_mac?: string | null;
  destination_mac?: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  transport?: string | null;
  tcp_flags?: string | null;
  ttl?: number | null;
  length: number;
  original_length?: number;
  info: string;
  interface?: string | null;
  capture_backend?: string | null;
};
type Overview = {
  total_packets: number;
  total_bytes: number;
  active_sessions: number;
  protocols: Record<string, number>;
  top_talkers: [string, number][];
};
type TrafficStatistics = {
  total_packets: number;
  total_bytes: number;
  packets_per_sec: number;
  protocols: [string, number][];
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
const CURRENT_AGENT_VERSION = "0.2.2";
const SUPPORTED_AGENT_VERSIONS = new Set(["0.2.1", CURRENT_AGENT_VERSION]);
type LoopbackPermissionState = "prompt" | "granted" | "denied";
function localFetch(input: RequestInfo | URL, init?: RequestInit) {
  const target = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url, window.location.href);
  const isLoopback = ["127.0.0.1", "localhost", "[::1]"].includes(target.hostname);
  const options = { ...init, ...(isLoopback ? { targetAddressSpace: "loopback" } : {}) } as RequestInit;
  return fetch(input, options);
}
const AGENT_DOWNLOAD = "https://github.com/Pocket-Packet-Sniffer/Pocket-Packet-Sniffer/releases/latest/download/pocket-packet-sniffer-agent-windows.zip";
const EMPTY_OVERVIEW: Overview = {
  total_packets: 0,
  total_bytes: 0,
  active_sessions: 0,
  protocols: {},
  top_talkers: [],
};
const EMPTY_STATISTICS: TrafficStatistics = {
  total_packets: 0,
  total_bytes: 0,
  packets_per_sec: 0,
  protocols: [],
  top_talkers: [],
};
const IDLE_CAPTURE: CaptureStatus = {
  state: "idle",
  session_id: null,
  source: null,
  interface: null,
  started_at: null,
  result: null,
  error: null,
};
const NAV_ITEMS: { label: PageName; icon: typeof LayoutDashboard }[] = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Packets", icon: Activity },
  { label: "Alerts", icon: AlertTriangle },
  { label: "Sessions", icon: Radio },
  { label: "Settings", icon: Settings },
];

function formatDate(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString() : "—";
}

function splitAddresses(value: string) {
  return value
    .split(/[\n,;]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function packetFromApi(packet: Record<string, unknown>): Packet {
  const time = String(packet.time || "");
  return {
    id: packet.id as string | number,
    session_id: String(packet.session_id || ""),
    time: formatDate(time),
    timestamp: Date.parse(time),
    protocol: String(packet.protocol || "OTHER"),
    source: String(packet.source || "—"),
    destination: String(packet.destination || "—"),
    source_mac: (packet.source_mac as string | null) || null,
    destination_mac: (packet.destination_mac as string | null) || null,
    source_port: (packet.source_port as number | null) ?? null,
    destination_port: (packet.destination_port as number | null) ?? null,
    transport: (packet.transport as string | null) || null,
    tcp_flags: (packet.tcp_flags as string | null) || null,
    ttl: (packet.ttl as number | null) ?? null,
    length: Number(packet.length || 0),
    original_length: Number(packet.original_length || packet.length || 0),
    info: String(packet.info || `${packet.protocol || "Packet"} packet`),
    interface: (packet.interface as string | null) || null,
    capture_backend: (packet.capture_backend as string | null) || null,
  };
}

function exportVisibleCsv(rows: Packet[]) {
  const values = [
    ["Time", "Protocol", "Source", "Source port", "Destination", "Destination port", "Size", "Interface", "Session"],
    ...rows.map((packet) => [
      packet.time,
      packet.protocol,
      packet.source,
      packet.source_port ?? "",
      packet.destination,
      packet.destination_port ?? "",
      packet.length,
      packet.interface || "",
      packet.session_id,
    ]),
  ];
  const csv = values
    .map((row) => row.map((value) => `"${String(value).replace(/"/g, '""')}"`).join(","))
    .join("\r\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "pocket-packet-sniffer-visible-packets.csv";
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function App() {
  const [page, setPage] = useState<PageName>("Overview");
  const [rows, setRows] = useState<Packet[]>([]);
  const [packetRows, setPacketRows] = useState<Packet[]>([]);
  const [totalMatches, setTotalMatches] = useState(0);
  const [overview, setOverview] = useState<Overview>(EMPTY_OVERVIEW);
  const [statistics, setStatistics] = useState<TrafficStatistics>(EMPTY_STATISTICS);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [capture, setCapture] = useState<CaptureStatus>(IDLE_CAPTURE);
  const [captureMode, setCaptureMode] = useState<"interface" | "pcap">("interface");
  const [interfaces, setInterfaces] = useState<CaptureInterface[]>([]);
  const [selectedInterfaces, setSelectedInterfaces] = useState<string[]>([]);
  const [interfaceError, setInterfaceError] = useState("");
  const [pcapFile, setPcapFile] = useState<File | null>(null);
  const [bpfFilter, setBpfFilter] = useState("");
  const [knownDevices, setKnownDevices] = useState("");
  const [knownAccessPoints, setKnownAccessPoints] = useState("");
  const [captureBusy, setCaptureBusy] = useState(false);
  const [reportBusy, setReportBusy] = useState("");
  const [online, setOnline] = useState(false);
  const [agentUpdateAvailable, setAgentUpdateAvailable] = useState(false);
  const [loopbackPermission, setLoopbackPermission] = useState<LoopbackPermissionState>("prompt");
  const [connectionRequested, setConnectionRequested] = useState(false);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [addressFilter, setAddressFilter] = useState("");
  const [protocol, setProtocol] = useState("All protocols");
  const [sessionFilter, setSessionFilter] = useState("");
  const [startTime, setStartTime] = useState("");
  const [endTime, setEndTime] = useState("");
  const [pageOffset, setPageOffset] = useState(0);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const [toast, setToast] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const sensorHealthRequest = useRef<Promise<Record<string, unknown>> | null>(null);
  const captureSnapshot = useRef(capture);
  captureSnapshot.current = capture;

  async function checkSensorHealth() {
    if (sensorHealthRequest.current) return sensorHealthRequest.current;
    const request = (async () => {
      const response = await localFetch(`${API}/api/health`, { cache: "no-store", signal: AbortSignal.timeout(8000) });
      const health = await response.json() as Record<string, unknown>;
      if (!response.ok || health.status !== "ok") {
        throw new Error(String(health.detail || "The local sensor is not ready yet."));
      }
      if (!SUPPORTED_AGENT_VERSIONS.has(String(health.version))) {
        throw new Error("Your capture sensor needs an update. Download and open the latest sensor, then reconnect.");
      }
      return health;
    })();
    sensorHealthRequest.current = request;
    try {
      return await request;
    } finally {
      if (sensorHealthRequest.current === request) sensorHealthRequest.current = null;
    }
  }

  useEffect(() => {
    let cancelled = false;
    async function inspectPermission() {
      try {
        const permission = await navigator.permissions.query({ name: "loopback-network" as PermissionName });
        if (cancelled) return;
        setLoopbackPermission(permission.state as LoopbackPermissionState);
        if (permission.state === "granted") setConnectionRequested(true);
        permission.addEventListener("change", () => {
          setLoopbackPermission(permission.state as LoopbackPermissionState);
          if (permission.state === "granted") setConnectionRequested(true);
        });
      } catch {
        // Older browsers do not expose this permission; the explicit Connect action still works.
      }
    }
    void inspectPermission();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    try {
      setKnownDevices(window.localStorage.getItem("pps-known-devices") || "");
      setKnownAccessPoints(window.localStorage.getItem("pps-known-access-points") || "");
    } catch {
      // Storage may be disabled; local-only settings remain editable in memory.
    }
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem("pps-known-devices", knownDevices);
      window.localStorage.setItem("pps-known-access-points", knownAccessPoints);
    } catch {
      // The capture sensor still receives these lists when storage is unavailable.
    }
  }, [knownDevices, knownAccessPoints]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        searchRef.current?.focus();
      }
      if (event.key === "Escape") setMenuOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (!online) return;
    let cancelled = false;
    async function loadInterfaces() {
      try {
        const response = await localFetch(`${API}/api/interfaces`, { cache: "no-store" });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Could not find your network adapters.");
        if (cancelled) return;
        const available = (data.interfaces || []) as CaptureInterface[];
        const candidates = available.filter(
          (item) => item.capture_candidate !== false &&
            !/wan miniport|network monitor|loopback|wi-fi direct/i.test(
              [item.description, item.friendly_name, item.name].join(" "),
            ),
        );
        setInterfaces(candidates);
        const best = candidates.find((item) => item.recommended && item.status === "Up") ||
          candidates.find((item) => item.status === "Up") || candidates[0];
        setSelectedInterfaces((current) =>
          current.length && current.every((name) => candidates.some((item) => item.name === name))
            ? current
            : best ? [best.name] : [],
        );
        setInterfaceError(candidates.length ? "" : "No ready network adapters found. Check Npcap and that Wi-Fi or Ethernet is connected.");
      } catch (cause) {
        if (!cancelled) setInterfaceError(cause instanceof Error ? cause.message : "Could not find your network adapters.");
      }
    }
    void loadInterfaces();
    return () => { cancelled = true; };
  }, [online]);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    let consecutiveFailures = 0;
    async function refresh() {
      if (!connectionRequested) return;
      let needsUpdate = false;
      try {
        const health = await checkSensorHealth();
        if (cancelled) return;
        consecutiveFailures = 0;
        needsUpdate = health.version !== CURRENT_AGENT_VERSION;
        setAgentUpdateAvailable(needsUpdate);
        setOnline(true);
        setError("");
      } catch (cause) {
        if (cancelled) return;
        consecutiveFailures += 1;
        if (consecutiveFailures >= 2) setOnline(false);
        setError(cause instanceof Error ? cause.message : "Open the local sensor to connect this dashboard.");
        timer = window.setTimeout(refresh, 2500);
        return;
      }

      const updateFrom = async (path: string, update: (data: Record<string, any>) => void) => {
        try {
          const response = await localFetch(`${API}${path}`, {
            cache: "no-store",
            signal: AbortSignal.timeout(12000),
          });
          if (!response.ok) return;
          const data = await response.json();
          if (!cancelled) update(data);
        } catch {
          // Keep the last successful values; each panel refreshes independently.
        }
      };
      const liveSessionId = captureSnapshot.current.session_id;
      const packetPath = needsUpdate
        ? liveSessionId ? `/api/packets?limit=250&session_id=${encodeURIComponent(liveSessionId)}` : null
        : "/api/packets?limit=250";
      await Promise.all([
        needsUpdate ? Promise.resolve() : updateFrom("/api/overview", (data) => setOverview(data as unknown as Overview)),
        packetPath ? updateFrom(packetPath, (data) => setRows(((data.packets || []) as Record<string, unknown>[]).map(packetFromApi))) : Promise.resolve(),
        updateFrom("/api/sessions", (data) => setSessions(data as unknown as Session[])),
        updateFrom("/api/alerts?limit=100", (data) => setAlerts((data.alerts || []) as Alert[])),
        updateFrom("/api/statistics", (data) => {
          const snapshot = data as unknown as TrafficStatistics;
          setStatistics(snapshot);
          if (needsUpdate) {
            setOverview({
              total_packets: snapshot.total_packets,
              total_bytes: snapshot.total_bytes,
              active_sessions: snapshot.total_packets ? 1 : 0,
              protocols: Object.fromEntries(snapshot.protocols),
              top_talkers: snapshot.top_talkers,
            });
          }
        }),
      ]);
      if (!cancelled) timer = window.setTimeout(refresh, 2500);
    }
    if (connectionRequested) void refresh();
    return () => { cancelled = true; if (timer !== undefined) window.clearTimeout(timer); };
  }, [connectionRequested]);

  useEffect(() => {
    if (!online) return;
    let cancelled = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const response = await localFetch(`${API}/api/capture/status`, { cache: "no-store", signal: AbortSignal.timeout(8000) });
        if (!response.ok) throw new Error("Capture status request failed.");
        const status = (await response.json()) as CaptureStatus;
        if (!cancelled) setCapture(status);
      } catch {
        // Connection state is presented by the health check.
      }
      if (!cancelled) {
        const active = ["starting", "running", "stopping"].includes(capture.state);
        timer = window.setTimeout(poll, active ? 400 : 1500);
      }
    };
    if (online) void poll();
    return () => { cancelled = true; if (timer !== undefined) window.clearTimeout(timer); };
  }, [capture.state, online]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(""), 4200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  useEffect(() => {
    if (!online) {
      setPacketRows([]);
      setTotalMatches(0);
      return;
    }
    let cancelled = false;
    const params = new URLSearchParams({ limit: "50", offset: String(pageOffset) });
    if (query.trim()) params.set("search", query.trim());
    if (addressFilter.trim()) params.set("address", addressFilter.trim());
    if (protocol !== "All protocols") params.set("protocol", protocol);
    if (sessionFilter) params.set("session_id", sessionFilter);
    if (startTime) params.set("start", new Date(startTime).toISOString());
    if (endTime) params.set("end", new Date(endTime).toISOString());
    void localFetch(`${API}/api/packets?${params.toString()}`, { cache: "no-store" })
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Could not search captured packets.");
        if (!cancelled) {
          setPacketRows((data.packets || []).map(packetFromApi));
          setTotalMatches(Number(data.total || 0));
          setSelectedPacket(null);
        }
      })
      .catch((cause: unknown) => {
        if (!cancelled) setToast(cause instanceof Error ? cause.message : "Could not search captured packets.");
      });
    return () => { cancelled = true; };
  }, [online, query, addressFilter, protocol, sessionFilter, startTime, endTime, pageOffset]);

  const protocolEntries = Object.entries(overview.protocols).sort((left, right) => right[1] - left[1]);
  const maxTalker = Math.max(...overview.top_talkers.map((item) => item[1]), 1);
  const captureActive = ["running", "starting", "stopping"].includes(capture.state);
  const isCapturing = capture.state === "running";
  const title: Record<PageName, string> = {
    Overview: "Your network, at a glance",
    Packets: "Explore packet details",
    Alerts: "Review unusual activity",
    Sessions: "Your saved capture sessions",
    Settings: "Set up your local sensor",
  };
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

  async function connectSensor() {
    setError("Allow this site to access the local network if your browser asks, then keep the sensor running.");
    try {
      const health = await checkSensorHealth();
      setAgentUpdateAvailable(health.version !== CURRENT_AGENT_VERSION);
      setOnline(true);
      setError("");
      setConnectionRequested(true);
    } catch (cause) {
      setOnline(false);
      setError(loopbackPermission === "denied"
        ? "Local network access is blocked. In your browser’s site settings, allow Loopback/Local Network access for this dashboard, then try Connect again."
        : cause instanceof Error && /needs an update/i.test(cause.message)
          ? cause.message
        : cause instanceof Error && cause.name === "TimeoutError"
          ? "The sensor did not respond. Make sure PocketSniff is running on this computer, then connect again."
          : "Could not reach the local sensor. Allow Loopback/Local Network access when prompted and make sure PocketSniff is running.");
    }
  }

  async function startCapture() {
    setCaptureBusy(true);
    setCapture({ ...IDLE_CAPTURE, state: "starting", source: captureMode });
    try {
      let payload: Record<string, unknown>;
      if (captureMode === "pcap") {
        if (!pcapFile) throw new Error("Choose a PCAP file from this computer first.");
        const form = new FormData();
        form.set("file", pcapFile);
        const uploadResponse = await localFetch(`${API}/api/capture/upload`, { method: "POST", body: form, cache: "no-store", signal: AbortSignal.timeout(30000) });
        const uploaded = await uploadResponse.json();
        if (!uploadResponse.ok) throw new Error(uploaded.detail || "That PCAP file could not be opened.");
        payload = { mode: "pcap", upload_id: uploaded.upload_id, delay: 0 };
      } else {
        if (!selectedInterfaces.length) throw new Error("Choose at least one connected adapter.");
        payload = {
          mode: "interface",
          interface: selectedInterfaces[0],
          interfaces: selectedInterfaces,
          bpf_filter: bpfFilter.trim() || null,
          known_devices: splitAddresses(knownDevices),
          known_access_points: splitAddresses(knownAccessPoints),
        };
      }
      const response = await localFetch(`${API}/api/capture/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        cache: "no-store",
        signal: AbortSignal.timeout(15000),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Could not start capture (HTTP ${response.status}).`);
      setCapture(data);
      setToast(captureMode === "pcap" ? "Local PCAP replay started." : "Live packet capture started.");
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
      const response = await localFetch(`${API}/api/capture/stop`, { method: "POST", cache: "no-store", signal: AbortSignal.timeout(15000) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not stop capture.");
      setCapture((current) => ({ ...current, state: data.state || "stopping" }));
      setToast("Stopping safely. The sensor is finishing the current packet.");
    } catch (cause) {
      setToast(cause instanceof Error ? cause.message : "Capture could not stop.");
    } finally {
      setCaptureBusy(false);
    }
  }

  function resetPacketFilters() {
    setQuery("");
    setAddressFilter("");
    setProtocol("All protocols");
    setSessionFilter("");
    setStartTime("");
    setEndTime("");
    setPageOffset(0);
  }

  async function downloadSessionReport(sessionId: string, format: "csv" | "pdf") {
    setReportBusy(`${sessionId}-${format}`);
    try {
      const response = await localFetch(`${API}/api/sessions/${encodeURIComponent(sessionId)}/report?format=${format}`, { cache: "no-store" });
      if (!response.ok) {
        const message = await response.json().catch(() => ({}));
        throw new Error(message.detail || "The session report could not be created.");
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `pocket-packet-sniffer-session.${format}`;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setToast(`${format.toUpperCase()} session summary saved to your downloads.`);
    } catch (cause) {
      setToast(cause instanceof Error ? cause.message : "The session report could not be downloaded.");
    } finally {
      setReportBusy("");
    }
  }

  return (
    <div className="app-shell">
      {menuOpen && <button className="scrim" onClick={() => setMenuOpen(false)} aria-label="Close navigation" />}
      <aside className={`sidebar ${menuOpen ? "open" : ""}`}>
        <div className="brand">
          <BrandLogo className="brand-logo" />
          <div><strong>pocket<span>sniff</span></strong><small>PACKET SNIFFER</small></div>
          <button className="icon-btn side-close" onClick={() => setMenuOpen(false)} aria-label="Close navigation"><X size={17} /></button>
        </div>
        <div className="workspace">
          <span className="work-icon"><ShieldCheck size={17} /></span>
          <div><strong>Private sensor</strong><small>{online ? "On this computer" : "Waiting to connect"}</small></div>
          <span className={`connection-dot ${online ? "connected" : ""}`} aria-label={online ? "Sensor connected" : "Sensor offline"} />
        </div>
        <nav aria-label="Main navigation">
          <div className="nav-caption">YOUR NETWORK</div>
          {NAV_ITEMS.slice(0, 4).map(({ label, icon: Icon }) => (
            <button key={label} className={`nav-item ${page === label ? "active" : ""}`} aria-current={page === label ? "page" : undefined} onClick={() => { setPage(label); setMenuOpen(false); }}>
              <Icon size={17} /><span>{label}</span>
              {label === "Packets" && overview.total_packets > 0 && <small>{overview.total_packets.toLocaleString()}</small>}
              {label === "Alerts" && alerts.length > 0 && <small className="alert-count">{alerts.length}</small>}
            </button>
          ))}
          <div className="nav-caption manage">YOUR SENSOR</div>
          <button className={`nav-item ${page === "Settings" ? "active" : ""}`} aria-current={page === "Settings" ? "page" : undefined} onClick={() => { setPage("Settings"); setMenuOpen(false); }}>
            <Settings size={17} /><span>Setup & privacy</span>
          </button>
        </nav>
        <div className="sidebar-bottom">
          <div className="privacy-card"><LockKeyhole size={17} /><div><strong>Your data stays here</strong><small>Nothing sent to the cloud</small></div><Check size={15} /></div>
          <div className="operator"><span className="avatar" aria-hidden="true">LS</span><div><strong>Local monitor</strong><small>Authorized capture only</small></div></div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <button className="icon-btn menu-btn" onClick={() => setMenuOpen(true)} aria-label="Open navigation"><Menu size={20} /></button>
          <div className="crumb">PocketSniff <span>/</span> <strong>{page}</strong></div>
          <label className="global-search"><Search size={16} /><input ref={searchRef} value={query} onChange={(event) => { setQuery(event.target.value); setPageOffset(0); }} placeholder="Find an address or packet" /><kbd>CTRL K</kbd></label>
          <div className="top-actions"><span className={`connection-pill ${online ? "online" : "offline"}`} role="status"><i />{online ? "SENSOR READY" : "SENSOR OFFLINE"}</span></div>
        </header>

        <div className="content">
          {!online ? (
            <section className="welcome-panel" role="status">
              <div className="welcome-copy">
                <span className="welcome-icon"><BrandLogo size={54} /></span>
                <div><span className="section-kicker">LET’S GET YOU STARTED</span><h2>Your private network view is one minute away.</h2><p>Connect a small sensor on this computer. No account, project setup, or packet upload needed.</p></div>
              </div>
              <div className="setup-steps">
                <div className="setup-step"><span>1</span><div><strong>Download the sensor</strong><small>It runs on your own computer.</small></div><a className="setup-link" href={AGENT_DOWNLOAD} target="_blank" rel="noreferrer" aria-label="Download the Windows capture sensor"><Download size={17} /></a></div>
                <div className="setup-step"><span>2</span><div><strong>Install Npcap on Windows</strong><small>Windows needs this driver to listen to Wi-Fi or Ethernet.</small></div><a className="setup-text-link" href="https://npcap.com/#download" target="_blank" rel="noreferrer">Get Npcap <ArrowRight size={14} /></a></div>
                <div className="setup-step"><span>3</span><div><strong>Open the latest sensor, then this page</strong><small>Keep it running and allow local-network access when asked.</small></div><span className="step-check"><Clock3 size={16} /></span></div>
              </div>
              {error && <div className="inline-error" role="alert">{error}{/update|latest sensor/i.test(error) && <> <a href={AGENT_DOWNLOAD} target="_blank" rel="noreferrer">Download the updated sensor</a></>}</div>}
              <div className="connect-sensor-action"><button className="btn primary" onClick={() => void connectSensor()}><Radio size={16} /> Connect to this computer</button><small>{loopbackPermission === "denied" ? "Allow local network access in your browser’s site settings, then reconnect." : "This will ask your browser to let the dashboard reach its local sensor."}</small></div>
              <p className="welcome-privacy"><LockKeyhole size={15} /> The sensor stays on this PC. Packet data is never sent to this website.</p>
            </section>
          ) : (
            <section className="connected-note" role="status"><span><Check size={16} /></span><div><strong>Your sensor is connected on this computer.</strong><small>Captured packets and reports are stored locally. This dashboard does not upload them.</small>{agentUpdateAvailable && <a className="agent-update-link" href={AGENT_DOWNLOAD} target="_blank" rel="noreferrer">Update sensor for faster packet history <ArrowRight size={13} /></a>}</div><span className="connected-note-local"><i /> LOCAL ONLY</span></section>
          )}
          {online && error && <div className="inline-error" role="alert">{error}</div>}

          <div className="page-heading">
            <div><div className="eyebrow"><span /> {isCapturing ? "WATCHING YOUR NETWORK NOW" : "YOUR PRIVATE NETWORK DASHBOARD"}</div><h1>{title[page]}<em>.</em></h1><p>{page === "Overview" ? "A packet is a tiny message sent between devices. Here you can see where messages go and when something deserves a closer look." : "Real traffic from the sensor on this computer, explained in plain language."}</p></div>
            <div className="heading-buttons">
              {page === "Packets" && <button className="btn secondary" onClick={() => exportVisibleCsv(packetRows)} disabled={!packetRows.length}><ArrowDownToLine size={16} /> Export visible CSV</button>}
              {page === "Packets" && <button className="btn primary" onClick={() => { setPage("Sessions"); setSessionFilter(capture.session_id || ""); }}><FileDown size={16} /> Session reports</button>}
              {page === "Overview" && <button className="btn primary" onClick={() => { document.getElementById("capture-controls")?.scrollIntoView({ behavior: "smooth", block: "center" }); }}><Play size={15} /> Start here</button>}
            </div>
          </div>

          {(page === "Overview" || page === "Packets") && (
            <section className="capture card" id="capture-controls" aria-labelledby="capture-title">
              <div className="capture-head">
                <div className="capture-title"><span className="capture-symbol"><Radio size={20} /></span><div><h2 id="capture-title">Start watching packets</h2><p>Choose where to listen. PocketSniff only observes traffic; it never changes or sends network traffic.</p></div></div>
                <span className={`status ${capture.state}`} role="status"><i />{capture.state === "running" ? "Watching now" : capture.state === "starting" ? "Connecting" : capture.state === "stopping" ? "Stopping safely" : capture.state === "error" ? "Needs attention" : capture.state === "stopped" ? "Stopped" : "Ready"}</span>
              </div>
              <div className="capture-row">
                <div className="mode-switch" role="group" aria-label="Capture source">
                  <button className={captureMode === "interface" ? "selected" : ""} disabled={captureActive || captureBusy} onClick={() => setCaptureMode("interface")}><Wifi size={16} /> Live network</button>
                  <button className={captureMode === "pcap" ? "selected" : ""} disabled={captureActive || captureBusy} onClick={() => setCaptureMode("pcap")}><FileUp size={16} /> Open a capture file</button>
                </div>
                {captureMode === "interface" ? (
                  <div className="adapter-picker">
                    <span className="field-label">WHICH NETWORK SHOULD WE WATCH?</span>
                    <div className="adapter-options" role="group" aria-label="Network adapters">
                      {interfaces.map((item) => (
                        <label key={item.name} className={`adapter-option ${selectedInterfaces.includes(item.name) ? "chosen" : ""}`}>
                          <input type="checkbox" value={item.name} checked={selectedInterfaces.includes(item.name)} disabled={!online || captureActive || captureBusy || item.status !== "Up"} onChange={(event) => {
                            setSelectedInterfaces((current) => event.target.checked ? [...current, item.name] : current.filter((name) => name !== item.name));
                          }} />
                          <Wifi size={17} /><span><strong>{item.friendly_name || item.description || item.name}</strong><small>{item.status === "Up" ? item.ips?.[0] || "Connected adapter" : "Not connected"}{item.recommended ? " · Recommended" : ""}</small></span>
                          {selectedInterfaces.includes(item.name) && <Check size={16} />}
                        </label>
                      ))}
                      {!interfaces.length && <p className="adapter-hint">{interfaceError || "Looking for a connected Wi-Fi or Ethernet adapter…"}</p>}
                    </div>
                    <small className="field-hint">Select one adapter for everyday use. Choose more than one only if you want to combine them in one session.</small>
                    <label className="field bpf-field"><span className="field-label">OPTIONAL: NARROW WHAT YOU WATCH</span><input value={bpfFilter} onChange={(event) => setBpfFilter(event.target.value)} placeholder="Example: tcp port 443" disabled={captureActive || captureBusy} /><small>Leave blank to observe all supported packets. This filter runs locally.</small></label>
                  </div>
                ) : (
                  <div className="pcap-picker">
                    <input ref={fileRef} type="file" accept=".pcap,.cap,application/vnd.tcpdump.pcap" onChange={(event) => setPcapFile(event.target.files?.[0] || null)} disabled={captureActive || captureBusy} aria-label="Choose a classic PCAP file from this computer" />
                    <div className="pcap-dropzone" onClick={() => fileRef.current?.click()} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") fileRef.current?.click(); }} role="button" tabIndex={0}>
                      <span className="pcap-drop-icon"><FileUp size={22} /></span><strong>{pcapFile ? pcapFile.name : "Choose a PCAP file from this computer"}</strong><small>{pcapFile ? `${(pcapFile.size / (1024 * 1024)).toFixed(1)} MB · stays on this computer` : "Classic .pcap or .cap · up to 100 MB · PCAPNG is not supported yet"}</small>
                      <span className="btn secondary">Browse files</span>
                    </div>
                    <p className="field-hint">The selected file is sent only to the sensor running on this same computer, then replayed into your local capture history.</p>
                  </div>
                )}
                <div className="capture-action">
                  {capture.state === "running" || capture.state === "stopping" ? <button className="btn danger" disabled={captureBusy} onClick={() => void stopCapture()}><Square size={14} fill="currentColor" /> Stop watching</button> : <button className="btn primary" disabled={!online || captureBusy || (captureMode === "interface" ? !selectedInterfaces.length : !pcapFile)} onClick={() => void startCapture()}><Play size={14} fill="currentColor" />{captureMode === "pcap" ? "Replay this file" : "Start watching"}</button>}
                  <small><ShieldCheck size={14} /> Passive & local</small>
                </div>
              </div>
              {captureMode === "interface" && selectedInterfaces.length > 1 && <p className="capture-hint">One combined session will watch {selectedInterfaces.length} adapters. Live multi-adapter behavior depends on your drivers.</p>}
              {capture.result && <p className="capture-result">{capture.state === "running" ? "This session so far" : "Last session"}: {capture.result.packets_seen.toLocaleString()} seen · {capture.result.packets_stored.toLocaleString()} understood and saved · {capture.result.packets_ignored.toLocaleString()} unsupported or unreadable</p>}
              {capture.error && <p className="capture-error" role="alert">{capture.error}</p>}
            </section>
          )}

          {page === "Overview" && (
            <>
              <section className="metrics" aria-label="Network summary">
                <Metric title="Packets per second" value={statistics.packets_per_sec.toFixed(1)} sub="Recent live capture speed" icon={<Activity size={18} />} color="purple" explanation="How many packets the sensor has understood in the last few seconds." />
                <Metric title="Packets in this session" value={statistics.total_packets.toLocaleString()} sub="Seen by the local sensor" icon={<Network size={18} />} color="blue" explanation="A packet is one small message sent between devices." />
                <Metric title="Saved traffic" value={`${(overview.total_bytes / 1048576).toFixed(2)} MB`} sub="Stored on this computer" icon={<HardDrive size={18} />} color="teal" explanation="Original packet records stay in your local capture folder." />
                <Metric title="Signals to review" value={alerts.length.toLocaleString()} sub="Rule-based indicators" icon={<AlertTriangle size={18} />} color="amber" explanation="These are prompts to investigate, not proof of an attack." />
              </section>

              <NetworkMap packets={rows} isCapturing={isCapturing && statistics.packets_per_sec > 0} />

              <section className="network-grid">
                <div className="analytics-side">
                  <div className="card protocol-card">
                    <div className="section-head"><div><span className="section-kicker">THE KIND OF MESSAGES</span><h2>What is on the network?</h2><p>Each color represents a different packet protocol.</p></div><span className="help-bubble" title="Protocols are the rules apps use to exchange data." aria-label="Protocols are the rules apps use to exchange data"><HelpCircle size={16} /></span></div>
                    <div className="protocol-total"><strong>{overview.total_packets.toLocaleString()}</strong><span>saved packets, all sessions</span></div>
                    <div className="stacked" role="img" aria-label="Protocol distribution across saved packets">{protocolEntries.map(([name, count], index) => <i key={name} className={`chart-color-${index % 5}`} style={{ width: `${overview.total_packets ? (count / overview.total_packets) * 100 : 0}%` }} />)}</div>
                    <div className="protocol-list">{protocolEntries.map(([name, count], index) => <div className="protocol-row" key={name}><i className={`chart-color-${index % 5}`} /><span>{name}</span><strong>{count.toLocaleString()}</strong><small>{overview.total_packets ? `${((count / overview.total_packets) * 100).toFixed(1)}%` : "0%"}</small></div>)}{!protocolEntries.length && <EmptyNote icon={<Network size={20} />} title="No packet types yet" text="Start watching your network. The protocol mix will appear here." />}</div>
                  </div>
                  <div className="card talker-card"><div className="section-head"><div><span className="section-kicker">MOST ACTIVE ADDRESSES</span><h2>Who is talking most?</h2><p>Addresses that appear most often in saved traffic.</p></div></div>{overview.top_talkers.map(([address, count], index) => <div className="talker" key={address}><span className={`rank ${index === 0 ? "first" : ""}`}>{String(index + 1).padStart(2, "0")}</span><div className="talker-info"><strong>{address}</strong><small>Observed address · {count.toLocaleString()} packets</small><div className="bar"><i style={{ width: `${(count / maxTalker) * 100}%` }} /></div></div></div>)}{!overview.top_talkers.length && <EmptyNote icon={<Radio size={20} />} title="No addresses observed yet" text="When packets arrive, the busiest addresses will be ranked here." />}</div>
                </div>

                <div className="overview-side">
                  <div className="card activity-card"><div className="section-head"><div><span className="section-kicker">REAL CAPTURE RECORDS</span><h2>Traffic activity</h2><p>How the latest saved packets are spread over time.</p></div><span className={`live-sample ${isCapturing ? "is-live" : ""}`}><i />{isCapturing ? "LIVE" : "RECENT"}</span></div><div className="activity-chart" role="img" aria-label={rows.length ? "Counts across recent packet timestamps" : "No captured traffic yet"}><div className="activity-y"><span>MORE</span><span>FEWER</span></div><div className="activity-bars">{activityBins.map((count, index) => <div className="activity-column" key={index} title={`${count} observed packets`}><i style={{ height: `${count ? Math.max(5, (count / maxActivity) * 100) : 2}%` }} /><span>{String(index + 1).padStart(2, "0")}</span></div>)}</div>{!rows.length && <span className="chart-empty-label">No traffic captured yet</span>}</div><div className="activity-foot"><span><i className="legend-dot purple-dot" />Real saved packet timestamps</span><span>No sample data</span></div></div>
                  <div className="card signal-card"><div className="section-head"><div><span className="section-kicker">SENSOR CHECK</span><h2>Is your sensor ready?</h2><p>Simple status for this computer.</p></div><span className={`health-indicator ${isCapturing ? "health-running" : ""}`}><i />{capture.state === "running" ? "Watching" : capture.state === "error" ? "Check setup" : capture.state === "stopped" ? "Stopped" : online ? "Ready" : "Offline"}</span></div><div className="signal-main"><BrandLogo size={48} /><div><strong>{isCapturing ? "Your sensor is watching real traffic" : capture.state === "error" ? "The sensor needs your attention" : online ? "Ready when you are" : "Connect the local sensor"}</strong><p>{capture.interface || "Choose a connected Wi-Fi or Ethernet adapter to begin."}</p></div></div><div className="signal-stats"><div><small>Seen</small><strong>{capture.result?.packets_seen?.toLocaleString() ?? "—"}</strong></div><div><small>Saved</small><strong>{capture.result?.packets_stored?.toLocaleString() ?? "—"}</strong></div><div><small>Not decoded</small><strong>{capture.result?.packets_ignored?.toLocaleString() ?? "—"}</strong></div></div></div>
                </div>
              </section>

              <section className="lower"><div className="card recent-card"><div className="section-head"><div><span className="section-kicker">LATEST ACTIVITY</span><h2>Recent packets</h2><p>Messages observed most recently.</p></div><button className="link-button" onClick={() => setPage("Packets")}>See all packets <ArrowRight size={15} /></button></div><PacketTable rows={rows.slice(0, 7)} onSelect={(packet) => { setSelectedPacket(packet); setPage("Packets"); }} /></div><AlertPreview alerts={alerts} onOpen={() => setPage("Alerts")} /></section>
            </>
          )}

          {page === "Packets" && (
            <section className="card explorer">
              <div className="section-head"><div><span className="section-kicker">SEARCH SAVED TRAFFIC</span><h2>Find a packet</h2><p>Search dates, addresses, protocols, and sessions. Raw message contents are kept private.</p></div><span className="result-count">{totalMatches.toLocaleString()} matches</span></div>
              <div className="filters packet-filters">
                <label className="searchbox"><Search size={16} /><input value={query} onChange={(event) => { setQuery(event.target.value); setPageOffset(0); }} placeholder="Search address, packet ID, or interface" aria-label="Search saved packet metadata" /></label>
                <label className="protocol-select"><Filter size={15} /><select value={protocol} onChange={(event) => { setProtocol(event.target.value); setPageOffset(0); }} aria-label="Filter by protocol"><option>All protocols</option>{Array.from(new Set([...Object.keys(overview.protocols), ...rows.map((packet) => packet.protocol.toUpperCase())])).sort().map((name) => <option key={name}>{name}</option>)}</select><ChevronDown size={14} /></label>
                <label className="protocol-select session-filter"><Radio size={15} /><select value={sessionFilter} onChange={(event) => { setSessionFilter(event.target.value); setPageOffset(0); }} aria-label="Filter by capture session"><option value="">All sessions</option>{sessions.map((session) => <option key={session.session_id} value={session.session_id}>{session.session_id.slice(0, 12)} · {session.packet_count} packets</option>)}</select><ChevronDown size={14} /></label>
                <label className="searchbox address-filter"><Network size={15} /><input value={addressFilter} onChange={(event) => { setAddressFilter(event.target.value); setPageOffset(0); }} placeholder="Exact IP or device address" aria-label="Filter by exact address" /></label>
                <label className="date-filter"><span><Clock3 size={14} /> From</span><input type="datetime-local" value={startTime} onChange={(event) => { setStartTime(event.target.value); setPageOffset(0); }} aria-label="Start time" /></label>
                <label className="date-filter"><span><Clock3 size={14} /> To</span><input type="datetime-local" value={endTime} onChange={(event) => { setEndTime(event.target.value); setPageOffset(0); }} aria-label="End time" /></label>
                <button className="btn secondary clear-filters" onClick={resetPacketFilters}><X size={14} /> Clear filters</button>
              </div>
              <PacketTable rows={packetRows} onSelect={setSelectedPacket} empty={online ? "No saved packets match these filters. Try clearing a filter or start an authorized capture." : "Connect your local sensor to search saved traffic."} />
              <div className="table-bottom"><span>Showing {totalMatches ? pageOffset + 1 : 0}–{Math.min(pageOffset + packetRows.length, totalMatches)} of {totalMatches.toLocaleString()} · packet contents are never shown</span><div className="pagination"><button className="btn secondary" disabled={pageOffset === 0} onClick={() => setPageOffset(Math.max(0, pageOffset - 50))}><ArrowLeft size={14} /> Newer</button><button className="btn secondary" disabled={pageOffset + packetRows.length >= totalMatches} onClick={() => setPageOffset(pageOffset + 50)}>Older <ArrowRight size={14} /></button></div></div>
              {selectedPacket && <PacketDetails packet={selectedPacket} onClose={() => setSelectedPacket(null)} />}
            </section>
          )}

          {page === "Alerts" && <section className="card explorer alerts-page"><div className="section-head"><div><span className="section-kicker">A CLOSER LOOK, WHEN NEEDED</span><h2>Signals worth reviewing</h2><p>Rules look for unusual patterns in packet metadata. You decide what they mean.</p></div><span className="result-count">{alerts.length} signals</span></div><div className="heuristic-note"><ShieldCheck size={18} /><span>A signal is not proof of an attack. No signal does not prove that a network is safe. Packet contents are not inspected.</span></div><AlertTable alerts={alerts} empty={online ? "No review signals yet. If a rule finds an unusual pattern, it will appear here." : "Connect the sensor to review alerts from local captures."} /></section>}

          {page === "Sessions" && <section className="card explorer"><div className="section-head"><div><span className="section-kicker">YOUR PRIVATE HISTORY</span><h2>Saved capture sessions</h2><p>Each session keeps its own packet file and searchable index on this computer.</p></div><span className="result-count">{sessions.length} sessions</span></div><div className="table-wrap"><table><thead><tr><th>Session</th><th>Packets saved</th><th>First observed</th><th>Last observed</th><th>Download summary</th></tr></thead><tbody>{sessions.length ? sessions.map((session) => <tr key={session.session_id}><td className="id-cell">{session.session_id}</td><td>{session.packet_count.toLocaleString()}</td><td>{formatDate(session.first_packet_at)}</td><td>{formatDate(session.last_packet_at)}</td><td><div className="report-buttons"><button className="btn secondary" disabled={!!reportBusy} onClick={() => void downloadSessionReport(session.session_id, "csv")}><FileDown size={14} /> CSV</button><button className="btn secondary" disabled={!!reportBusy} onClick={() => void downloadSessionReport(session.session_id, "pdf")}><FileDown size={14} /> PDF</button></div></td></tr>) : <tr><td colSpan={5} className="empty">No sessions yet. Start watching a network or open a local PCAP file.</td></tr>}</tbody></table></div><p className="table-explainer"><LockKeyhole size={15} /> Reports contain packet metadata only, not raw message contents. They download directly from your local sensor.</p></section>}

          {page === "Settings" && <section className="card settings">
            <div className="section-head"><div><span className="section-kicker">YOUR COMPUTER, YOUR DATA</span><h2>Sensor setup & privacy</h2><p>Clear information about what runs locally and how to make alerts more useful.</p></div><Settings size={20} /></div>
            <div className="settings-grid">
              <div className="settings-card"><span className="setting-icon"><Radio size={19} /></span><div><strong>Local capture sensor</strong><p>{API}</p></div><span className={`setting-status ${online ? "good" : "pending"}`}>{online ? "CONNECTED" : "OFFLINE"}</span></div>
              <div className="settings-card"><span className="setting-icon"><HardDrive size={19} /></span><div><strong>Where your traffic is saved</strong><p>PCAP files and the searchable packet list stay on this computer.</p></div><span className="setting-status good">LOCAL</span></div>
              <div className="settings-card"><span className="setting-icon"><LockKeyhole size={19} /></span><div><strong>What PocketSniff can read</strong><p>It records packet headers for analysis. It does not display packet contents or upload captures.</p></div><span className="setting-status good">PRIVATE</span></div>
              <div className="settings-card"><span className="setting-icon"><ShieldCheck size={19} /></span><div><strong>How unusual activity is detected</strong><p>Metadata rules check for address conflicts, unfamiliar devices, access points, unusual bursts, and destination scans.</p></div><span className="setting-status">REVIEW SIGNALS</span></div>
            </div>
            <div className="allowlist-settings"><div><span className="section-kicker">MAKE DEVICE ALERTS PERSONAL</span><h3>Tell the sensor which devices you recognize</h3><p>Use a device’s MAC address, usually shown on the router label or in its network settings. Unlisted devices may trigger a review signal. This list stays in this browser and is sent only to your local sensor when capture starts.</p></div><div className="allowlist-fields"><label>Known devices (one MAC address per line)<textarea value={knownDevices} onChange={(event) => setKnownDevices(event.target.value)} placeholder="Example: 02:00:00:00:00:01" rows={3} /></label><label>Known Wi-Fi access points (one BSSID per line)<textarea value={knownAccessPoints} onChange={(event) => setKnownAccessPoints(event.target.value)} placeholder="Example: 02:00:00:00:00:02" rows={3} /></label></div></div>
            <div className="agent-download-card"><span className="agent-download-icon"><Download size={20} /></span><div><strong>Set up PocketSniff on another Windows computer</strong><p>Download the ready-to-run sensor. Install Npcap once, open the sensor, then visit this dashboard and allow local-network access.</p></div><a className="btn primary" href={AGENT_DOWNLOAD} target="_blank" rel="noreferrer"><Download size={15} /> Download sensor</a></div>
            <p className="settings-safe-use"><ShieldCheck size={16} /> Only monitor a network or device that you own or have permission to inspect. This tool watches traffic; it never injects, changes, or replays packets onto a network.</p>
          </section>}

          <footer className="footer"><div><BrandLogo size={22} /><strong>POCKET PACKET SNIFFER</strong><span>·</span> Understand the traffic around you</div><div><LockKeyhole size={14} /> Local-only capture <span>Authorized networks only</span></div></footer>
        </div>
      </main>
      {toast && <div className="toast" role="status"><Check size={16} /><span>{toast}</span><button onClick={() => setToast("")} aria-label="Dismiss notification"><X size={15} /></button></div>}
    </div>
  );
}

function Metric({ title, value, sub, icon, color, explanation }: { title: string; value: string; sub: string; icon: React.ReactNode; color: string; explanation: string }) {
  return <article className={`metric card metric-${color}`}><div className="metric-head"><span>{title}</span><span className="metric-icon">{icon}</span></div><div className="metric-number">{value}</div><div className="metric-sub">{sub}</div><p className="metric-explanation">{explanation}</p></article>;
}

function EmptyNote({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) {
  return <div className="empty-note"><span>{icon}</span><strong>{title}</strong><p>{text}</p></div>;
}

function PacketTable({ rows, empty = "No saved packets yet.", onSelect }: { rows: Packet[]; empty?: string; onSelect?: (packet: Packet) => void }) {
  return <div className="table-wrap"><table><thead><tr><th>Time</th><th>Type of message</th><th>Source · port</th><th>Destination · port</th><th>Size</th><th>Network</th></tr></thead><tbody>{rows.length ? rows.map((packet) => <tr key={packet.id} className={onSelect ? "packet-table-row" : ""} onClick={() => onSelect?.(packet)} onKeyDown={(event) => { if (onSelect && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); onSelect(packet); } }} tabIndex={onSelect ? 0 : undefined} aria-label={onSelect ? `Inspect ${packet.protocol} packet from ${packet.source}${packet.source_port ? ` port ${packet.source_port}` : ""} to ${packet.destination}${packet.destination_port ? ` port ${packet.destination_port}` : ""}` : undefined}><td className="time-cell">{packet.time}</td><td><span className={`proto-tag proto-${packet.protocol.toLowerCase()}`}>{packet.protocol}</span></td><td className="ip">{packet.source}{packet.source_port ? <small className="port-label">:{packet.source_port}</small> : null}</td><td className="ip">{packet.destination}{packet.destination_port ? <small className="port-label">:{packet.destination_port}</small> : null}</td><td className="length">{packet.length.toLocaleString()} B</td><td className="info">{packet.interface || packet.capture_backend || "Unknown"}</td></tr>) : <tr><td colSpan={6} className="empty">{empty}</td></tr>}</tbody></table></div>;
}

function PacketDetails({ packet, onClose }: { packet: Packet; onClose: () => void }) {
  const details: [string, string][] = [
    ["Protocol", packet.protocol],
    ["From", packet.source],
    ["To", packet.destination],
    ["Source port", packet.source_port?.toString() || "Not present"],
    ["Destination port", packet.destination_port?.toString() || "Not present"],
    ["Source device", packet.source_mac || "Not present"],
    ["Destination device", packet.destination_mac || "Not present"],
    ["TCP flags", packet.tcp_flags || "Not applicable"],
    ["TTL / hop limit", packet.ttl?.toString() || "Not present"],
    ["Packet size", `${packet.length.toLocaleString()} bytes`],
    ["Network adapter", packet.interface || "Not available"],
    ["Capture session", packet.session_id],
    ["Observed at", packet.time],
  ];
  return <section className="packet-detail-panel" aria-labelledby="packet-detail-title"><div className="packet-detail-heading"><div><span className="section-kicker">PACKET DETAILS</span><h3 id="packet-detail-title">A closer look at one message</h3><p>Header information only. The message contents stay hidden.</p></div><button className="icon-btn" onClick={onClose} aria-label="Close packet details"><X size={18} /></button></div><dl className="packet-detail-grid">{details.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl><div className="detail-private"><LockKeyhole size={15} /> Raw packet contents are never shown in this dashboard.</div></section>;
}

function AlertPreview({ alerts, onOpen }: { alerts: Alert[]; onOpen: () => void }) {
  return <div className="card alert-preview"><div className="section-head"><div><span className="section-kicker">REVIEW SIGNALS</span><h2>Anything unusual?</h2><p>Rule matches to look at more closely.</p></div><button className="link-button" onClick={onOpen}>Review signals <ArrowRight size={14} /></button></div><AlertList alerts={alerts.slice(0, 4)} empty="No review signals. Keep in mind: no signal is not proof a network is safe." /></div>;
}

function AlertList({ alerts, empty }: { alerts: Alert[]; empty: string }) {
  if (!alerts.length) return <EmptyNote icon={<ShieldCheck size={20} />} title="No new signals" text={empty} />;
  return <div className="alert-list">{alerts.map((alert) => <article className="alert-row" key={alert.id}><span className="alert-mark"><AlertTriangle size={17} /></span><div><div className="alert-title"><strong>{alert.message}</strong><span>{alert.severity}</span></div><small>{formatDate(alert.time)} · review signal, not a verdict</small></div></article>)}</div>;
}

function AlertTable({ alerts, empty }: { alerts: Alert[]; empty: string }) {
  return <div className="alert-list">{alerts.length ? alerts.map((alert) => <article className="alert-row" key={alert.id}><span className="alert-mark"><AlertTriangle size={18} /></span><div><div className="alert-title"><strong>{alert.message}</strong><span>{alert.severity}</span></div><small>{alert.rule_id.replaceAll("-", " ")} · {formatDate(alert.time)} · session {alert.session_id.slice(0, 8)}</small><div className="alert-evidence">{Object.entries(alert.evidence || {}).map(([name, value]) => <span key={name}><b>{name.replaceAll("_", " ")}:</b> {value}</span>)}</div></div></article>) : <EmptyNote icon={<ShieldCheck size={20} />} title="No signals to review" text={empty} />}</div>;
}
