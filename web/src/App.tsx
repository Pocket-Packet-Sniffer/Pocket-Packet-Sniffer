import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Activity, ArrowDownToLine, ArrowRight, ArrowUpRight, Bell, Check, ChevronDown, CircleHelp, FileText, Filter, Gauge, HardDrive, LayoutDashboard, Menu, Network, Play, Radio, Search, Settings, ShieldCheck, Square, Wifi, X } from "lucide-react";

type Packet = { id: number; time: string; protocol: string; source: string; destination: string; length: number; info: string };
const seed: Packet[] = [
  { id: 12487, time: "14:32:08.482", protocol: "TCP", source: "192.168.1.24", destination: "142.250.72.14", length: 1420, info: "443 → 52184 [ACK]" },
  { id: 12486, time: "14:32:08.476", protocol: "TLS", source: "192.168.1.24", destination: "142.250.72.14", length: 892, info: "Application Data" },
  { id: 12485, time: "14:32:08.441", protocol: "DNS", source: "192.168.1.1", destination: "192.168.1.24", length: 118, info: "Standard query response" },
  { id: 12484, time: "14:32:08.438", protocol: "DNS", source: "192.168.1.24", destination: "192.168.1.1", length: 74, info: "A api.github.com" },
  { id: 12483, time: "14:32:08.391", protocol: "TCP", source: "140.82.112.5", destination: "192.168.1.24", length: 1514, info: "443 → 52184 [PSH, ACK]" },
  { id: 12482, time: "14:32:08.365", protocol: "UDP", source: "192.168.1.24", destination: "192.168.1.1", length: 238, info: "5353 → 5353" },
  { id: 12481, time: "14:32:08.334", protocol: "TCP", source: "192.168.1.24", destination: "13.107.42.14", length: 648, info: "443 → 52201 [ACK]" },
  { id: 12480, time: "14:32:08.302", protocol: "TLS", source: "13.107.42.14", destination: "192.168.1.24", length: 1248, info: "Application Data" },
  { id: 12479, time: "14:32:08.275", protocol: "ARP", source: "192.168.1.1", destination: "192.168.1.24", length: 60, info: "Who has 192.168.1.24?" },
  { id: 12478, time: "14:32:08.244", protocol: "TCP", source: "192.168.1.24", destination: "142.250.72.14", length: 74, info: "52184 → 443 [ACK]" }
];
const protocols = [{ n: "TCP", p: 48, count: "5,994", c: "mint" }, { n: "TLS", p: 25, count: "3,122", c: "blue" }, { n: "DNS", p: 14, count: "1,748", c: "purple" }, { n: "UDP", p: 8, count: "999", c: "orange" }, { n: "Other", p: 5, count: "624", c: "gray" }];
const talkers = [{ ip: "192.168.1.24", note: "This device", count: "4,281", p: 86 }, { ip: "142.250.72.14", note: "Remote host", count: "2,106", p: 62 }, { ip: "192.168.1.1", note: "Local gateway", count: "1,548", p: 48 }, { ip: "13.107.42.14", note: "Remote host", count: "936", p: 34 }];
const navigation = [{ label: "Overview", icon: LayoutDashboard }, { label: "Packets", icon: Activity }, { label: "Reports", icon: FileText }, { label: "Settings", icon: Settings }];

function exportCsv(rows: Packet[]) {
  const lines = [["No.", "Time", "Protocol", "Source", "Destination", "Length", "Info"], ...rows.map(p => [p.id, p.time, p.protocol, p.source, p.destination, p.length, p.info])];
  const csv = lines.map(row => row.map(v => '"' + String(v).replace(/"/g, '""') + '"').join(",")).join("\r\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const a = document.createElement("a"); a.href = url; a.download = "pocket-packet-sniffer-preview.csv"; a.click(); URL.revokeObjectURL(url);
}

export default function App() {
  const [page, setPage] = useState("Overview");
  const [mode, setMode] = useState("interface");
  const [iface, setIface] = useState("Wi-Fi");
  const [running, setRunning] = useState(false);
  const [rows, setRows] = useState(seed);
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("All protocols");
  const [menu, setMenu] = useState(false);
  const [toast, setToast] = useState("");

  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => setRows(current => {
      const id = Math.max(...current.map(p => p.id)) + 1;
      const proto = id % 7 === 0 ? "DNS" : id % 5 === 0 ? "UDP" : id % 4 === 0 ? "TLS" : "TCP";
      const now = new Date();
      const next: Packet = { id, time: now.toLocaleTimeString("en-GB", { hour12: false }) + "." + String(now.getMilliseconds()).padStart(3, "0"), protocol: proto, source: id % 3 ? "192.168.1.24" : "192.168.1.1", destination: id % 2 ? "142.250.72.14" : "13.107.42.14", length: [74, 238, 648, 892, 1420][id % 5], info: proto === "DNS" ? "A sample.local" : proto === "UDP" ? "5353 → 5353" : proto === "TLS" ? "Application Data" : "443 → 52184 [ACK]" };
      return [next, ...current].slice(0, 40);
    }), 1400);
    return () => window.clearInterval(timer);
  }, [running]);
  useEffect(() => { if (!toast) return; const timer = window.setTimeout(() => setToast(""), 2800); return () => window.clearTimeout(timer); }, [toast]);

  const filtered = useMemo(() => rows.filter(p => {
    const matches = !query || [p.protocol, p.source, p.destination, p.info, String(p.id)].some(s => s.toLowerCase().includes(query.toLowerCase()));
    return matches && (protocol === "All protocols" || p.protocol === protocol);
  }), [rows, query, protocol]);
  const pageTitle = page === "Overview" ? "Network overview" : page === "Packets" ? "Packet explorer" : page;

  return <div className="app-shell">
    {menu && <button className="scrim" onClick={() => setMenu(false)} aria-label="Close menu" />}
    <aside className={"sidebar " + (menu ? "open" : "")}>
      <div className="brand"><div className="brand-icon"><Network size={21}/></div><div><strong>pocket<span>sniff</span></strong><small>NETWORK OBSERVABILITY</small></div><button className="icon-btn side-close" onClick={() => setMenu(false)} aria-label="Close menu"><X size={17}/></button></div>
      <div className="side-label">WORKSPACE</div><div className="workspace"><div className="work-icon"><ShieldCheck size={17}/></div><div><strong>Local workstation</strong><small>Private environment</small></div><ChevronDown size={15}/></div>
      <nav><div className="nav-caption">MONITOR</div>{navigation.slice(0, 2).map(({ label, icon: Icon }) => <button key={label} className={"nav-item " + (page === label ? "active" : "")} onClick={() => { setPage(label); setMenu(false); }}><Icon size={17}/><span>{label}</span>{label === "Packets" && <small>40</small>}</button>)}<div className="nav-caption manage">MANAGE</div>{navigation.slice(2).map(({ label, icon: Icon }) => <button key={label} className={"nav-item " + (page === label ? "active" : "")} onClick={() => { setPage(label); setMenu(false); }}><Icon size={17}/><span>{label}</span></button>)}</nav>
      <div className="sidebar-bottom"><div className="privacy-card"><ShieldCheck size={17}/><div><strong>Privacy first</strong><small>Designed for local processing.</small></div><Check size={15}/></div><div className="operator"><div className="avatar">VK</div><div><strong>Local operator</strong><small>Personal workspace</small></div><Settings size={17}/></div></div>
    </aside>

    <main className="main">
      <header className="topbar"><button className="icon-btn menu-btn" onClick={() => setMenu(true)} aria-label="Open menu"><Menu size={20}/></button><div className="crumb">Workspace <span>/</span> <strong>{pageTitle}</strong></div><div className="top-actions"><div className="preview-pill"><i/> PREVIEW MODE</div><div className="top-sep"/><button className="icon-btn notification" onClick={() => setToast("No notifications in preview mode.")} aria-label="Notifications"><Bell size={18}/></button><button className="icon-btn" onClick={() => setToast("Synthetic sample data only.")} aria-label="Help"><CircleHelp size={18}/></button></div></header>
      <div className="content">
        <div className="warning"><div className="warning-icon"><Activity size={17}/></div><div><strong>UI preview · synthetic sample data</strong><p>These controls simulate the interface only. No network packets are being captured and the Python backend is not connected.</p></div><span className="offline-tag">BACKEND OFFLINE</span></div>
        <div className="page-heading"><div><div className="eyebrow"><span/> LOCAL NETWORK MONITOR</div><h1>{pageTitle}<em>.</em></h1><p>Understand your network traffic at a glance.</p></div><div className="heading-buttons"><button className="btn secondary" onClick={() => exportCsv(filtered)}><ArrowDownToLine size={16}/> Export sample CSV</button><button className="btn primary" onClick={() => setPage("Packets")}><Search size={16}/> Explore packets <ArrowRight size={15}/></button></div></div>

        {(page === "Overview" || page === "Packets") && <section className="capture card">
          <div className="capture-head"><div className="capture-title"><div className="capture-symbol"><Radio size={19}/></div><div><h2>Capture session</h2><p>Choose a source to preview the capture experience.</p></div></div><span className={"status " + (running ? "running" : "")}><i/>{running ? "Preview running" : "Idle preview"}</span></div>
          <div className="capture-row"><div className="mode-switch"><button className={mode === "interface" ? "selected" : ""} onClick={() => setMode("interface")}><Wifi size={16}/> Live interface</button><button className={mode === "pcap" ? "selected" : ""} onClick={() => setMode("pcap")}><FileText size={16}/> PCAP replay</button></div>{mode === "interface" ? <label className="field"><small>NETWORK INTERFACE</small><div className="select-wrap"><select value={iface} onChange={e => setIface(e.target.value)}><option>Wi-Fi</option><option>Ethernet</option><option>Loopback</option></select><ChevronDown size={15}/></div></label> : <div className="field"><small>PCAP INPUT</small><div className="file-field"><FileText size={15}/> sample-demo.pcap <span>Preview only</span></div></div>}<div className="capture-action">{running ? <button className="btn danger" onClick={() => { setRunning(false); setToast("Preview stopped; no real capture was performed."); }}><Square size={14} fill="currentColor"/> Stop preview</button> : <button className="btn primary" onClick={() => { setRunning(true); setToast(mode === "pcap" ? "Sample replay preview started." : "Simulated stream started."); }}><Play size={14} fill="currentColor"/> {mode === "pcap" ? "Replay preview" : "Start preview"} <ArrowRight size={14}/></button>}<small><ShieldCheck size={13}/> No real capture</small></div></div>
        </section>}

        {page === "Overview" && <>
          <section className="metrics">
            <Metric title="Total packets" value={String(12487 + rows.length - seed.length)} sub="Sample session" icon={<Activity size={17}/>} color="mint"/>
            <Metric title="Data captured" value="8.42 MB" sub="Sample session" icon={<HardDrive size={17}/>} color="blue"/>
            <Metric title="Packet rate" value={running ? "74.2" : "—"} unit={running ? "pkt/s" : "idle"} sub={running ? "Simulated stream" : "Preview stopped"} icon={<Gauge size={17}/>} color="purple"/>
            <Metric title="Active sessions" value={running ? "1" : "0"} sub="This browser preview" icon={<Radio size={17}/>} color="orange"/>
          </section>
          <section className="analytics">
            <div className="card chart-card"><div className="section-head"><div><h2>Traffic overview</h2><p>Packet-rate pattern · sample visualization</p></div><button className="period" onClick={() => setToast("This chart is a fixed synthetic series.")}>Last 60 seconds <ChevronDown size={14}/></button></div><div className="chart-legend"><span><i/> Packets / sec</span><small>SAMPLE SERIES</small></div><div className="chart-area"><div className="y-axis"><span>120</span><span>90</span><span>60</span><span>30</span><span>0</span></div><svg viewBox="0 0 620 190" preserveAspectRatio="none" aria-label="Illustrative packet rate chart"><defs><linearGradient id="fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#53dfb8" stopOpacity=".23"/><stop offset="100%" stopColor="#53dfb8" stopOpacity="0"/></linearGradient></defs><g className="gridlines"><path d="M0 12H620 M0 52H620 M0 92H620 M0 132H620 M0 172H620"/></g><path className="area-path" d="M0 132 L25 120 L50 137 L76 101 L101 110 L126 82 L151 96 L176 68 L201 83 L226 58 L251 77 L276 38 L301 70 L326 84 L351 58 L376 63 L401 33 L426 52 L451 22 L476 58 L501 43 L526 67 L551 48 L576 76 L601 51 L620 57 L620 172H0Z"/><path className="line-path" d="M0 132 L25 120 L50 137 L76 101 L101 110 L126 82 L151 96 L176 68 L201 83 L226 58 L251 77 L276 38 L301 70 L326 84 L351 58 L376 63 L401 33 L426 52 L451 22 L476 58 L501 43 L526 67 L551 48 L576 76 L601 51 L620 57"/><circle cx="451" cy="22" r="4" className="chart-point"/><path className="chart-guide" d="M451 22V172"/></svg></div><div className="x-axis"><span>14:31:10</span><span>14:31:25</span><span>14:31:40</span><span>14:31:55</span><span>14:32:10</span></div><div className="chart-foot"><span><i/> Example data for layout preview</span><span>Not measured from a live interface</span></div></div>
            <div className="card protocol-card"><div className="section-head"><div><h2>Protocol distribution</h2><p>Sample packet classification</p></div><button className="icon-btn" onClick={() => setToast("Protocol distribution is synthetic sample data.")} aria-label="Protocol information"><CircleHelp size={17}/></button></div><div className="protocol-total"><strong>12,487</strong><span>sample packets</span></div><div className="stacked">{protocols.map(p => <i key={p.n} className={p.c} style={{width: p.p + "%"}}/>)}</div><div className="protocol-list">{protocols.map(p => <div className="protocol-row" key={p.n}><i className={p.c}/><span>{p.n}</span><strong>{p.count}</strong><small>{p.p}%</small></div>)}</div><button className="link-button" onClick={() => setPage("Packets")}>Explore packet data <ArrowRight size={14}/></button></div>
          </section>
          <section className="lower">
            <div className="card recent-card"><div className="section-head"><div><h2>Recent packets</h2><p>Latest records in the sample session</p></div><button className="link-button" onClick={() => setPage("Packets")}>View all <ArrowRight size={14}/></button></div><PacketTable rows={rows.slice(0, 5)}/></div>
            <div className="card talker-card"><div className="section-head"><div><h2>Top talkers</h2><p>Sources by sample packet count</p></div><button className="icon-btn" onClick={() => setToast("Talker values are synthetic sample data.")} aria-label="Top talker information"><CircleHelp size={17}/></button></div>{talkers.map((t, i) => <div className="talker" key={t.ip}><span className={"rank " + (!i ? "first" : "")}>{String(i + 1).padStart(2, "0")}</span><div className="talker-info"><strong>{t.ip}</strong><small>{t.note}</small><div className="bar"><i style={{width: t.p + "%"}}/></div></div><b>{t.count}</b></div>)}<div className="talker-foot"><span>Ranked by packets sent</span><span>Sample only</span></div></div>
          </section>
        </>}

        {page === "Packets" && <section className="card explorer"><div className="section-head"><div><h2>Packet explorer</h2><p>Filter synthetic records shown in this preview.</p></div><span className="result-count">{filtered.length} records</span></div><div className="filters"><label className="searchbox"><Search size={16}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search IP, protocol, packet info..."/></label><label className="protocol-select"><Filter size={15}/><select value={protocol} onChange={e => setProtocol(e.target.value)}><option>All protocols</option><option>TCP</option><option>TLS</option><option>DNS</option><option>UDP</option><option>ARP</option></select><ChevronDown size={14}/></label><button className="btn secondary" onClick={() => {setQuery("");setProtocol("All protocols");}}><X size={14}/> Clear</button></div><PacketTable rows={filtered} empty="No sample packets match those filters."/><div className="table-bottom"><span>Sample data only · No packet payloads displayed</span><button className="btn secondary" onClick={() => exportCsv(filtered)}><ArrowDownToLine size={15}/> Export visible rows</button></div></section>}

        {page === "Reports" && <section className="reports"><div className="card report-hero"><div className="report-icon"><FileText size={22}/></div><h2>Session reports</h2><p>Export the visible synthetic records while the real report API is being integrated.</p><button className="btn primary" onClick={() => exportCsv(filtered)}><ArrowDownToLine size={16}/> Download sample CSV</button><small>This file contains preview data, not a real capture session.</small></div><div className="card report-tile"><div className="report-tile-icon"><FileText size={19}/><span>CSV</span></div><h3>Sample capture report</h3><p>{filtered.length} visible records · Generated in browser</p><div className="report-meta">Current preview <span>SYNTHETIC</span></div><button className="link-button" onClick={() => exportCsv(filtered)}>Export report <ArrowRight size={14}/></button></div></section>}

        {page === "Settings" && <section className="card settings"><div className="section-head"><div><h2>Workspace settings</h2><p>Backend settings will be available after local API integration.</p></div><Settings size={19}/></div>{[{icon: <ShieldCheck size={18}/>, title:"Local-only processing", desc:"Design target: keep capture files on your machine.", status:"DESIGN TARGET"},{icon: <Radio size={18}/>, title:"Capture backend", desc:"Not connected in this preview.", status:"OFFLINE"},{icon: <HardDrive size={18}/>, title:"Local storage", desc:"Python implementation stores PCAP and SQLite metadata.", status:"NOT QUERIED"}].map(item => <div className="setting-row" key={item.title}><div className="setting-icon">{item.icon}</div><div><strong>{item.title}</strong><p>{item.desc}</p></div><span>{item.status}</span></div>)}</section>}

        <footer className="footer"><div><Network size={14}/> <strong>POCKET PACKET SNIFFER</strong><span>·</span> Local-first network analysis</div><div><ShieldCheck size={14}/> Privacy by design <span>UI preview build</span></div></footer>
      </div>
    </main>
    {toast && <div className="toast"><Check size={16}/><span>{toast}</span><button onClick={() => setToast("")} aria-label="Dismiss"><X size={15}/></button></div>}
  </div>;
}

function Metric({ title, value, sub, icon, color, unit }: { title:string; value:string; sub:string; icon:ReactNode; color:string; unit?:string }) {
  return <div className="metric card"><div className="metric-head"><span>{title}</span><i className={color}>{icon}</i></div><div className="metric-number">{value}<small>{unit}</small></div><div className="metric-sub"><i/>{sub}</div></div>;
}

function PacketTable({ rows, empty = "No packet records to display." }: { rows:Packet[]; empty?:string }) {
  return <div className="table-wrap"><table><thead><tr><th>No.</th><th>Time</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Length</th><th>Info</th></tr></thead><tbody>{rows.length ? rows.map(p => <tr key={p.id}><td className="id-cell">{p.id}</td><td className="time-cell">{p.time}</td><td><span className={"proto-tag proto-" + p.protocol.toLowerCase()}>{p.protocol}</span></td><td className="ip">{p.source}</td><td className="ip">{p.destination}</td><td className="length">{p.length} B</td><td className="info">{p.info}</td></tr>) : <tr><td colSpan={7} className="empty">{empty}</td></tr>}</tbody></table></div>;
}
