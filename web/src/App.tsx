import { useEffect, useMemo, useState } from "react";
import { Activity, ArrowDownToLine, Check, ChevronDown, Filter, HardDrive, LayoutDashboard, Menu, Network, Play, Radio, Search, Settings, ShieldCheck, Square, Wifi, FileText, X } from "lucide-react";

type Packet = { id:number; session_id:string; time:string; protocol:string; source:string; destination:string; length:number; info:string };
type Overview = { total_packets:number; total_bytes:number; active_sessions:number; protocols:Record<string,number>; top_talkers:[string,number][] };
type Session = { session_id:string; packet_count:number; first_packet_at:string|null; last_packet_at:string|null };
type CaptureStatus = { state:string; session_id:string|null; source:string|null; interface:string|null; started_at:string|null; result:{packets_seen:number;packets_stored:number;packets_ignored:number;exit_code:number|null}|null; error:string|null };
const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";
const nav = [{label:"Overview",icon:LayoutDashboard},{label:"Packets",icon:Activity},{label:"Sessions",icon:Radio},{label:"Settings",icon:Settings}];
const zero:Overview = {total_packets:0,total_bytes:0,active_sessions:0,protocols:{},top_talkers:[]};
const idleCapture:CaptureStatus = {state:"idle",session_id:null,source:null,interface:null,started_at:null,result:null,error:null};

function exportCsv(rows:Packet[]) {
  const csv = [["ID","Time","Session","Protocol","Source","Destination","Length","Info"],...rows.map(p=>[p.id,p.time,p.session_id,p.protocol,p.source,p.destination,p.length,p.info])]
    .map(r=>r.map(v=>'"'+String(v).replace(/"/g,'""')+'"').join(",")).join("\\r\\n");
  const url=URL.createObjectURL(new Blob([csv],{type:"text/csv;charset=utf-8"}));
  const a=document.createElement("a");a.href=url;a.download="pocket-packet-sniffer.csv";a.click();URL.revokeObjectURL(url);
}
const date = (v:string|null) => v ? new Date(v).toLocaleString() : "—";

export default function App() {
  const [page,setPage]=useState("Overview");
  const [rows,setRows]=useState<Packet[]>([]);
  const [overview,setOverview]=useState<Overview>(zero);
  const [sessions,setSessions]=useState<Session[]>([]);
  const [capture,setCapture]=useState<CaptureStatus>(idleCapture);
  const [captureMode,setCaptureMode]=useState("interface");
  const [iface,setIface]=useState("");
  type CaptureInterface = {name:string;description:string;friendly_name?:string;ips:string[];mac:string|null;status?:string};
  const [interfaces,setInterfaces]=useState<CaptureInterface[]>([]);
  const [interfaceError,setInterfaceError]=useState("");
  const [pcapPath,setPcapPath]=useState("");
  const [captureBusy,setCaptureBusy]=useState(false);
  const [online,setOnline]=useState(false);
  const [error,setError]=useState("");
  const [query,setQuery]=useState("");
  const [protocol,setProtocol]=useState("All protocols");
  const [menu,setMenu]=useState(false);
  const [toast,setToast]=useState("");
  useEffect(()=>{
    let cancelled=false;
    async function loadInterfaces(){
      try{
        const response=await fetch(`${API}/api/interfaces`);
        const data=await response.json();
        if(!response.ok)throw new Error(data.detail||"Could not load network interfaces.");
        if(cancelled)return;
        const names=(data.interfaces||[]) as CaptureInterface[];
        setInterfaces(names);
        const isUsable=(item:CaptureInterface)=>item.status==="Up"&&!/loopback|virtual|vmware|virtualbox|hyper-v|wi-fi direct|wan miniport|tap-windows/i.test(item.description+" "+item.name);
        const hasUsableIPv4=(item:CaptureInterface)=>item.ips?.some(ip=>/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)&&!ip.startsWith("127.")&&!ip.startsWith("169.254."));
        const preferred=names.find(item=>isUsable(item)&&hasUsableIPv4(item)&&/wi-?fi|wireless/i.test(item.friendly_name+" "+item.description));
        const active=names.find(item=>isUsable(item)&&hasUsableIPv4(item));
        setIface(current=>names.some(item=>item.name===current)?current:(preferred?.name||active?.name||""));
        setInterfaceError(names.length?"":"No capture interfaces were found. Check Npcap installation.");
      }catch(e){
        if(cancelled)return;
        setInterfaceError(e instanceof Error?e.message:"Could not load network interfaces.");
      }
    }
    void loadInterfaces();
    return()=>{cancelled=true;};
  },[]);
  useEffect(()=>{
    let cancelled=false;
    async function refresh(){
      try{
        const rs=await Promise.all([fetch(`${API}/api/health`),fetch(`${API}/api/overview`),fetch(`${API}/api/packets?limit=500`),fetch(`${API}/api/sessions`),fetch(`${API}/api/capture/status`)]);
        if(rs.some(r=>!r.ok)) throw new Error("API request failed. Check the Python backend terminal.");
        const [health,summary,packetResult,sessionResult,captureResult]=await Promise.all(rs.map(r=>r.json()));
        if(cancelled)return;
        setOnline(health.status==="ok");setOverview(summary);setSessions(sessionResult||[]);setCapture(captureResult||idleCapture);
        setRows((packetResult.packets||[]).map((p:any)=>({id:p.id,session_id:p.session_id||"",time:date(p.time),protocol:p.protocol||"OTHER",source:p.source||"—",destination:p.destination||"—",length:p.length||0,info:p.info||`${p.protocol||"Packet"} packet`})));
        setError("");
      }catch(e){if(cancelled)return;setOnline(false);setError(e instanceof Error?e.message:"Could not reach the backend.");}
    }
    void refresh();const t=window.setInterval(()=>void refresh(),2500);
    return()=>{cancelled=true;window.clearInterval(t);};
  },[]);
  useEffect(()=>{if(!toast)return;const t=window.setTimeout(()=>setToast(""),2800);return()=>window.clearTimeout(t);},[toast]);
  const filtered=useMemo(()=>rows.filter(p=>(!query||[p.protocol,p.source,p.destination,p.info,String(p.id),p.session_id].some(s=>s.toLowerCase().includes(query.toLowerCase())))&&(protocol==="All protocols"||p.protocol.toUpperCase()===protocol)),[rows,query,protocol]);
  const protocols=Object.entries(overview.protocols).sort((a,b)=>b[1]-a[1]);
  const maxTalker=Math.max(...overview.top_talkers.map(x=>x[1]),1);
  const title=page==="Overview"?"Network overview":page==="Packets"?"Packet explorer":page==="Sessions"?"Capture sessions":page;
  return <div className="app-shell">
    {menu&&<button className="scrim" onClick={()=>setMenu(false)} aria-label="Close menu"/>}
    <aside className={"sidebar "+(menu?"open":"")}>
      <div className="brand"><div className="brand-icon"><Network size={21}/></div><div><strong>pocket<span>sniff</span></strong><small>NETWORK OBSERVABILITY</small></div><button className="icon-btn side-close" onClick={()=>setMenu(false)} aria-label="Close menu"><X size={17}/></button></div>
      <div className="side-label">WORKSPACE</div><div className="workspace"><div className="work-icon"><ShieldCheck size={17}/></div><div><strong>Local workstation</strong><small>Private environment</small></div></div>
      <nav><div className="nav-caption">MONITOR</div>{nav.slice(0,3).map(({label,icon:Icon})=><button key={label} className={"nav-item "+(page===label?"active":"")} onClick={()=>{setPage(label);setMenu(false)}}><Icon size={17}/><span>{label}</span>{label==="Packets"&&<small>{rows.length}</small>}</button>)}<div className="nav-caption manage">MANAGE</div>{nav.slice(3).map(({label,icon:Icon})=><button key={label} className={"nav-item "+(page===label?"active":"")} onClick={()=>{setPage(label);setMenu(false)}}><Icon size={17}/><span>{label}</span></button>)}</nav>
      <div className="sidebar-bottom"><div className="privacy-card"><ShieldCheck size={17}/><div><strong>Privacy first</strong><small>Local processing</small></div><Check size={15}/></div><div className="operator"><div className="avatar">VK</div><div><strong>Local operator</strong><small>Personal workspace</small></div></div></div>
    </aside>
    <main className="main">
      <header className="topbar"><button className="icon-btn menu-btn" onClick={()=>setMenu(true)} aria-label="Open menu"><Menu size={20}/></button><div className="crumb">Workspace <span>/</span> <strong>{title}</strong></div><div className="top-actions"><div className="preview-pill"><i/> {online?"BACKEND CONNECTED":"CONNECTING"}</div></div></header>
      <div className="content">
        <div className="warning"><div className="warning-icon"><Activity size={17}/></div><div><strong>{online?"Python backend connected":"Python backend unavailable"}</strong><p>{online?`Auto-refreshing stored data · ${overview.total_packets.toLocaleString()} packets`:error||"Start the API with: python -m uvicorn pocket_packet_sniffer.api:app --reload"}</p></div><span className="offline-tag">{online?"BACKEND ONLINE":"BACKEND OFFLINE"}</span></div>
        <div className="page-heading"><div><div className="eyebrow"><span/> LOCAL NETWORK MONITOR</div><h1>{title}<em>.</em></h1><p>Inspect stored packet metadata and capture sessions.</p></div><div className="heading-buttons"><button className="btn secondary" onClick={()=>exportCsv(filtered)}><ArrowDownToLine size={16}/> Export CSV</button><button className="btn primary" onClick={()=>setPage("Packets")}><Search size={16}/> Explore packets</button></div></div>
        {(page==="Overview"||page==="Packets")&&<section className="capture card">
          <div className="capture-head"><div className="capture-title"><div className="capture-symbol"><Radio size={19}/></div><div><h2>Capture session</h2><p>Start passive capture on an authorized interface or replay a local classic PCAP file.</p></div></div><span className={"status "+(capture.state==="running"?"running":capture.state==="error"?"failed":capture.state==="stopped"?"stopped":"")}><i/>{capture.state==="running"?"Capturing":capture.state==="stopping"?"Stopping":capture.state==="error"?"Capture error":capture.state==="stopped"?"Stopped":"Idle"}</span></div>
          <div className="capture-row">
            <div className="mode-switch"><button className={captureMode==="interface"?"selected":""} disabled={captureBusy||capture.state==="running"||capture.state==="stopping"} onClick={()=>setCaptureMode("interface")}><Wifi size={16}/> Live interface</button><button className={captureMode==="pcap"?"selected":""} disabled={captureBusy||capture.state==="running"||capture.state==="stopping"} onClick={()=>setCaptureMode("pcap")}><FileText size={16}/> PCAP replay</button></div>
            {captureMode==="interface"?<label className="field"><small>INTERFACE NAME (SCAPY)</small><div className="select-wrap"><select value={iface} onChange={e=>setIface(e.target.value)} disabled={captureBusy||capture.state==="running"||capture.state==="stopping"||!interfaces.length}><option value="" disabled>Select a network adapter</option>{interfaces.map(item=><option key={item.name} value={item.name}>{item.friendly_name||item.description}{item.ips?.length?" · "+item.ips.filter(ip=>/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)).join(", "):""} · {item.status||"Unknown"} · {item.name}</option>)}</select></div></label>:<label className="field"><small>LOCAL PCAP FILE PATH</small><div className="select-wrap"><input value={pcapPath} onChange={e=>setPcapPath(e.target.value)} placeholder="C:\\captures\\sample.pcap" disabled={captureBusy||capture.state==="running"||capture.state==="stopping"}/></div></label>}
            <div className="capture-action">{capture.state==="running"||capture.state==="stopping"?<button className="btn danger" disabled={captureBusy||capture.state==="stopping"} onClick={async()=>{setCaptureBusy(true);try{const r=await fetch(`${API}/api/capture/stop`,{method:"POST"});const data=await r.json();if(!r.ok)throw new Error(data.detail||"Could not stop capture");setCapture(data);setToast("Stop requested.");}catch(e){setToast(e instanceof Error?e.message:"Stop failed");}finally{setCaptureBusy(false);}}}><Square size={14} fill="currentColor"/> Stop capture</button>:<button className="btn primary" disabled={captureBusy||!online||(captureMode==="interface"?(!iface.trim()||!interfaces.some(item=>item.name===iface)):!pcapPath.trim())} onClick={async()=>{setCaptureBusy(true);try{const r=await fetch(`${API}/api/capture/start`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(captureMode==="interface"?{mode:"interface",interface:iface.trim()}:{mode:"pcap",pcap_path:pcapPath.trim(),delay:0.01})});const data=await r.json();if(!r.ok)throw new Error(data.detail||"Could not start capture");setCapture(data);setToast(captureMode==="pcap"?"PCAP replay started.":"Capture start requested.");}catch(e){setToast(e instanceof Error?e.message:"Capture failed");}finally{setCaptureBusy(false);}}}><Play size={14} fill="currentColor"/> {captureMode==="pcap"?"Replay PCAP":"Start capture"}</button>}<small><ShieldCheck size={13}/> Passive capture · local only</small></div>
          </div>
          {captureMode==="interface"&&interfaceError&&<p>{interfaceError}</p>}
          {capture.error&&<p role="alert">{capture.error}</p>}
          {capture.state==="running"&&capture.result?.packets_seen===0&&<p>Listening for traffic. Open a website or generate normal network activity; if the count stays at zero, stop capture and choose the adapter with your active IP address.</p>}
          {capture.result&&<p>{capture.state==="running"?"Live progress":"Last session"}: {capture.result.packets_seen} seen · {capture.result.packets_stored} stored · {capture.result.packets_ignored} ignored{capture.result.exit_code!==null?" (exit "+capture.result.exit_code+")":""}</p>}
          {capture.state==="running"&&<p>Session {capture.session_id} · new packets appear as the dashboard refreshes.</p>}
        </section>}
        {page==="Overview"&&<>
          <section className="metrics">
            <Metric title="Total packets" value={overview.total_packets.toLocaleString()} sub="Stored packet records" icon={<Activity size={17}/>} color="mint"/>
            <Metric title="Data captured" value={(overview.total_bytes/1048576).toFixed(2)+" MB"} sub="Stored packet bytes" icon={<HardDrive size={17}/>} color="blue"/>
            <Metric title="Packet rate" value="—" unit="not measured" sub="Not provided by current API" icon={<Radio size={17}/>} color="purple"/>
            <Metric title="Capture sessions" value={String(overview.active_sessions)} sub="Recorded sessions" icon={<Network size={17}/>} color="orange"/>
          </section>
          <section className="analytics">
            <div className="card protocol-card"><div className="section-head"><div><h2>Protocol distribution</h2><p>Classification of stored packets</p></div></div><div className="protocol-total"><strong>{overview.total_packets.toLocaleString()}</strong><span>recorded packets</span></div><div className="stacked">{protocols.map(([n,c],i)=><i key={n} className={["mint","blue","purple","orange","gray"][i%5]} style={{width:(overview.total_packets?c/overview.total_packets*100:0)+"%"}}/>)}</div><div className="protocol-list">{protocols.map(([n,c],i)=><div className="protocol-row" key={n}><i className={["mint","blue","purple","orange","gray"][i%5]}/><span>{n}</span><strong>{c.toLocaleString()}</strong><small>{overview.total_packets?(c/overview.total_packets*100).toFixed(1):0}%</small></div>)}{!protocols.length&&<p>No protocol data yet.</p>}</div></div>
            <div className="card talker-card"><div className="section-head"><div><h2>Top talkers</h2><p>Frequently observed addresses</p></div></div>{overview.top_talkers.map(([ip,count],i)=><div className="talker" key={ip}><span className={"rank "+(!i?"first":"")}>{String(i+1).padStart(2,"0")}</span><div className="talker-info"><strong>{ip}</strong><small>Observed address</small><div className="bar"><i style={{width:(count/maxTalker*100)+"%"}}/></div></div><b>{count.toLocaleString()}</b></div>)}{!overview.top_talkers.length&&<p>No address data yet.</p>}</div>
          </section>
          <section className="card recent-card"><div className="section-head"><div><h2>Recent packets</h2><p>Latest stored records</p></div><button className="link-button" onClick={()=>setPage("Packets")}>View all →</button></div><PacketTable rows={rows.slice(0,8)}/></section>
        </>}
        {page==="Packets"&&<section className="card explorer"><div className="section-head"><div><h2>Packet explorer</h2><p>Search and filter real stored packet records.</p></div><span className="result-count">{filtered.length} records</span></div><div className="filters"><label className="searchbox"><Search size={16}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search IP, protocol, session..."/></label><label className="protocol-select"><Filter size={15}/><select value={protocol} onChange={e=>setProtocol(e.target.value)}><option>All protocols</option>{Array.from(new Set(rows.map(p=>p.protocol.toUpperCase()))).sort().map(p=><option key={p}>{p}</option>)}</select><ChevronDown size={14}/></label><button className="btn secondary" onClick={()=>{setQuery("");setProtocol("All protocols")}}><X size={14}/> Clear</button></div><PacketTable rows={filtered} empty="No stored packets match those filters."/><div className="table-bottom"><span>Metadata only · packet payloads are not displayed</span><button className="btn secondary" onClick={()=>exportCsv(filtered)}><ArrowDownToLine size={15}/> Export rows</button></div></section>}
        {page==="Sessions"&&<section className="card explorer"><div className="section-head"><div><h2>Capture sessions</h2><p>Sessions recorded by the storage layer.</p></div><span className="result-count">{sessions.length} sessions</span></div><div className="table-wrap"><table><thead><tr><th>Session ID</th><th>Packets</th><th>First packet</th><th>Last packet</th></tr></thead><tbody>{sessions.length?sessions.map(s=><tr key={s.session_id}><td className="id-cell">{s.session_id}</td><td>{s.packet_count}</td><td>{date(s.first_packet_at)}</td><td>{date(s.last_packet_at)}</td></tr>):<tr><td colSpan={4} className="empty">No stored sessions yet.</td></tr>}</tbody></table></div></section>}
        {page==="Settings"&&<section className="card settings"><div className="section-head"><div><h2>Connection settings</h2><p>Local API configuration</p></div><Settings size={19}/></div><div className="setting-row"><div className="setting-icon"><Radio size={18}/></div><div><strong>Backend API</strong><p>{API}</p></div><span>{online?"CONNECTED":"OFFLINE"}</span></div><div className="setting-row"><div className="setting-icon"><HardDrive size={18}/></div><div><strong>Storage</strong><p>PCAP files and SQLite metadata on this machine.</p></div><span>LOCAL</span></div></section>}
        <footer className="footer"><div><Network size={14}/> <strong>POCKET PACKET SNIFFER</strong><span>·</span> Local-first network analysis</div><div><ShieldCheck size={14}/> Privacy by design <span>API-connected build</span></div></footer>
      </div>
    </main>
    {toast&&<div className="toast"><Check size={16}/><span>{toast}</span><button onClick={()=>setToast("")} aria-label="Dismiss"><X size={15}/></button></div>}
  </div>;
}
function Metric({title,value,sub,icon,color,unit}:{title:string;value:string;sub:string;icon:React.ReactNode;color:string;unit?:string}){return <div className="metric card"><div className="metric-head"><span>{title}</span><i className={color}>{icon}</i></div><div className="metric-number">{value}<small>{unit}</small></div><div className="metric-sub"><i/>{sub}</div></div>}
function PacketTable({rows,empty="No packet records to display."}:{rows:Packet[];empty?:string}){return <div className="table-wrap"><table><thead><tr><th>No.</th><th>Time</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Length</th><th>Info</th></tr></thead><tbody>{rows.length?rows.map(p=><tr key={p.id}><td className="id-cell">{p.id}</td><td className="time-cell">{p.time}</td><td><span className={"proto-tag proto-"+p.protocol.toLowerCase()}>{p.protocol}</span></td><td className="ip">{p.source}</td><td className="ip">{p.destination}</td><td className="length">{p.length} B</td><td className="info">{p.info}</td></tr>):<tr><td colSpan={7} className="empty">{empty}</td></tr>}</tbody></table></div>}
