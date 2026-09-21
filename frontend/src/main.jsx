import React, {useEffect, useState} from "react";
import {createRoot} from "react-dom/client";
import axios from "axios";
import "./styles.css";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000/api";
const api = axios.create({baseURL: API});

function Severity({value}) { return <span className={`sev ${String(value).toLowerCase()}`}>{value}</span> }

function App() {
  const [stats,setStats]=useState({});
  const [alerts,setAlerts]=useState([]);
  const [analysis,setAnalysis]=useState(null);
  const [loading,setLoading]=useState(false);
  const [message,setMessage]=useState("");

  const refresh=async()=>{
    try {
      const [s,a]=await Promise.all([api.get("/stats"),api.get("/alerts")]);
      setStats(s.data); setAlerts(a.data);
    } catch(e){setMessage("Backend not reachable. Start FastAPI on port 8000.");}
  };
  useEffect(()=>{refresh()},[]);

  const demo=async()=>{
    setLoading(true); setMessage("");
    try { const r=await api.post("/demo/load"); setMessage(`Demo loaded: ${r.data.events_added} events, ${r.data.alerts_created} new alerts.`); await refresh(); }
    catch(e){setMessage("Could not load demo data.");}
    finally{setLoading(false)}
  };

  const analyze=async(id)=>{
    setLoading(true); setAnalysis(null);
    try { const r=await api.post(`/alerts/${id}/analyze`); setAnalysis(r.data); }
    catch(e){setMessage("Analysis failed.");}
    finally{setLoading(false)}
  };

  return <div className="app">
    <aside>
      <div className="brand">🛡️ SOC-X</div>
      <div className="sub">Security Operations Center</div>
      <nav><a className="active">Dashboard</a><a>Alerts</a><a>Investigations</a><a>MITRE ATT&CK</a><a>Threat Intelligence</a><a>Detection Rules</a></nav>
      <div className="side-note">AI assists the analyst. Detection evidence remains the source of truth.</div>
    </aside>
    <main>
      <header><div><h1>SOC Dashboard</h1><p>AI-assisted alert triage and investigation lab</p></div><button onClick={demo} disabled={loading}>⚡ Load Demo Attack</button></header>
      {message && <div className="notice">{message}</div>}
      <section className="cards">
        <Card title="Total Alerts" value={stats.total_alerts||0}/>
        <Card title="Critical" value={stats.critical||0}/>
        <Card title="High" value={stats.high||0}/>
        <Card title="Medium" value={stats.medium||0}/>
        <Card title="Open Incidents" value={stats.open_incidents||0}/>
      </section>
      <section className="grid">
        <div className="panel">
          <div className="panel-head"><h2>Recent Alerts</h2><button className="ghost" onClick={refresh}>Refresh</button></div>
          {alerts.length===0?<div className="empty">No alerts yet. Load the demo attack to generate a SOC investigation.</div>:
          <div className="table-wrap"><table><thead><tr><th>Alert</th><th>Severity</th><th>Score</th><th>MITRE</th><th>Source</th><th></th></tr></thead>
          <tbody>{alerts.map(a=><tr key={a.id}><td><b>{a.title}</b><small>{a.rule}</small></td><td><Severity value={a.severity}/></td><td>{a.score}</td><td>{a.mitre_technique}<small>{a.mitre_name}</small></td><td>{a.source_ip||"—"}</td><td><button className="analyze" onClick={()=>analyze(a.id)}>🤖 Analyze</button></td></tr>)}</tbody></table></div>}
        </div>
        <div className="panel">
          <h2>AI Investigation</h2>
          {!analysis?<div className="empty">Select an alert and click Analyze.</div>:
          <div className="analysis">
            <div className="analysis-top"><Severity value={analysis.severity}/><b>Confidence: {analysis.confidence}</b></div>
            <h3>Summary</h3><p>{analysis.summary}</p>
            <h3>Evidence</h3><ul>{(analysis.evidence||[]).map((x,i)=><li key={i}>{x}</li>)}</ul>
            <h3>MITRE ATT&CK</h3><ul>{(analysis.mitre||[]).map((x,i)=><li key={i}><b>{x.technique}</b> — {x.name}</li>)}</ul>
            <h3>Investigation Questions</h3><ul>{(analysis.investigation_questions||[]).map((x,i)=><li key={i}>{x}</li>)}</ul>
            <h3>Recommended Actions</h3><ul>{(analysis.recommended_actions||[]).map((x,i)=><li key={i}>{x}</li>)}</ul>
          </div>}
        </div>
      </section>
    </main>
  </div>
}
function Card({title,value}){return <div className="card"><span>{title}</span><strong>{value}</strong></div>}
createRoot(document.getElementById("root")).render(<App/>);
