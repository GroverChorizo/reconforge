import React from "react";
import {
  GitBranch, Activity, Cpu, Layers, Bell, Terminal, Globe, FileText, Zap,
  AlertTriangle, CheckCircle2,
} from "lucide-react";
import Sparkline from "./Sparkline.jsx";

const TILE_DEFS = [
  ["Live Hosts", Globe, "hosts", "accent"],
  ["URLs", Layers, "urls", ""],
  ["JS Files", FileText, "js", ""],
  ["Parameters", GitBranch, "params", ""],
  ["Vuln Signals", Zap, "vulns", ""],
  ["Findings", AlertTriangle, "findings", "find"],
];

function Tiles({ view }) {
  const fmt = (n) => (typeof n === "number" ? n.toLocaleString() : "—");
  return (
    <div className="tiles">
      {TILE_DEFS.map(([label, Icon, key, cls]) => {
        const val = view.stats[key];
        const has = typeof val === "number";
        let delta = "no telemetry";
        if (has) {
          if (key === "findings") delta = "drafted";
          else if (view.live) delta = "live";
          else { const d = view.deltas[key] || 0; delta = d > 0 ? `+${d} this cycle` : "·"; }
        }
        return (
          <div key={label} className={`tile ${has ? cls : ""}`}>
            <div className="tl"><Icon /> {label}</div>
            <div className={`num ${has ? "" : "muted"}`}>{fmt(val)}</div>
            <div className={`delta ${delta.startsWith("+") ? "up" : ""}`}>{delta}</div>
          </div>
        );
      })}
    </div>
  );
}

function AgentPipeline({ view }) {
  const { agents, agentMeta } = view;
  const cur = agents[agentMeta.stage] || agents[0] || { label: "—", desc: "" };
  return (
    <div className="panel" style={{ marginBottom: 14 }}>
      <div className="phead">
        <div className="pt"><GitBranch /> Agent Pipeline</div>
        <div className="pmeta">backend: {agentMeta.backend} · cap ${Number(agentMeta.costCap).toFixed(3)} / run</div>
      </div>
      <div className="flow">
        {agents.map((a) => {
          const Icon = a.icon;
          return (
            <div key={a.name} className={`agent ${a.state}`}>
              <span className="conn" />
              <div className="node"><Icon /></div>
              <div className="alabel">{a.label}</div>
              <div className="astate">{a.state === "done" ? "complete" : a.state === "running" ? "running" : a.state === "error" ? "error" : "queued"}</div>
              <div className="acost">{a.state === "done" || a.cost ? `$${Number(a.cost).toFixed(3)}` : a.state === "running" ? "…" : "—"}</div>
            </div>
          );
        })}
      </div>
      <div className="flowfoot">
        <span>stage <b>{Math.min(agentMeta.stage + 1, agentMeta.total)}/{agentMeta.total}</b> · {cur.label}{cur.desc ? ` — ${cur.desc}` : ""}</span>
        <span className="cap">run cost <b>${Number(agentMeta.totalCost).toFixed(3)}</b></span>
      </div>
    </div>
  );
}

function JobQueue({ view }) {
  const { running, queued, completed } = view.jobs;
  const c = view.jobCounts || {};
  const rows = [
    ...running.map((j) => ({ ...j, kind: "run" })),
    ...queued.map((j) => ({ ...j, kind: "q" })),
    ...completed.slice(0, 2).map((j) => ({ ...j, kind: "ok" })),
  ];
  return (
    <div className="panel">
      <div className="phead">
        <div className="pt"><Activity /> Job Queue</div>
        <div className="pmeta">{c.running ?? running.length} running · {c.queued ?? queued.length} queued · max {c.max ?? 5}</div>
      </div>
      <div className="pbody">
        {rows.length === 0 && <div className="empty">No jobs running. Load a target to start recon.</div>}
        {rows.map((j, i) => (
          <div className="job" key={i}>
            <span className="jdom">{j.dom}</span>
            <span className="jphase">{j.phase}</span>
            {j.kind === "run" ? (
              <>
                <span className="bar"><i style={{ width: `${j.pct ?? 0}%` }} /></span>
                <span className="jpct">{j.pct != null ? `${j.step != null ? j.step + "/" + j.total + " · " : ""}${j.pct}%` : "running"}</span>
                <span className="tag run">running</span>
              </>
            ) : j.kind === "q" ? (
              <>
                <span className="bar q"><i style={{ width: "0%" }} /></span>
                <span className="jpct">queued</span><span className="tag q">queued</span>
              </>
            ) : (
              <>
                <span className="bar ok"><i style={{ width: "100%" }} /></span>
                <span className="jpct">{j.total ? `${j.total}/${j.total}` : "done"}</span><span className="tag ok">done</span>
              </>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function ResourcesPanel({ view }) {
  const r = view.resources;
  const rows = [["CPU", r.cpu, r.cpuH, "var(--pp)"], ["Memory", r.mem, r.memH, "var(--ok)"], ["Disk", r.disk, r.diskH, "var(--warn)"]];
  return (
    <div className="panel">
      <div className="phead"><div className="pt"><Cpu /> Host Resources</div><div className="pmeta">local</div></div>
      <div className="pbody">
        <div className="res">
          {rows.map(([k, v, h, c]) => (
            <div className="resrow" key={k}>
              <div className="rtop"><span className="rk">{k}</span><span className="rv">{Math.round(v)}%</span></div>
              <Sparkline data={h} color={c} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function SurfacePanel({ view }) {
  const surf = view.live ? [] : view.surface;
  return (
    <div className="panel">
      <div className="phead"><div className="pt"><Layers /> Attack Surface</div>
        <div className="pmeta">{typeof view.stats.hosts === "number" ? `${view.stats.hosts} hosts` : "—"}</div></div>
      <div className="pbody">
        {surf.length === 0 ? (
          <div className="empty">Map populates after passive + active recon.</div>
        ) : (
          <div className="tree">
            {surf.map((n, i) => (
              <div key={i} style={{ paddingLeft: n.d * 14 }}>
                {n.d > 0 && <span className="t-path">{"└─ "}</span>}
                {n.host ? <span className="t-host">{n.host}</span> : <span className="t-path">{n.path}</span>}
                {n.flag && <span className="t-flag">{n.flag}</span>}
                {n.int && <span className="t-int">{n.int}</span>}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function MonitorsPanel({ view }) {
  return (
    <div className="panel">
      <div className="phead"><div className="pt"><Bell /> Monitors</div><div className="pmeta">adaptive</div></div>
      <div className="pbody">
        {view.monitors.length === 0 && <div className="empty">No monitors enrolled.</div>}
        {view.monitors.map((m) => (
          <div className="mon" key={m.dom}><span className={`mp ${m.state}`} /><span className="mdom">{m.dom}</span><span className="mcad">{m.cadence}</span></div>
        ))}
      </div>
    </div>
  );
}

function ToolHealthPanel({ view }) {
  return (
    <div className="panel">
      <div className="phead"><div className="pt"><Terminal /> Tool Health</div><div className="pmeta">{view.tools.length} wired</div></div>
      <div className="pbody">
        {view.tools.length === 0 && <div className="empty">No tool gates reporting.</div>}
        {view.tools.map((t) => (
          <div className="mon" key={t.name}><span className={`mp ${t.state}`} /><span className="mdom">{t.name}</span><span className="mcad">{t.status}</span></div>
        ))}
      </div>
    </div>
  );
}

export default function Dashboard({ view }) {
  return (
    <main className="ws">
      <div className="ws-head">
        <div className="ws-title">
          <div className="ey">Operations · {view.live ? "Live" : "Offline"}</div>
          <h1>Mission Control</h1>
          <div className="sub">Everything in motion for the active engagement — surface, agents, jobs, and signal.</div>
        </div>
        <div className={`demo-pill ${view.live ? "live" : ""}`}>
          {view.live ? <><CheckCircle2 size={11} /> Live telemetry</> : <>Backend offline · no telemetry</>}
        </div>
      </div>

      <div className="tstrip">
        <div className="tcell"><span className="l">Program</span><span className="val">{view.program}</span></div>
        <div className="tcell"><span className="l">Target</span><span className="val tgt">{view.target || "none"}</span></div>
        <div className="tcell"><span className="l">Scope</span>
          <span className={`scopechip ${view.scopeValidated ? "" : "none"}`}>
            <CheckCircle2 size={13} /> {view.scopeValidated ? "Validated" : "Not set"}
          </span>
        </div>
        <div className="tcell"><span className="l">Mode</span><span className={`risk ${view.mode.toLowerCase()}`}>{view.mode}</span></div>
        <div className="tcell"><span className="l">Vault</span><span className="val">ResearchVault/BugBounty/{view.target || "—"}</span></div>
      </div>

      <Tiles view={view} />
      <AgentPipeline view={view} />

      <div className="row2" style={{ marginBottom: 14 }}>
        <JobQueue view={view} />
        <ResourcesPanel view={view} />
      </div>

      <div className="row3">
        <SurfacePanel view={view} />
        <MonitorsPanel view={view} />
        <ToolHealthPanel view={view} />
      </div>
    </main>
  );
}
