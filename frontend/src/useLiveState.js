import { useState, useEffect, useRef } from "react";
import { api } from "./api.js";
import { AGENTS } from "./constants.js";

/* ── small utils ─────────────────────────────────────────── */
const prefersReduced = () =>
  typeof window !== "undefined" && window.matchMedia &&
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function clampPct(p) {
  if (p == null || isNaN(p)) return null;
  let v = Number(p);
  if (v <= 1) v *= 100;
  return Math.max(0, Math.min(100, Math.round(v)));
}
function cadence(sec) {
  if (!sec) return "manual";
  const h = sec / 3600;
  if (h >= 1) return `${Math.round(h)}h cadence`;
  return `${Math.round(sec / 60)}m cadence`;
}
function fmtTs(l) {
  const raw = l.ts ?? l.time ?? l.timestamp ?? l.t;
  if (raw == null) return new Date().toTimeString().slice(0, 8);
  if (typeof raw === "number") {
    const d = new Date(raw > 1e12 ? raw : raw * 1000);
    return d.toTimeString().slice(0, 8);
  }
  const s = String(raw);
  const m = s.match(/(\d{2}:\d{2}:\d{2})/);
  if (m) return m[1];
  const d = new Date(s);
  return isNaN(d.getTime()) ? s.slice(0, 8) : d.toTimeString().slice(0, 8);
}
function lvlClass(level) {
  const s = String(level || "").toUpperCase();
  if (s.startsWith("WARN")) return "warn";
  if (s.startsWith("ERR") || s === "CRITICAL") return "err";
  if (s === "SUCCESS" || s === "OK") return "ok";
  return "";
}
function toolStat(st) {
  if (st == null) return { label: "ready", state: "ok" };
  if (typeof st === "string") return { label: st, state: /run|busy|active/i.test(st) ? "proc" : "ok" };
  if (typeof st === "object") {
    const active = st.active ?? st.running ?? st.in_flight ?? st.inflight ?? 0;
    const max = st.max ?? st.limit ?? st.capacity;
    if (active > 0) return { label: `running ${active}${max ? "/" + max : ""}`, state: "proc" };
    if (st.healthy === false || st.ok === false || st.available === false) return { label: "down", state: "idle" };
    return { label: "ready", state: "ok" };
  }
  return { label: String(st), state: "ok" };
}
const byName = Object.fromEntries(AGENTS.map((a) => [a.name, a]));
function mapAgentState(s) {
  const v = String(s || "idle").toLowerCase();
  if (v === "completed" || v === "complete" || v === "done") return "done";
  if (v === "running" || v === "active") return "running";
  if (v === "error" || v === "failed") return "error";
  return "pending";
}

/* ── kill-chain rail ─────────────────────────────────────── */
const RAIL_LABELS = ["Target", "Scope", "Passive", "Active", "Map", "Test", "Evidence", "Report"];
function railFrom(doneCount) {
  const dc = Math.max(0, Math.min(RAIL_LABELS.length, doneCount));
  return RAIL_LABELS.map((label, i) => ({
    label,
    state: i < dc ? "done" : i === dc ? "current" : "todo",
  }));
}

/* ── seed (sim baseline; shown before probe + when no backend) ── */
function seedView() {
  return {
    live: false,
    target: "example.com",
    program: "intigriti · example-program",
    scopeValidated: true,
    mode: "ACTIVE",
    phaseLabel: "passive recon",
    rail: railFrom(3),
    stats: { hosts: 128, urls: 4219, js: 83, params: 612, vulns: 27, findings: 3 },
    deltas: { hosts: 0, urls: 0, js: 0, params: 0, vulns: 0 },
    agents: AGENTS.map((a, i) => ({ ...a, state: i < 2 ? "done" : i === 2 ? "running" : "pending", cost: i < 2 ? 0.018 * (i + 1) : 0 })),
    agentMeta: { stage: 2, total: 6, totalCost: 0.036, costCap: 0.25, backend: "claude" },
    jobs: {
      running: [{ dom: "example.com", phase: "passive", step: 7, total: 12, pct: 58 }],
      queued: [
        { dom: "api.example.com", phase: "passive" },
        { dom: "staging.example.com", phase: "passive" },
      ],
      completed: [{ dom: "cdn.example.com", phase: "full chain", total: 19 }],
    },
    jobCounts: { running: 1, queued: 2, max: 5 },
    resources: {
      cpu: 34, mem: 58, disk: 41,
      cpuH: Array.from({ length: 40 }, () => 30 + Math.random() * 25),
      memH: Array.from({ length: 40 }, () => 50 + Math.random() * 15),
      diskH: Array.from({ length: 40 }, (_, i) => 38 + i * 0.08),
    },
    monitors: [
      { dom: "example.com", cadence: "4h cadence", state: "ok" },
      { dom: "acme.io", cadence: "12h cadence", state: "ok" },
      { dom: "wildcard.dev", cadence: "new assets · 1h", state: "q" },
    ],
    tools: [
      { name: "subfinder", status: "ready", state: "ok" },
      { name: "httpx", status: "running 2", state: "proc" },
      { name: "nuclei", status: "ready", state: "ok" },
      { name: "katana", status: "running 1", state: "proc" },
      { name: "dalfox", status: "ready", state: "ok" },
      { name: "gowitness", status: "ready", state: "ok" },
    ],
    surface: [
      { d: 0, host: "example.com" },
      { d: 1, host: "api.example.com", int: "params: 41" },
      { d: 2, path: "/v1/auth" },
      { d: 2, path: "/v1/users", flag: "200" },
      { d: 1, host: "admin.example.com", flag: "login" },
      { d: 1, host: "static.example.com" },
      { d: 2, path: "app.bundle.js", int: "3 secrets?" },
    ],
    log: [
      { t: "12:04:22", s: "scope_guard", m: "target validated · example.com", k: "ok" },
      { t: "12:05:11", s: "subfinder", m: "passive enumeration · 128 subdomains", k: "" },
      { t: "12:06:38", s: "httpx", m: "probing live hosts", k: "pp" },
    ],
  };
}

const SIM_PHASES = ["passive", "resolve", "httpx", "katana", "screenshot", "nuclei"];
const SIM_LOG = [
  { s: "httpx", m: "200 · api.example.com/v1/users", k: "pp" },
  { s: "nuclei", m: "info · tech-detect matched", k: "" },
  { s: "katana", m: "crawled app.bundle.js · 41 links", k: "" },
  { s: "analyst", m: "finding promoted · CORS misconfig", k: "warn" },
  { s: "gowitness", m: "captured 12 screenshots", k: "ok" },
  { s: "subfinder", m: "resolved 4 new hosts", k: "" },
];

function simTick(v, cycle) {
  const d = {
    hosts: Math.random() < 0.3 ? 1 : 0,
    urls: Math.floor(Math.random() * 7),
    js: Math.random() < 0.25 ? 1 : 0,
    params: Math.floor(Math.random() * 4),
    vulns: Math.random() < 0.12 ? 1 : 0,
  };
  const stats = {
    hosts: v.stats.hosts + d.hosts, urls: v.stats.urls + d.urls, js: v.stats.js + d.js,
    params: v.stats.params + d.params, vulns: v.stats.vulns + d.vulns,
    findings: v.stats.findings + (Math.random() < 0.05 ? 1 : 0),
  };
  const cpu = Math.max(8, Math.min(96, v.resources.cpu + (Math.random() - 0.5) * 22));
  const mem = Math.max(30, Math.min(90, v.resources.mem + (Math.random() - 0.5) * 8));
  const disk = Math.min(95, v.resources.disk + 0.05);
  const resources = {
    cpu, mem, disk,
    cpuH: [...v.resources.cpuH.slice(1), cpu],
    memH: [...v.resources.memH.slice(1), mem],
    diskH: [...v.resources.diskH.slice(1), disk],
  };
  let step = v.jobs.running[0].step + 1;
  let stage = v.agentMeta.stage;
  if (step > v.jobs.running[0].total) { step = 1; stage = stage >= 5 ? 5 : stage + 1; }
  const pct = Math.round((step / v.jobs.running[0].total) * 100);
  const phase = SIM_PHASES[stage % SIM_PHASES.length];
  const agents = AGENTS.map((a, i) => ({
    ...a, state: i < stage ? "done" : i === stage ? "running" : "pending",
    cost: i < stage ? 0.018 * (i + 1) : 0,
  }));
  const totalCost = +(stage * 0.018 + (step / v.jobs.running[0].total) * 0.014).toFixed(3);
  const pick = cycle % 2 === 0
    ? { s: phase, m: `discovered ${Math.floor(Math.random() * 6) + 1} new endpoints`, k: "" }
    : SIM_LOG[cycle % SIM_LOG.length];
  const log = [...v.log.slice(-70), { t: new Date().toTimeString().slice(0, 8), ...pick }];
  return {
    ...v, live: false, phaseLabel: `${phase} recon`,
    stats, deltas: d, resources, agents, log,
    agentMeta: { ...v.agentMeta, stage, totalCost },
    jobs: { ...v.jobs, running: [{ ...v.jobs.running[0], phase, step, pct }] },
    rail: railFrom(Math.min(2 + stage, 7)),
  };
}

/* ── live merge (real /api/state → view) ─────────────────── */
function mergeLive(v, s, agent, logs, scope, tgt) {
  try {
    const st = s.stats || {};
    const stats = {
      hosts: st.total_subdomains ?? null, urls: null, js: null, params: null,
      vulns: null, findings: st.total_findings ?? null,
    };
    const mapJob = (j) => ({
      dom: j.domain || j.target || "—",
      phase: j.current_step || j.phase || "—",
      total: j.steps_total || 0,
      step: j.steps_done ?? j.step ?? null,
      pct: j.progress != null ? clampPct(j.progress)
        : (j.steps_done != null && j.steps_total ? Math.round((j.steps_done / j.steps_total) * 100) : null),
    });
    const running = (s.running_jobs || []).map(mapJob);
    const queued = (s.queued_jobs || []).map(mapJob);
    const completed = (s.completed_jobs || []).map((j) => ({
      dom: j.domain || j.target || "—", phase: j.current_step || j.phase || "full chain", total: j.steps_total || 0,
    }));
    const r = s.resources || {};
    const resources = {
      cpu: r.cpu || 0, mem: r.memory || 0, disk: r.disk || 0,
      cpuH: r.cpu_history?.length ? r.cpu_history : [r.cpu || 0],
      memH: r.mem_history?.length ? r.mem_history : [r.memory || 0],
      diskH: r.disk_history?.length ? r.disk_history : [r.disk || 0],
    };
    const monitors = (s.schedule || []).map((m) => ({
      dom: m.domain || "—", cadence: cadence(m.interval_seconds),
      state: m.enabled === false ? "idle" : "ok",
    }));
    const tools = Object.entries(s.workers || {}).map(([name, w]) => {
      const t = toolStat(w);
      return { name, status: t.label, state: t.state };
    });
    let agents, agentMeta;
    if (agent && Array.isArray(agent.chain) && agent.chain.length) {
      agents = agent.chain.map((c) => {
        const base = byName[c.name] || { name: c.name, label: c.label || c.name, icon: AGENTS[0].icon, desc: c.desc || "" };
        return { ...base, state: mapAgentState(c.status), cost: c.cost || 0, error: c.error };
      });
      const stage = Math.max(0, agents.findIndex((a) => a.state === "running"));
      agentMeta = {
        stage: stage < 0 ? agents.filter((a) => a.state === "done").length : stage,
        total: agents.length, totalCost: agent.total_cost || 0,
        costCap: agent.cost_cap || 0.25, backend: agent.backend || "api",
      };
    } else {
      agents = AGENTS.map((a) => ({ ...a, state: "pending", cost: 0 }));
      agentMeta = { stage: 0, total: AGENTS.length, totalCost: 0, costCap: agent?.cost_cap || 0.25, backend: agent?.backend || "api" };
    }
    // /api/scope returns {program: <obj|null>, active_program, program_slug}.
    const prog = scope && scope.program;
    const scopeValidated = !!prog || !!(agent && agent.scope_active);
    const program = (prog && (prog.name || prog.workspace)) || scope?.program_slug
      || (s.schedule?.[0]?.program_slug) || "—";
    const mode = running.length ? "ACTIVE" : "PASSIVE";
    const log = (logs || []).slice(-80).map((l) => ({
      t: fmtTs(l), s: l.src || "", m: l.msg || l.message || "", k: lvlClass(l.level),
    }));
    return {
      ...v, live: true, target: tgt || "—", program, scopeValidated, mode,
      phaseLabel: running[0]?.phase ? `${running[0].phase}` : "idle",
      rail: railFrom(scopeValidated ? (running.length ? 3 : 2) : 1),
      stats, deltas: { hosts: 0, urls: 0, js: 0, params: 0, vulns: 0 },
      agents, agentMeta,
      jobs: { running, queued, completed },
      jobCounts: { running: st.running_count ?? running.length, queued: st.queued_count ?? queued.length, max: s.max_jobs || 5 },
      resources, monitors, tools,
      log: log.length ? log : v.log,
    };
  } catch (e) {
    return { ...v, live: true };
  }
}

/* ── the hook ────────────────────────────────────────────── */
export function useLiveState() {
  const [view, setView] = useState(seedView);
  const cycle = useRef(0);

  useEffect(() => {
    let alive = true;
    let timer = null;

    async function pollLive() {
      try {
        const s = await api.state();
        const running = s.running_jobs || [];
        let scope = null;
        try { scope = await api.scope(); } catch (_) {}
        // Target precedence: a live job's domain, else the active program's
        // workspace/name so the engagement persists across reloads with no job.
        const tgt = (running[0] && running[0].domain)
          || scope?.program?.workspace || scope?.program?.name
          || scope?.target || scope?.domain || null;
        let agent = null, logs = null;
        try { agent = await api.agentState(tgt || ""); } catch (_) {}
        try { logs = await api.logs(); } catch (_) {}
        if (!alive) return;
        setView((v) => mergeLive(v, s, agent, logs, scope, tgt));
        timer = setTimeout(pollLive, 3000);
      } catch (e) {
        if (!alive) return;
        startSim();
      }
    }

    function startSim() {
      setView((v) => ({ ...v, live: false }));
      if (prefersReduced()) return; // freeze on the seed
      timer = setInterval(() => {
        cycle.current += 1;
        setView((v) => simTick(v, cycle.current));
      }, 1400);
    }

    pollLive();
    return () => { alive = false; if (timer) { clearTimeout(timer); clearInterval(timer); } };
  }, []);

  return view;
}
