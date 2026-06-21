import { useState, useEffect } from "react";
import { api } from "./api.js";
import { AGENTS } from "./constants.js";

/* ── small utils ─────────────────────────────────────────── */
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

/* ── empty baseline ──────────────────────────────────────────
   Honest "nothing yet" state. `connected` is false until /api/state
   answers; the UI renders this as OFFLINE with em-dashes rather than
   inventing a fake engagement. No synthetic data — ever. */
function emptyView(connected = false, authed = null) {
  return {
    live: false,
    connected,
    // null = unknown (still connecting), true = signed in, false = needs login.
    authed,
    user: null,
    target: null,
    program: "—",
    scopeValidated: false,
    mode: "PASSIVE",
    phaseLabel: connected ? "idle" : "offline",
    rail: railFrom(0),
    stats: { hosts: null, urls: null, js: null, params: null, vulns: null, findings: null },
    deltas: { hosts: 0, urls: 0, js: 0, params: 0, vulns: 0 },
    agents: AGENTS.map((a) => ({ ...a, state: "pending", cost: 0 })),
    agentMeta: { stage: 0, total: AGENTS.length, totalCost: 0, costCap: 0.25, backend: "—" },
    jobs: { running: [], queued: [], completed: [] },
    jobCounts: { running: 0, queued: 0, max: 5 },
    resources: { cpu: 0, mem: 0, disk: 0, cpuH: [], memH: [], diskH: [] },
    monitors: [],
    tools: [],
    surface: [],
    session: [],
    log: [],
  };
}

/* ── live merge (real /api/state → view) ─────────────────── */
function mergeLive(v, s, agent, logs, scope, tgt, session) {
  try {
    const st = s.stats || {};
    const stats = {
      hosts: st.total_subdomains ?? null,
      urls: st.total_urls ?? null,
      js: st.total_js ?? null,
      params: st.total_params ?? null,
      vulns: st.total_vuln_signals ?? null,
      findings: st.total_findings ?? null,
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
      ...v, live: true, connected: true, authed: true, user: s.session || v.user || null,
      target: tgt || "—", program, scopeValidated, mode,
      phaseLabel: running[0]?.phase ? `${running[0].phase}` : "idle",
      rail: railFrom(scopeValidated ? (running.length ? 3 : 2) : 1),
      stats, deltas: { hosts: 0, urls: 0, js: 0, params: 0, vulns: 0 },
      agents, agentMeta,
      jobs: { running, queued, completed },
      jobCounts: { running: st.running_count ?? running.length, queued: st.queued_count ?? queued.length, max: s.max_jobs || 5 },
      resources, monitors, tools,
      session: Array.isArray(session) ? session.slice(0, 30) : (v.session || []),
      log: log.length ? log : v.log,
    };
  } catch (e) {
    return { ...v, live: true, connected: true, authed: true };
  }
}

/* ── the hook ────────────────────────────────────────────── */
export function useLiveState() {
  const [view, setView] = useState(() => emptyView(false));

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
        let agent = null, logs = null, session = null;
        try { agent = await api.agentState(tgt || ""); } catch (_) {}
        try { logs = await api.logs(); } catch (_) {}
        try { session = tgt ? await api.history(tgt) : []; } catch (_) {}
        if (!alive) return;
        setView((v) => mergeLive(v, s, agent, logs, scope, tgt, session));
        timer = setTimeout(pollLive, 3000);
      } catch (e) {
        if (!alive) return;
        if (e && e.status === 401) {
          // Backend is up but we have no valid session — show the login screen
          // (connected=true so it's clearly "sign in", not "offline"). Keep
          // polling so a login in another tab is picked up too.
          setView(() => emptyView(true, false));
          timer = setTimeout(pollLive, 3000);
        } else {
          // Backend unreachable: honest OFFLINE state (no synthetic data),
          // preserving any known auth state so a transient blip doesn't bounce
          // the operator to the login screen. Keep retrying.
          setView((v) => emptyView(false, v.authed));
          timer = setTimeout(pollLive, 5000);
        }
      }
    }

    pollLive();
    return () => { alive = false; if (timer) clearTimeout(timer); };
  }, []);

  return view;
}
