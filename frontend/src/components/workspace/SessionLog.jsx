import React, { useState, useEffect, useCallback } from "react";
import { ScrollText, RefreshCw } from "lucide-react";
import { api } from "../../api.js";

/* Session Log — the per-target hunt record. Reads the persisted history
   timeline (GET /api/history?domain=) and shows everything done on the
   target newest-first: commands copied from the Forge, scope changes,
   scope-guard decisions, dispatched jobs, and agent runs. This is what
   turns "I copied a command" into a durable, reviewable session. */

// source → [short label, css colour class]. Unknown sources fall back to "evt".
const SRC = {
  forge: ["forge", "pp"], scope: ["scope", "ok"], scope_guard: ["guard", "warn"],
  dispatch: ["dispatch", ""], pipeline: ["pipeline", "pp"], agent: ["agent", "pp"],
  monitor: ["monitor", "ok"], note: ["note", ""],
};
const srcMeta = (s) => SRC[s] || [s || "evt", ""];
const timeOf = (s) => (String(s || "").match(/(\d{2}:\d{2}:\d{2})/) || [, ""])[1];
const dayOf = (s) => (String(s || "").match(/(\d{4}-\d{2}-\d{2})/) || [, ""])[1];

export default function SessionLog({ target, onNav }) {
  const [rows, setRows] = useState(null); // null = loading
  const [filter, setFilter] = useState("all");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!target) { setRows([]); return; }
    setBusy(true);
    try { const r = await api.history(target); setRows(Array.isArray(r) ? r : []); }
    catch (_) { setRows([]); }
    finally { setBusy(false); }
  }, [target]);

  useEffect(() => { load(); const t = setInterval(load, 8000); return () => clearInterval(t); }, [load]);

  if (!target) {
    return (
      <main className="ws">
        <div className="ws-head"><div className="ws-title">
          <div className="ey">Operations · Session Log</div>
          <h1>Session Log</h1>
          <div className="sub">A per-target timeline of everything done on the engagement — commands generated, scope changes, jobs, and agent runs.</div>
        </div></div>
        <div className="panel"><div className="placeholder">
          <div className="pk">No target loaded</div>
          Load a target in <b className="lk" onClick={() => onNav && onNav("intake")}>Target Intake</b> to start its session log.
        </div></div>
      </main>
    );
  }

  const all = rows || [];
  const counts = all.reduce((m, r) => { m[r.source] = (m[r.source] || 0) + 1; return m; }, {});
  const shown = filter === "all" ? all : all.filter((r) => r.source === filter);
  let lastDay = null;

  return (
    <main className="ws">
      <div className="ws-head">
        <div className="ws-title">
          <div className="ey">Operations · Session Log</div>
          <h1>Session Log</h1>
          <div className="sub">Everything done on <b className="hi">{target}</b> — commands you copied, scope changes, jobs, and agent runs. Newest first.</div>
        </div>
        <button className="btn ghost" onClick={load} disabled={busy}>
          <RefreshCw size={12} className={busy ? "spin" : ""} /> refresh
        </button>
      </div>

      <div className="sl-filters">
        <button className={`slf ${filter === "all" ? "on" : ""}`} onClick={() => setFilter("all")}>all <i>{all.length}</i></button>
        {Object.keys(counts).sort().map((s) => (
          <button key={s} className={`slf ${filter === s ? "on" : ""}`} onClick={() => setFilter(s)}>
            {srcMeta(s)[0]} <i>{counts[s]}</i>
          </button>
        ))}
      </div>

      <div className="panel">
        <div className="phead"><div className="pt"><ScrollText /> Timeline</div>
          <div className="pmeta">{shown.length} event{shown.length === 1 ? "" : "s"}</div></div>
        <div className="pbody">
          {rows === null && <div className="empty">Loading…</div>}
          {rows && shown.length === 0 && (
            <div className="empty">No activity yet for {target}. Copy a command from any methodology workspace and it lands here.</div>
          )}
          {shown.map((r, i) => {
            const [label, cls] = srcMeta(r.source);
            const day = dayOf(r.created_at);
            const showDay = day && day !== lastDay; lastDay = day;
            return (
              <React.Fragment key={r.id || i}>
                {showDay && <div className="sl-day">{day}</div>}
                <div className="slrow">
                  <span className="sltime">{timeOf(r.created_at)}</span>
                  <span className={`slsrc ${cls}`}>{label}</span>
                  <span className="sltext">{r.text}</span>
                </div>
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </main>
  );
}
