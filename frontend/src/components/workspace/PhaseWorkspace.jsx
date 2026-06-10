import React, { useState, useEffect, useCallback } from "react";
import { RefreshCw, Info, AlertTriangle } from "lucide-react";
import { api } from "../../api.js";
import { PHASE_PAGES } from "../../constants.js";
import CommandForge from "./CommandForge.jsx";
import { TargetStrip, Checklist } from "./bits.jsx";

/* Generic methodology workspace. Reads the kill-chain phases for the active
   target from /api/pipeline, filters to this route's phase ids, and renders a
   Command Forge per phase plus a status checklist. Pure presentation of the
   existing pipeline — it never starts a run. */
export default function PhaseWorkspace({ route, view, target, guide, onEvent }) {
  const cfg = PHASE_PAGES[route];
  const [phases, setPhases] = useState(null);
  const [err, setErr] = useState(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    if (!target) { setPhases(null); setErr(null); return; }
    setLoading(true);
    setErr(null);
    try {
      const data = await api.pipeline(target);
      const byId = Object.fromEntries((data.phases || []).map((p) => [p.id, p]));
      setPhases(cfg.phases.map((id) => byId[id]).filter(Boolean));
    } catch (e) {
      setErr(String(e.message || e));
    } finally {
      setLoading(false);
    }
  }, [target, route]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load(); }, [load]);

  const output = `ResearchVault/BugBounty/${target || "—"}/`;
  const aggressive = cfg.risk === "aggressive" || (phases || []).some((p) => p.risk === "aggressive");

  return (
    <main className="ws">
      <div className="ws-head">
        <div className="ws-title">
          <div className="ey">{cfg.eyebrow}</div>
          <h1>{cfg.title}</h1>
          <div className="sub">{cfg.sub}</div>
        </div>
        <button className="btn ghost" onClick={load} disabled={loading || !target}>
          <RefreshCw size={12} className={loading ? "spin" : ""} /> {loading ? "loading" : "refresh"}
        </button>
      </div>

      <TargetStrip view={view} target={target} />

      {aggressive && (
        <div className="risknote">
          <AlertTriangle size={14} />
          <span>
            Aggressive workflow — these tools send active payloads to the target. Confirm scope and
            authorization first. Commands here are copy-only and never auto-run.
          </span>
        </div>
      )}

      {guide && cfg.guide && (
        <div className="guide">
          <Info size={13} />
          <div><b>Why this matters</b><p>{cfg.guide}</p></div>
        </div>
      )}

      {!target ? (
        <div className="panel">
          <div className="empty big">
            No target loaded. Open <b>Intake</b> to declare a program and scope — this workspace then
            forges commands for it.
          </div>
        </div>
      ) : err ? (
        <div className="panel"><div className="empty big err">Could not load phases — {err}</div></div>
      ) : !phases ? (
        <div className="panel"><div className="empty big">Loading phases…</div></div>
      ) : phases.length === 0 ? (
        <div className="panel"><div className="empty big">No phases mapped to this workspace.</div></div>
      ) : (
        <>
          <Checklist phases={phases} />
          <div className="forge-stack">
            {phases.map((p) => (
              <CommandForge key={p.id} phase={p} target={target} output={output} onEvent={onEvent} />
            ))}
          </div>
        </>
      )}
    </main>
  );
}
