import React, { useState, useEffect, useCallback } from "react";
import { RefreshCw, Info, AlertTriangle, Crosshair, GitBranch, ShieldCheck, FolderPlus } from "lucide-react";
import { api } from "../../api.js";
import { PHASE_PAGES } from "../../constants.js";
import { VULN_PLAYBOOKS } from "../../data/vulnPlaybooks.js";
import CommandForge from "./CommandForge.jsx";
import { TargetStrip, Checklist } from "./bits.jsx";
import { Panel, SectionLabel, Bullets, PhaseList, PatternGrid, MethodChecklist } from "./methodology.jsx";

/* Generic methodology workspace. Reads the kill-chain phases for the active
   target from /api/pipeline, filters to this route's phase ids, and renders a
   Command Forge per phase plus a status checklist. When a route also has a
   VULN_PLAYBOOK (xss/sqli/auth/takeover), the narrative methodology — overview,
   how-to-test steps, variant cards, chaining, confirm-before-report — wraps
   around the Command Forge. The playbook is target-independent reference and
   renders even before a target is loaded; only the commands need a target.
   Pure presentation of the existing pipeline — it never starts a run. */
export default function PhaseWorkspace({ route, view, target, guide, onEvent }) {
  const cfg = PHASE_PAGES[route];
  const pb = VULN_PLAYBOOKS[route];
  const [phases, setPhases] = useState(null);
  const [runMeta, setRunMeta] = useState({});
  const [freshNext, setFreshNext] = useState(false);
  const [err, setErr] = useState(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    if (!target) { setPhases(null); setErr(null); setRunMeta({}); return; }
    setLoading(true);
    setErr(null);
    try {
      const data = await api.pipeline(target);
      const byId = Object.fromEntries((data.phases || []).map((p) => [p.id, p]));
      setPhases(cfg.phases.map((id) => byId[id]).filter(Boolean));
      setRunMeta({ datestamp: data.datestamp, run_dir: data.run_dir });
    } catch (e) {
      setErr(String(e.message || e));
    } finally {
      setLoading(false);
    }
  }, [target, route]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load(); }, [load]);

  const output = `ResearchVault/BugBounty/${target || "—"}/`;
  const aggressive = cfg.risk === "aggressive" || (phases || []).some((p) => p.risk === "aggressive");

  function renderCommands() {
    if (!target) {
      return (
        <div className="panel">
          <div className="empty big">
            {pb ? (
              <>Load a target in <b>Intake</b> to forge the commands for this workflow — the methodology applies to any target.</>
            ) : (
              <>No target loaded. Open <b>Intake</b> to declare a program and scope — this workspace then forges commands for it.</>
            )}
          </div>
        </div>
      );
    }
    if (err) return <div className="panel"><div className="empty big err">Could not load phases — {err}</div></div>;
    if (!phases) return <div className="panel"><div className="empty big">Loading phases…</div></div>;
    if (phases.length === 0) {
      if (pb) return null;
      return <div className="panel"><div className="empty big">No phases mapped to this workspace.</div></div>;
    }
    return (
      <>
        {pb && <SectionLabel>Run it · Command Forge</SectionLabel>}
        <Checklist phases={phases} />
        <div className="forge-stack">
          {phases.map((p) => (
            <CommandForge key={p.id} phase={p} target={target} output={output}
              fresh={freshNext} onEvent={onEvent}
              onLaunched={() => { setFreshNext(false); load(); }} />
          ))}
        </div>
      </>
    );
  }

  return (
    <main className={`ws${pb ? " method" : ""}`}>
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

      {target && (
        <div className="run-bar">
          <span className="run-bar-l">
            active run · <b>{runMeta.datestamp || "— starts on first Run"}</b>
            {runMeta.run_dir && <span className="run-dir">{runMeta.run_dir}</span>}
          </span>
          <button className={`btn ghost ${freshNext ? "on" : ""}`} onClick={() => setFreshNext((v) => !v)}
                  title="Start the next Run in a new dated folder so it doesn't merge with the current run">
            <FolderPlus size={12} /> {freshNext ? "new run armed" : "new run"}
          </button>
        </div>
      )}

      {aggressive && (
        <div className="risknote">
          <AlertTriangle size={14} />
          <span>
            Active workflow — these tools send live payloads to the target. Running a phase here
            executes it on the server; aggressive phases confirm before they launch.
          </span>
        </div>
      )}

      {guide && cfg.guide && (
        <div className="guide">
          <Info size={13} />
          <div><b>Why this matters</b><p>{cfg.guide}</p></div>
        </div>
      )}

      {/* methodology — overview + how-to-test (before the commands) */}
      {pb && (
        <>
          <Panel icon={Info} title="Overview" style={{ marginBottom: 14 }}>
            <p className="mp-sum">{pb.intro}</p>
            {pb.signals && <><div className="mp-subh">Detection signals</div><Bullets items={pb.signals} /></>}
          </Panel>
          {pb.method && (
            <>
              <SectionLabel>How to test</SectionLabel>
              <PhaseList phases={pb.method} />
            </>
          )}
        </>
      )}

      {renderCommands()}

      {/* methodology — variants, chaining, confirm-before-report (after the commands) */}
      {pb && (
        <>
          {pb.patterns && (
            <Panel icon={Crosshair} title="Variants & sub-techniques" meta={`${pb.patterns.length} variants`} style={{ marginTop: 14 }}>
              <PatternGrid patterns={pb.patterns} />
            </Panel>
          )}
          {pb.chain && (
            <Panel icon={GitBranch} title="Chaining & escalation" style={{ marginTop: 14 }}>
              <Bullets items={pb.chain} />
            </Panel>
          )}
          {pb.confirm && (
            <Panel icon={ShieldCheck} title="Before you report" style={{ marginTop: 14 }}>
              {pb.confirm.pitfalls && <Bullets items={pb.confirm.pitfalls} />}
              {pb.confirm.checklist && (
                <>
                  <div className="mp-subh">Confirm before submitting</div>
                  <MethodChecklist storageKey={`${route}-confirm`} items={pb.confirm.checklist} onEvent={onEvent} />
                </>
              )}
            </Panel>
          )}
          {pb.refs && (
            <div className="mrefs">
              <b>Deeper</b>
              {pb.refs.map((r, i) => <span key={i}>{r}</span>)}
            </div>
          )}
        </>
      )}
    </main>
  );
}
