import React, { useState, useEffect, useCallback } from "react";
import { FolderOpen, RefreshCw, FileText } from "lucide-react";
import { api } from "../../api.js";
import { TargetStrip } from "./bits.jsx";

/* Browse dated scan runs on disk: out/<target>/<datestamp>/<phase>/. Each hunt
   gets its own dated folder, so past runs stay findable and never get buried or
   merged. Read-only view over the filesystem (GET /api/runs). */
export default function Runs({ view, target }) {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    if (!target) { setData(null); return; }
    setLoading(true);
    try { setData(await api.runs(target)); setErr(null); }
    catch (e) { setErr(String(e.message || e)); }
    finally { setLoading(false); }
  }, [target]);

  useEffect(() => { load(); }, [load]);

  return (
    <main className="ws">
      <div className="ws-head">
        <div className="ws-title">
          <div className="ey">Operations · Runs</div>
          <h1>Scan Runs</h1>
          <div className="sub">Every hunt writes its own dated folder. Browse past runs so nothing gets buried.</div>
        </div>
        <button className="btn ghost" onClick={load} disabled={!target}>
          <RefreshCw size={12} className={loading ? "spin" : ""} /> refresh
        </button>
      </div>

      <TargetStrip view={view} target={target} />

      {!target ? (
        <div className="panel"><div className="empty big">No target loaded. Open <b>Intake</b> first — runs are organized per target.</div></div>
      ) : err ? (
        <div className="panel"><div className="empty big err">{err}</div></div>
      ) : !data ? (
        <div className="panel"><div className="empty big">Loading runs…</div></div>
      ) : data.runs.length === 0 ? (
        <div className="panel"><div className="empty big">No runs yet for {target}. Launch a phase from a Recon workspace to create one.</div></div>
      ) : (
        <div className="runs">
          {data.runs.map((r) => (
            <div className={`panel run ${r.active ? "active" : ""}`} key={r.datestamp}>
              <div className="phead">
                <div className="pt"><FolderOpen /> {r.datestamp} {r.active && <span className="run-active-pill">active</span>}</div>
                <div className="pmeta">{r.phases.length} phase{r.phases.length === 1 ? "" : "s"}</div>
              </div>
              <div className="run-path">{r.path}</div>
              <div className="pbody">
                {r.phases.length === 0 && <div className="empty">No phase output written yet.</div>}
                {r.phases.map((p) => (
                  <div className="run-phase" key={p.phase}>
                    <span className="rp-name"><FileText size={12} /> {p.phase}</span>
                    <span className="rp-meta">{p.files} file{p.files === 1 ? "" : "s"}{p.modified ? ` · ${p.modified}` : ""}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </main>
  );
}
