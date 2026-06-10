import React, { useState, useEffect } from "react";
import { Shield, ShieldCheck, ShieldAlert, RefreshCw, Target } from "lucide-react";
import { api } from "../../api.js";
import { TargetStrip } from "./bits.jsx";

function ScopeList({ title, entries, tone, Icon }) {
  return (
    <div className="panel">
      <div className="phead">
        <div className="pt"><Icon /> {title}</div>
        <div className="pmeta">{entries.length} {entries.length === 1 ? "entry" : "entries"}</div>
      </div>
      <div className="pbody">
        {entries.length === 0 ? (
          <div className="empty">none declared</div>
        ) : (
          <div className="scopelist">
            {entries.map((e, i) => (
              <div className={`scoperow ${tone}`} key={i}>
                <span className="sval">{e.value}</span>
                {e.type && <span className="stype">{e.type}</span>}
                {e.tier != null && <span className="stier">tier {e.tier}</span>}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

const asList = (x) =>
  (Array.isArray(x) ? x : []).map((e) =>
    typeof e === "string" ? { value: e } : { value: e.value ?? "", type: e.type, tier: e.tier }
  );

/* Scope — read-only mirror of the enforced program. Renders exactly what
   /api/scope reports so the operator sees the same in / out-of-scope rules
   Scope Guard gates on. Editing lives in Intake; no scope logic is reimplemented
   here (scope stays single-source, server-side). */
export default function Scope({ view, onNav }) {
  const [data, setData] = useState(undefined); // undefined = loading
  const [err, setErr] = useState(null);

  const load = async () => {
    setErr(null);
    try {
      setData(await api.scope());
    } catch (e) {
      setErr(String(e.message || e));
      setData(null);
    }
  };
  useEffect(() => { load(); }, []);

  const prog = data && data.program;

  return (
    <main className="ws">
      <div className="ws-head">
        <div className="ws-title">
          <div className="ey">Target · Scope</div>
          <h1>Scope Validation</h1>
          <div className="sub">The active program enforced by Scope Guard before every tool dispatch.</div>
        </div>
        <button className="btn ghost" onClick={load}><RefreshCw size={12} /> refresh</button>
      </div>

      <TargetStrip view={view} target={prog && (prog.workspace || prog.name)} />

      {err ? (
        <div className="panel"><div className="empty big err">Could not load scope — {err}</div></div>
      ) : data === undefined ? (
        <div className="panel"><div className="empty big">Loading scope…</div></div>
      ) : !prog ? (
        <div className="panel">
          <div className="empty big">
            <ShieldAlert size={18} style={{ verticalAlign: "-3px", marginRight: 6 }} />
            No active program. Scope Guard is fail-closed — dispatches are refused until a program is set.
            <div style={{ marginTop: 12 }}>
              <button className="btn primary" onClick={() => onNav && onNav("intake")}><Target size={13} /> Go to Intake</button>
            </div>
          </div>
        </div>
      ) : (
        <>
          <div className="panel scope-banner">
            <ShieldCheck size={16} />
            <div>
              <b>{prog.name || prog.workspace}</b> is the active program — Scope Guard enforces these rules on every dispatch.
              <span className="scope-meta">
                {prog.platform && <span>platform: {prog.platform}</span>}
                {prog.platform_handle && <span>handle: {prog.platform_handle}</span>}
                {data.program_slug && <span>slug: {data.program_slug}</span>}
              </span>
            </div>
          </div>
          <div className="row2" style={{ marginTop: 14 }}>
            <ScopeList title="In scope" entries={asList(prog.in_scope)} tone="in" Icon={ShieldCheck} />
            <ScopeList title="Out of scope" entries={asList(prog.out_of_scope)} tone="out" Icon={ShieldAlert} />
          </div>
          <div className="scope-foot">
            <Shield size={12} /> Out-of-scope rules take precedence over in-scope wildcards. Edit in Intake.
          </div>
        </>
      )}
    </main>
  );
}
