import React, { useState } from "react";
import { Target, Save, CheckCircle2, AlertTriangle, ShieldCheck } from "lucide-react";
import { api } from "../../api.js";
import { RISK_MODES } from "../../constants.js";

const PLATFORMS = [
  ["", "—"], ["intigriti", "Intigriti"], ["hackerone", "HackerOne"],
  ["bugcrowd", "Bugcrowd"], ["yeswehack", "YesWeHack"], ["synack", "Synack"], ["other", "Other"],
];

function Field({ label, hint, children }) {
  return (
    <label className="field">
      <span className="flabel">{label}{hint && <i>{hint}</i>}</span>
      {children}
    </label>
  );
}

/* Target Intake — the default landing. Declares the program + scope and POSTs
   to /api/scope, which persists scopes/<slug>.json and makes it the active
   program. After it returns, Scope Guard gates every dispatch against exactly
   these rules. The risk mode is frontend-only UI classification. */
export default function Intake({ view, target, riskMode, setRiskMode, onSaved, onEvent }) {
  const [f, setF] = useState({
    program: "", target: target && target !== "example.com" ? target : "",
    workspace: "", platform: "", platform_handle: "",
    in_scope: "", out_of_scope: "",
  });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);
  const set = (k) => (e) => setF((s) => ({ ...s, [k]: e.target.value }));
  const lines = (s) => s.split("\n").map((x) => x.trim()).filter(Boolean);

  const save = async () => {
    const tgt = f.target.trim().toLowerCase();
    if (!tgt) { setMsg({ k: "err", t: "Target domain is required." }); return; }
    setBusy(true);
    setMsg(null);
    try {
      const body = {
        target: tgt,
        program: f.program.trim(),
        workspace: f.workspace.trim() || tgt,
        platform: f.platform,
        platform_handle: f.platform_handle.trim(),
        in_scope: lines(f.in_scope),
        out_of_scope: lines(f.out_of_scope),
      };
      await api.saveScope(body);
      setMsg({ k: "ok", t: `Scope saved & enforced for ${tgt}. Scope Guard now gates every dispatch.` });
      onEvent && onEvent({ s: "scope", m: `scope set & enforced · ${tgt}`, k: "ok" });
      onSaved && onSaved(tgt);
    } catch (e) {
      setMsg({ k: "err", t: String(e.message || e) });
      onEvent && onEvent({ s: "scope", m: `scope save failed · ${e.message || e}`, k: "err" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="ws">
      <div className="ws-head">
        <div className="ws-title">
          <div className="ey">Target · Intake</div>
          <h1>Target Intake</h1>
          <div className="sub">Declare the engagement and its scope. Saving makes this the active program — Scope Guard enforces these exact in / out-of-scope rules on every dispatch.</div>
        </div>
      </div>

      <div className="row2 intake-grid">
        <div className="panel">
          <div className="phead"><div className="pt"><Target /> Program</div></div>
          <div className="pbody form">
            <Field label="Program name"><input value={f.program} onChange={set("program")} placeholder="example-program" /></Field>
            <div className="frow">
              <Field label="Target domain" hint="required">
                <input value={f.target} onChange={set("target")} placeholder="example.com" spellCheck={false} />
              </Field>
              <Field label="Workspace" hint="defaults to target">
                <input value={f.workspace} onChange={set("workspace")} placeholder="example.com" spellCheck={false} />
              </Field>
            </div>
            <div className="frow">
              <Field label="Platform">
                <select value={f.platform} onChange={set("platform")}>
                  {PLATFORMS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                </select>
              </Field>
              <Field label="Handle" hint="program identity header">
                <input value={f.platform_handle} onChange={set("platform_handle")} placeholder="grover" spellCheck={false} />
              </Field>
            </div>
            <Field label="Vault export path" hint="derived">
              <input value={`ResearchVault/BugBounty/${f.workspace.trim() || f.target.trim() || "<target>"}/`} readOnly className="ro" />
            </Field>
          </div>
        </div>

        <div className="panel">
          <div className="phead"><div className="pt"><ShieldCheck /> Scope</div></div>
          <div className="pbody form">
            <Field label="In-scope" hint="one host / wildcard per line">
              <textarea value={f.in_scope} onChange={set("in_scope")} rows={4}
                placeholder={"example.com\n*.example.com"} spellCheck={false} />
            </Field>
            <Field label="Out-of-scope" hint="takes precedence over in-scope">
              <textarea value={f.out_of_scope} onChange={set("out_of_scope")} rows={4}
                placeholder={"careers.example.com\n*.dev.example.com"} spellCheck={false} />
            </Field>
            <div className="fnote">Leave in-scope empty to default to the apex domain plus its wildcard.</div>
          </div>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 14 }}>
        <div className="phead"><div className="pt"><AlertTriangle /> Allowed testing level</div>
          <div className="pmeta">UI classification — does not trigger scans</div></div>
        <div className="pbody">
          <div className="seg">
            {RISK_MODES.map(([id, label, hint]) => (
              <button key={id} className={`segbtn ${riskMode === id ? "on" : ""}`} onClick={() => setRiskMode(id)}>
                <span className="seglabel">{label}</span>
                <span className="seghint">{hint}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="intake-foot">
        {msg && (
          <div className={`savemsg ${msg.k}`}>
            {msg.k === "ok" ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}{msg.t}
          </div>
        )}
        <button className="btn primary" onClick={save} disabled={busy}>
          <Save size={13} /> {busy ? "saving…" : "Save & enforce scope"}
        </button>
      </div>
    </main>
  );
}
