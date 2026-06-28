import React, { useState, useEffect, useCallback } from "react";
import { Terminal, Plus, Copy, Check, Trash2, RefreshCw } from "lucide-react";
import { api } from "../../api.js";
import { TargetStrip, copyText } from "./bits.jsx";

/* Per-program command library. Author and keep your own command lines for the
   active target — copy/recall only (not an execution queue). Pairs with the
   Session Log, which auto-logs what the pipeline ran and what you copied. */
export default function Commands({ view, target, onEvent }) {
  const [items, setItems] = useState(null);
  const [err, setErr] = useState(null);
  const [name, setName] = useState("");
  const [cmd, setCmd] = useState("");
  const [busy, setBusy] = useState(false);
  const [copiedId, setCopiedId] = useState(null);

  const load = useCallback(async () => {
    if (!target) { setItems(null); return; }
    try { setItems(await api.commands(target)); setErr(null); }
    catch (e) { setErr(String(e.message || e)); }
  }, [target]);

  useEffect(() => { load(); }, [load]);

  const add = async () => {
    if (!target || !cmd.trim()) return;
    setBusy(true);
    try {
      await api.saveCommand({ target, name: name.trim(), cmd: cmd.trim() });
      setName(""); setCmd("");
      onEvent && onEvent({ s: "cmdlib", m: `command saved · ${target}`, k: "ok" });
      load();
    } catch (e) {
      onEvent && onEvent({ s: "cmdlib", m: `save failed · ${e.message || e}`, k: "err" });
    } finally { setBusy(false); }
  };

  const copy = async (it) => {
    const ok = await copyText(it.cmd);
    if (ok) { setCopiedId(it.id); setTimeout(() => setCopiedId(null), 1300); }
  };

  const del = async (it) => {
    try { await api.deleteCommand(it.id); load(); }
    catch (e) { onEvent && onEvent({ s: "cmdlib", m: `delete failed · ${e.message || e}`, k: "err" }); }
  };

  return (
    <main className="ws">
      <div className="ws-head">
        <div className="ws-title">
          <div className="ey">Operations · Commands</div>
          <h1>Command Library</h1>
          <div className="sub">Your own saved commands for this program — author, copy, reuse. Kept per target.</div>
        </div>
        <button className="btn ghost" onClick={load} disabled={!target}><RefreshCw size={12} /> refresh</button>
      </div>

      <TargetStrip view={view} target={target} />

      {!target ? (
        <div className="panel"><div className="empty big">No target loaded. Open <b>Intake</b> to declare a program — saved commands are kept per target.</div></div>
      ) : (
        <>
          <div className="panel" style={{ marginBottom: 14 }}>
            <div className="phead"><div className="pt"><Plus /> Save a command</div></div>
            <div className="pbody form">
              <label className="field">
                <span className="flabel">Label <i>optional</i></span>
                <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. ffuf — admin paths" />
              </label>
              <label className="field">
                <span className="flabel">Command</span>
                <textarea value={cmd} onChange={(e) => setCmd(e.target.value)} rows={2} spellCheck={false}
                  placeholder={`ffuf -u https://${target}/FUZZ -w wordlist.txt`} />
              </label>
              <div style={{ display: "flex", justifyContent: "flex-end" }}>
                <button className="btn primary" onClick={add} disabled={busy || !cmd.trim()}>
                  <Plus size={13} /> {busy ? "saving…" : "Save command"}
                </button>
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="phead">
              <div className="pt"><Terminal /> Saved</div>
              <div className="pmeta">{items ? items.length : 0} command{items && items.length === 1 ? "" : "s"}</div>
            </div>
            <div className="pbody">
              {err && <div className="empty err">{err}</div>}
              {items && items.length === 0 && <div className="empty">No saved commands yet.</div>}
              {items && items.map((it) => (
                <div className="cmd" key={it.id}>
                  <div className="cmd-top">
                    <span className="cmd-name">{it.name || "command"}</span>
                    <span className="cmd-desc">{it.created_at}{it.created_by ? ` · ${it.created_by}` : ""}</span>
                  </div>
                  <div className="cmd-line">
                    <span className="cmd-prompt">$</span>
                    <code>{it.cmd}</code>
                    <button className={`cmd-copy ${copiedId === it.id ? "ok" : ""}`} onClick={() => copy(it)} title="Copy command">
                      {copiedId === it.id ? <Check size={12} /> : <Copy size={12} />}{copiedId === it.id ? "copied" : "copy"}
                    </button>
                    <button className="cmd-copy" onClick={() => del(it)} title="Delete"><Trash2 size={12} /></button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </main>
  );
}
