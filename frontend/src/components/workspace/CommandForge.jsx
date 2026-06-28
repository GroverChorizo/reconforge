import React, { useState, useEffect, useRef } from "react";
import { Terminal, Copy, Check, Play, AlertTriangle } from "lucide-react";
import { RiskBadge, fillCmd, copyText, statusMeta, isDone } from "./bits.jsx";
import { api } from "../../api.js";

const isTerminal = (s) => {
  const v = String(s || "").toLowerCase();
  return ["completed", "complete", "done", "ok", "error", "failed", "fail", "cancelled"].includes(v);
};

function CmdRow({ tool, target, onEvent }) {
  const [copied, setCopied] = useState(false);
  const isGate = !tool.cmd;
  const filled = fillCmd(tool.cmd, target);

  const copy = async () => {
    const ok = await copyText(filled);
    setCopied(ok);
    // Persist to the target's Session Log so the hunt records what was
    // generated, not just what the pipeline ran. Fire-and-forget.
    if (ok && target) api.logCommand({ target, source: "forge", text: `${tool.name}: ${filled}` }).catch(() => {});
    onEvent && onEvent({ s: "forge", m: `command copied · ${tool.name}`, k: ok ? "ok" : "err" });
    setTimeout(() => setCopied(false), 1300);
  };

  return (
    <div className="cmd">
      <div className="cmd-top">
        <span className="cmd-name">{tool.name}</span>
        {tool.type && <span className="cmd-type">{tool.type}</span>}
        {tool.description && <span className="cmd-desc">{tool.description}</span>}
      </div>
      {isGate ? (
        <div className="cmd-line gate">scope gate · runs before any tool in this phase — no shell command</div>
      ) : (
        <div className="cmd-line">
          <span className="cmd-prompt">$</span>
          <code>{filled}</code>
          <button className={`cmd-copy ${copied ? "ok" : ""}`} onClick={copy} title="Copy command">
            {copied ? <Check size={12} /> : <Copy size={12} />}{copied ? "copied" : "copy"}
          </button>
        </div>
      )}
    </div>
  );
}

function logText(l) {
  if (typeof l === "string") return l;
  if (!l) return "";
  const ts = l.ts || l.time || "";
  return `${ts ? ts + " " : ""}${l.msg || l.message || l.line || JSON.stringify(l)}`;
}

/* One Command Forge per methodology phase. The body lists each tool's
   copy-pasteable command (templates — secrets are never resolved client-side).
   "Run phase" executes the real phase script on the server (scope-gated by the
   backend before anything spawns) and streams its live output here; aggressive
   phases confirm first. Copy still works for running in your own terminal. */
export default function CommandForge({ phase, target, output, fresh, onEvent, onLaunched }) {
  const sm = statusMeta(phase.status);
  const tools = phase.tool_meta || [];
  const runnable = tools.filter((t) => t.cmd);
  const aggressive = String(phase.risk || "").toLowerCase() === "aggressive";

  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState([]);
  const [liveStatus, setLiveStatus] = useState(null);
  const [runErr, setRunErr] = useState(null);
  const aliveRef = useRef(true);
  const pollRef = useRef(null);

  const poll = async () => {
    try {
      const d = await api.pipelineLogs(target, phase.id);
      if (!aliveRef.current) return;
      setLogs(d.logs || []);
      setLiveStatus(d.status || null);
      if (isTerminal(d.status)) {
        setRunning(false);
        onEvent && onEvent({ s: "run", m: `phase ${phase.label} · ${String(d.status).toLowerCase()}`, k: isDone(d.status) ? "ok" : "err" });
        onLaunched && onLaunched();
        return;
      }
    } catch (_) { /* transient — keep polling */ }
    if (aliveRef.current) pollRef.current = setTimeout(poll, 1600);
  };

  // Re-attach to an already-running phase (launched before this mounted).
  useEffect(() => {
    aliveRef.current = true;
    if (String(phase.status || "").toLowerCase() === "running") { setRunning(true); poll(); }
    return () => { aliveRef.current = false; if (pollRef.current) clearTimeout(pollRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase.id, target]);

  const run = async () => {
    if (!target || running) return;
    if (aggressive && !window.confirm(
      `"${phase.label}" sends live / aggressive payloads to ${target}. Run it on the server now?`)) return;
    setRunErr(null); setLogs([]); setLiveStatus("running"); setRunning(true);
    try {
      await api.pipelineRun(target, phase.id, !!fresh);
      onEvent && onEvent({ s: "run", m: `phase launched · ${phase.label}${fresh ? " (fresh run)" : ""}`, k: "ok" });
      onLaunched && onLaunched();
      poll();
    } catch (e) {
      setRunning(false);
      const m = String(e.message || e);
      setRunErr(m);  // e.g. "out of scope: …" (403) from Scope Guard
      onEvent && onEvent({ s: "run", m: `launch refused · ${m}`, k: "err" });
    }
  };

  const copyAll = async () => {
    const all = runnable.map((t) => fillCmd(t.cmd, target)).join("\n");
    const ok = await copyText(all);
    if (ok && target) api.logCommand({
      target, source: "forge",
      text: `${phase.label}: copied ${runnable.length} command${runnable.length === 1 ? "" : "s"} (${runnable.map((t) => t.name).join(", ")})`,
    }).catch(() => {});
    onEvent && onEvent({
      s: "forge",
      m: `phase copied · ${phase.label} (${runnable.length} command${runnable.length === 1 ? "" : "s"})`,
      k: ok ? "ok" : "err",
    });
  };

  const shown = running ? { label: "running", cls: "proc" } : (liveStatus ? statusMeta(liveStatus) : sm);

  return (
    <div className="panel forge">
      <div className="phead">
        <div className="pt"><Terminal /> {phase.label} <span className="pnum">{phase.num}</span></div>
        <div className="forge-meta">
          <RiskBadge risk={phase.risk} />
          <span className={`fstat ${shown.cls}`}>{shown.label}</span>
          <button className={`btn ${aggressive ? "danger" : "primary"} run-btn`}
                  onClick={run} disabled={!target || running}
                  title={target ? "Run this phase on the server" : "Load a target first"}>
            <Play size={12} /> {running ? "running…" : "Run phase"}
          </button>
        </div>
      </div>
      <div className="forge-ctx">
        <span><i>target</i>{target || "—"}</span>
        <span><i>output</i>{output}</span>
        {phase.ingests && <span className="ingests">↳ ingests to asset map</span>}
      </div>
      <div className="pbody">
        {tools.length === 0 && <div className="empty">No tools mapped to this phase.</div>}
        {tools.map((t) => <CmdRow key={t.key} tool={t} target={target} onEvent={onEvent} />)}
      </div>

      {runErr && <div className="run-err"><AlertTriangle size={13} /> {runErr}</div>}
      {(running || logs.length > 0) && (
        <div className="run-logs">
          <div className="run-logs-head">live output{running && <span className="dotpulse" />}</div>
          <pre>{logs.length ? logs.slice(-300).map(logText).join("\n") : "waiting for output…"}</pre>
        </div>
      )}

      {runnable.length > 0 && (
        <div className="forge-foot">
          <span className="fhint">Run executes the phase on the server, scope-gated. Or copy to run in your own terminal.</span>
          <button className="btn ghost" onClick={copyAll}><Copy size={12} /> Copy all</button>
        </div>
      )}
    </div>
  );
}
