import React, { useState } from "react";
import { Terminal, Copy, Check } from "lucide-react";
import { RiskBadge, fillCmd, copyText, statusMeta } from "./bits.jsx";

function CmdRow({ tool, target, onEvent }) {
  const [copied, setCopied] = useState(false);
  const isGate = !tool.cmd;
  const filled = fillCmd(tool.cmd, target);

  const copy = async () => {
    const ok = await copyText(filled);
    setCopied(ok);
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

/* The centerpiece. One Command Forge per methodology phase: header carries the
   phase risk + live status; body lists each tool's copy-pasteable command for
   the active target. Display-only — nothing executes from here. */
export default function CommandForge({ phase, target, output, onEvent }) {
  const sm = statusMeta(phase.status);
  const tools = phase.tool_meta || [];
  const runnable = tools.filter((t) => t.cmd);

  const copyAll = async () => {
    const all = runnable.map((t) => fillCmd(t.cmd, target)).join("\n");
    const ok = await copyText(all);
    onEvent && onEvent({
      s: "forge",
      m: `phase copied · ${phase.label} (${runnable.length} command${runnable.length === 1 ? "" : "s"})`,
      k: ok ? "ok" : "err",
    });
  };

  return (
    <div className="panel forge">
      <div className="phead">
        <div className="pt"><Terminal /> {phase.label} <span className="pnum">{phase.num}</span></div>
        <div className="forge-meta">
          <RiskBadge risk={phase.risk} />
          <span className={`fstat ${sm.cls}`}>{sm.label}</span>
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
      {runnable.length > 0 && (
        <div className="forge-foot">
          <span className="fhint">Copy-only — commands run in your terminal. Nothing executes from here.</span>
          <button className="btn ghost" onClick={copyAll}><Copy size={12} /> Copy all</button>
        </div>
      )}
    </div>
  );
}
