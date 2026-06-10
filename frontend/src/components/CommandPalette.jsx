import React, { useState, useEffect } from "react";
import { PALETTE_ACTIONS } from "../constants.js";

export default function CommandPalette({ open, onClose, onRun }) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  useEffect(() => { if (open) { setQ(""); setSel(0); } }, [open]);
  if (!open) return null;
  const results = PALETTE_ACTIONS.filter((a) => a[0].toLowerCase().includes(q.toLowerCase()));
  const run = (a) => { if (a) { onRun(a[3]); onClose(); } };
  return (
    <div className="scrim" onClick={onClose}>
      <div className="pal" onClick={(e) => e.stopPropagation()}>
        <div className="palh">
          <span className="pp-prompt">&gt;</span>
          <input
            autoFocus value={q}
            onChange={(e) => { setQ(e.target.value); setSel(0); }}
            placeholder="type a command, target, or phase…"
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, results.length - 1)); }
              else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
              else if (e.key === "Enter") { e.preventDefault(); run(results[sel]); }
              else if (e.key === "Escape") onClose();
            }}
          />
          <span className="esc">ESC</span>
        </div>
        <div className="palres">
          {results.length === 0 && <div className="empty">No actions match “{q}”. Try “xss”, “scope”, or “export”.</div>}
          {results.map((a, i) => {
            const Icon = a[2];
            return (
              <div key={a[0]} className={`palrow ${i === sel ? "sel" : ""}`}
                   onMouseEnter={() => setSel(i)} onClick={() => run(a)}>
                <Icon /><span className="pl">{a[0]}</span><span className="pk">{a[1]}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
