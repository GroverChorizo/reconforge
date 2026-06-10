import React from "react";
import { CheckCircle2, ListChecks } from "lucide-react";

/* ── command-template helpers ─────────────────────────────────────────
   The backend ships cmd *templates* (e.g. "subfinder -d $DOMAIN$ -o $OUTPUT$")
   with placeholders left literal — no secret is ever resolved server-side.
   For display we substitute the target into the host placeholders and render
   every remaining placeholder as a readable <hint>, so the copied command is an
   honest fill-in-the-blanks template, not a fabricated concrete invocation. */
export function fillCmd(cmd, target) {
  if (!cmd) return "";
  const t = (target || "$TARGET").trim();
  return cmd
    .replace(/\$(DOMAIN|TARGET|SUBDOMAIN)\$/g, t)
    .replace(/\$([A-Z0-9_]+)\$/g, (_, v) => `<${v.toLowerCase().replace(/_/g, "-")}>`);
}

export async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (_) { /* fall through to legacy path (http / non-secure context) */ }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch (_) {
    return false;
  }
}

/* ── phase-status mapping (backend status → UI token) ─────────────── */
export function isDone(s) {
  const v = String(s || "").toLowerCase();
  return v === "completed" || v === "complete" || v === "done" || v === "ok";
}
export function statusMeta(s) {
  const v = String(s || "").toLowerCase();
  if (v === "running" || v === "active") return { label: "running", cls: "proc" };
  if (isDone(s)) return { label: "complete", cls: "ok" };
  if (v === "error" || v === "failed" || v === "fail") return { label: "error", cls: "err" };
  return { label: "idle", cls: "" };
}

/* ── shared chrome ────────────────────────────────────────────────── */
export function RiskBadge({ risk }) {
  const r = String(risk || "passive").toLowerCase();
  return <span className={`risk ${r}`}>{r}</span>;
}

export function TargetStrip({ view, target }) {
  const t = target || view.target;
  return (
    <div className="tstrip">
      <div className="tcell"><span className="l">Program</span><span className="val">{view.program || "—"}</span></div>
      <div className="tcell"><span className="l">Target</span><span className="val tgt">{t || "none"}</span></div>
      <div className="tcell"><span className="l">Scope</span>
        <span className={`scopechip ${view.scopeValidated ? "" : "none"}`}>
          <CheckCircle2 size={13} /> {view.scopeValidated ? "Validated" : "Not set"}
        </span>
      </div>
      <div className="tcell"><span className="l">Mode</span>
        <span className={`risk ${String(view.mode || "passive").toLowerCase()}`}>{view.mode}</span>
      </div>
      <div className="tcell"><span className="l">Vault</span><span className="val">ResearchVault/BugBounty/{t || "—"}</span></div>
    </div>
  );
}

export function Checklist({ phases }) {
  const done = phases.filter((p) => isDone(p.status)).length;
  return (
    <div className="panel" style={{ marginBottom: 14 }}>
      <div className="phead">
        <div className="pt"><ListChecks /> Phase Checklist</div>
        <div className="pmeta">{done}/{phases.length} complete</div>
      </div>
      <div className="pbody">
        <div className="checklist">
          {phases.map((p) => {
            const sm = statusMeta(p.status);
            const mark = sm.cls === "ok" ? "✓" : sm.cls === "proc" ? "◐" : sm.cls === "err" ? "✕" : "";
            return (
              <div className={`chk ${sm.cls}`} key={p.id}>
                <span className="box">{mark}</span>
                <span className="cklabel">{p.label}</span>
                <span className="ckstat">{sm.label}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
