import React, { useState, useCallback } from "react";
import { Layers, BookOpen } from "lucide-react";

/* Shared presentational pieces for methodology content. Used by both the
   standalone MethodologyWorkspace (AI API Fuzzing) and the per-vuln playbook
   overlay rendered inside PhaseWorkspace, so the look stays identical and the
   data shapes line up. Pure display — nothing here touches a target. */

export function SourceLink({ source }) {
  if (!source) return null;
  return (
    <a className="msrc" href={source.url} target="_blank" rel="noreferrer noopener">
      <BookOpen size={12} />
      <span>{source.work} · {source.author} · {source.date}</span>
    </a>
  );
}

export function Panel({ icon: Icon, title, meta, children, style }) {
  return (
    <div className="panel" style={style}>
      <div className="phead">
        <div className="pt">{Icon && <Icon />} {title}</div>
        {meta && <div className="pmeta">{meta}</div>}
      </div>
      <div className="pbody">{children}</div>
    </div>
  );
}

export function SectionLabel({ children }) {
  return <div className="msec">{children}</div>;
}

export function Bullets({ items }) {
  if (!items || !items.length) return null;
  return (
    <ul className="mp-points">
      {items.map((it, i) => <li key={i}>{it}</li>)}
    </ul>
  );
}

export function Callout({ kind, children }) {
  return <div className={`mp-note ${kind || "tip"}`}>{children}</div>;
}

export function PhaseCard({ p, icon: Icon = Layers }) {
  return (
    <div className="panel method-phase">
      <div className="phead">
        <div className="pt"><Icon /> {p.label} <span className="pnum">{p.num}</span></div>
      </div>
      <div className="pbody">
        {p.summary && <p className="mp-sum">{p.summary}</p>}
        <Bullets items={p.points} />
        {p.tools && (
          <div className="mp-tools">
            {p.tools.map((t, i) => <code key={i}>{t}</code>)}
          </div>
        )}
        {p.note && <Callout kind={p.note.kind}>{p.note.text}</Callout>}
      </div>
    </div>
  );
}

export function PhaseList({ phases, icon }) {
  if (!phases || !phases.length) return null;
  return (
    <div className="forge-stack">
      {phases.map((p) => <PhaseCard key={p.num} p={p} icon={icon} />)}
    </div>
  );
}

export function PatternGrid({ patterns }) {
  if (!patterns || !patterns.length) return null;
  return (
    <div className="pattern-grid">
      {patterns.map((pt, i) => (
        <div className="pcard" key={i}>
          <div className="pcard-t">{pt.title}</div>
          <div className="pcard-b">{pt.text}</div>
          {pt.action && <div className="pcard-a"><b>Action</b> {pt.action}</div>}
        </div>
      ))}
    </div>
  );
}

/* Interactive, localStorage-persisted checklist — the app affordance a static
   doc can't give: tick the steps and keep that progress across reloads. */
export function MethodChecklist({ storageKey, items, onEvent }) {
  const key = `rf_method_${storageKey}`;
  const [done, setDone] = useState(() => {
    try {
      const raw = typeof localStorage !== "undefined" && localStorage.getItem(key);
      return new Set(raw ? JSON.parse(raw) : []);
    } catch (_) { return new Set(); }
  });

  const toggle = useCallback((i) => {
    setDone((prev) => {
      const next = new Set(prev);
      next.has(i) ? next.delete(i) : next.add(i);
      try { localStorage.setItem(key, JSON.stringify([...next])); } catch (_) {}
      return next;
    });
    onEvent && onEvent({ s: "methodology", m: `checklist · ${storageKey}`, k: "ok" });
  }, [key, storageKey, onEvent]);

  return (
    <div className="checklist">
      {items.map((it, i) => {
        const on = done.has(i);
        return (
          <div
            className={`chk click ${on ? "on" : ""}`}
            key={i}
            role="checkbox"
            aria-checked={on}
            tabIndex={0}
            onClick={() => toggle(i)}
            onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(i); } }}
          >
            <span className="box">{on ? "✓" : ""}</span>
            <span className="cklabel">{it}</span>
          </div>
        );
      })}
    </div>
  );
}
