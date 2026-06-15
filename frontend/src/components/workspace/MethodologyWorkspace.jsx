import React from "react";
import { Crosshair, Cpu, ListChecks, Info } from "lucide-react";
import { METHODOLOGIES } from "../../data/methodologies.js";
import { TargetStrip } from "./bits.jsx";
import {
  SourceLink, Panel, Bullets, PhaseList, PatternGrid, MethodChecklist,
} from "./methodology.jsx";

/* Reference-methodology workspace. Renders a narrative playbook from
   METHODOLOGIES (build-your-own-harness workflow), not the kill-chain Command
   Forge. Display-only: nothing here touches a target — scope_guard still gates
   live execution against declared targets. */
export default function MethodologyWorkspace({ route, view, target, guide, onEvent }) {
  const m = METHODOLOGIES[route];
  if (!m) {
    return (
      <main className="ws">
        <div className="panel"><div className="empty big err">Unknown methodology — {route}</div></div>
      </main>
    );
  }

  return (
    <main className="ws method">
      <div className="ws-head">
        <div className="ws-title">
          <div className="ey">{m.eyebrow}</div>
          <h1>{m.title}</h1>
          <div className="sub">{m.sub}</div>
        </div>
        <SourceLink source={m.source} />
      </div>

      <TargetStrip view={view} target={target} />

      {m.note && <div className="mnote">{m.note}</div>}

      {guide && m.thesis && (
        <div className="guide">
          <Info size={13} />
          <div><b>Thesis</b><p>{m.thesis}</p></div>
        </div>
      )}

      <PhaseList phases={m.phases} />

      {m.patterns && (
        <Panel icon={Crosshair} title="Bug-class pattern cards" meta={`${m.patterns.length} patterns`} style={{ marginTop: 14 }}>
          <PatternGrid patterns={m.patterns} />
        </Panel>
      )}

      {m.principles && (
        <Panel icon={Cpu} title="Why it works" style={{ marginTop: 14 }}>
          <Bullets items={m.principles} />
        </Panel>
      )}

      {m.checklist && (
        <Panel icon={ListChecks} title="Hands-on replication checklist" meta="build it in your pipeline" style={{ marginTop: 14 }}>
          <MethodChecklist storageKey={`${route}-build`} items={m.checklist} onEvent={onEvent} />
        </Panel>
      )}
    </main>
  );
}
