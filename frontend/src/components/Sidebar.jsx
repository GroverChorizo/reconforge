import React from "react";
import { SIDEBAR } from "../constants.js";

export default function Sidebar({ route, setRoute, view }) {
  const dotFor = (id) => {
    if (id === "dashboard") return "proc";
    if (id === "jobs") return view.jobCounts?.running > 0 ? "proc" : null;
    if (id === "passive") return view.stats?.hosts ? "ok" : null;
    if (id === "active") return view.mode === "ACTIVE" ? "proc" : null;
    return null;
  };
  return (
    <aside className="side">
      {SIDEBAR.map((grp, gi) => (
        <div key={gi}>
          {grp.g && <div className="sgroup">{grp.g}</div>}
          {grp.items.map(([id, label, Icon]) => {
            const dot = dotFor(id);
            return (
              <div key={id} className={`nav ${route === id ? "on" : ""}`} onClick={() => setRoute(id)}>
                <Icon /><span>{label}</span>{dot && <span className={`ndot ${dot}`} />}
              </div>
            );
          })}
        </div>
      ))}
    </aside>
  );
}
