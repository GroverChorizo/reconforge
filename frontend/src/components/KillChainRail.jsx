import React from "react";
import { ChevronRight } from "lucide-react";

export default function KillChainRail({ rail }) {
  return (
    <nav className="rail">
      {rail.map((s, i) => (
        <div key={s.label} className={`rstep ${s.state === "todo" ? "" : s.state}`}>
          <span className="dot" />
          <span className="rnum">{String(i).padStart(2, "0")}</span>
          {s.label}
          {i < rail.length - 1 && <ChevronRight className="arr" size={13} />}
        </div>
      ))}
    </nav>
  );
}
