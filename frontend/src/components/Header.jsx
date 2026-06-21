import React from "react";
import { Command, Power, Circle, BookOpen } from "lucide-react";
import { api } from "../api.js";

export default function Header({ view, onPalette, guide, setGuide }) {
  const signOut = async () => {
    try { await api.logout(); } catch (_) {}
    // Reload so the SPA re-evaluates auth (the poller will see 401 → login).
    window.location.reload();
  };
  return (
    <header className="hdr">
      <div className="brand"><span className="b1">RECON</span><span className="b2">FORGE</span></div>
      <div className="ctx">
        <span><span className="k">target</span><span className="v">{view.target || "none"}</span></span>
        <span className="sep">/</span>
        <span><span className="k">phase</span><span className="v" style={{ textTransform: "capitalize" }}>{view.phaseLabel}</span></span>
        <span className="sep">/</span>
        <span><span className="k">mode</span><span className={`risk ${view.mode.toLowerCase()}`} style={{ marginLeft: 2 }}>{view.mode}</span></span>
      </div>
      <div className="hdr-r">
        <span className={`livedot ${view.live ? "on" : "off"}`}>
          <Circle size={7} fill="currentColor" /> {view.live ? "LIVE" : "OFFLINE"}
        </span>
        <button className={`gbtn ${guide ? "on" : ""}`} onClick={() => setGuide && setGuide(!guide)}
                title="Toggle guide mode">
          <BookOpen size={13} /> guide
        </button>
        <button className="kbtn" onClick={onPalette}><Command size={13} /> Command Palette <kbd>⌘K</kbd></button>
        <div className="usr"><span>{view.user?.username || "operator"}</span>
          <span className="role">[{view.user?.role || "—"}]</span>
          <button className="icobtn" title="Sign out" onClick={signOut}><Power size={15} /></button></div>
      </div>
    </header>
  );
}
