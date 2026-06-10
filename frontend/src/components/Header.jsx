import React from "react";
import { Command, Power, Circle, BookOpen } from "lucide-react";

export default function Header({ view, onPalette, guide, setGuide }) {
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
          <Circle size={7} fill="currentColor" /> {view.live ? "LIVE" : "SIMULATED"}
        </span>
        <button className={`gbtn ${guide ? "on" : ""}`} onClick={() => setGuide && setGuide(!guide)}
                title="Toggle guide mode">
          <BookOpen size={13} /> guide
        </button>
        <button className="kbtn" onClick={onPalette}><Command size={13} /> Command Palette <kbd>⌘K</kbd></button>
        <div className="usr"><span>operator</span><span className="role">[admin]</span>
          <button className="icobtn" title="Sign out"><Power size={15} /></button></div>
      </div>
    </header>
  );
}
