import React, { useState, useEffect, useCallback } from "react";
import { useLiveState } from "./useLiveState.js";
import { SIDEBAR, PHASE_PAGES } from "./constants.js";
import { METHODOLOGIES } from "./data/methodologies.js";
import Login from "./components/Login.jsx";
import Header from "./components/Header.jsx";
import KillChainRail from "./components/KillChainRail.jsx";
import Sidebar from "./components/Sidebar.jsx";
import Dashboard from "./components/Dashboard.jsx";
import Console from "./components/Console.jsx";
import CommandPalette from "./components/CommandPalette.jsx";
import Intake from "./components/workspace/Intake.jsx";
import Scope from "./components/workspace/Scope.jsx";
import Accounts from "./components/workspace/Accounts.jsx";
import SessionLog from "./components/workspace/SessionLog.jsx";
import Commands from "./components/workspace/Commands.jsx";
import Runs from "./components/workspace/Runs.jsx";
import PhaseWorkspace from "./components/workspace/PhaseWorkspace.jsx";
import MethodologyWorkspace from "./components/workspace/MethodologyWorkspace.jsx";

const LABELS = Object.fromEntries(
  SIDEBAR.flatMap((g) => g.items.map(([id, label]) => [id, label]))
);
const GROUP_OF = Object.fromEntries(
  SIDEBAR.flatMap((g) => g.items.map(([id]) => [id, g.g || "Operations"]))
);

function Placeholder({ route }) {
  return (
    <main className="ws">
      <div className="ws-head">
        <div className="ws-title">
          <div className="ey">{GROUP_OF[route]}</div>
          <h1>{LABELS[route] || "Section"}</h1>
          <div className="sub">This workspace is part of the command-center build.</div>
        </div>
      </div>
      <div className="panel">
        <div className="placeholder">
          <div className="pk">Wiring in progress</div>
          {LABELS[route]} connects to the existing pipeline next. Press <b style={{ color: "var(--pp-hi)" }}>⌘K</b> to jump anywhere, or return to Mission Control.
        </div>
      </div>
    </main>
  );
}

export default function App() {
  const view = useLiveState();
  const [route, setRoute] = useState("intake"); // spec: app opens to Target Intake
  const [palOpen, setPalOpen] = useState(false);
  const [consoleMin, setConsoleMin] = useState(false);
  const [targetOverride, setTargetOverride] = useState(null);
  const [riskMode, setRiskMode] = useState(() =>
    (typeof localStorage !== "undefined" && localStorage.getItem("rf_riskmode")) || "passive_active");
  const [guide, setGuide] = useState(() =>
    typeof localStorage !== "undefined" && localStorage.getItem("rf_guide") === "1");
  const [events, setEvents] = useState([]);

  // The real active target, or null. When the backend is offline we report
  // null so methodology workspaces show "load a target" rather than pretending
  // there's a live engagement.
  const liveTarget = view.live && view.target && view.target !== "—" ? view.target : null;
  const target = targetOverride || liveTarget;

  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalOpen((o) => !o); }
      else if (e.key === "/" && !palOpen && !/INPUT|TEXTAREA/.test(document.activeElement?.tagName || "")) { e.preventDefault(); setPalOpen(true); }
      else if (e.key === "Escape") setPalOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [palOpen]);

  useEffect(() => { try { localStorage.setItem("rf_riskmode", riskMode); } catch (_) {} }, [riskMode]);
  useEffect(() => { try { localStorage.setItem("rf_guide", guide ? "1" : "0"); } catch (_) {} }, [guide]);

  const onEvent = useCallback((e) => {
    setEvents((xs) => [...xs.slice(-40), { t: new Date().toTimeString().slice(0, 8), ...e }]);
  }, []);

  const onSaved = useCallback((t) => { setTargetOverride(t); setRoute("scope"); }, []);

  // Backend is reachable but we have no session: show sign-in. (All hooks above
  // run unconditionally so this early return is safe per the rules of hooks.)
  if (view.authed === false) return <Login />;

  function renderRoute() {
    if (route === "dashboard") return <Dashboard view={view} onNav={setRoute} />;
    if (route === "intake")
      return <Intake view={view} target={target} riskMode={riskMode} setRiskMode={setRiskMode} onSaved={onSaved} onEvent={onEvent} />;
    if (route === "scope") return <Scope view={view} onNav={setRoute} />;
    if (route === "accounts") return <Accounts />;
    if (route === "session") return <SessionLog target={target} onNav={setRoute} />;
    if (route === "commands") return <Commands view={view} target={target} onEvent={onEvent} />;
    if (route === "runs") return <Runs view={view} target={target} />;
    if (PHASE_PAGES[route])
      return <PhaseWorkspace route={route} view={view} target={target} guide={guide} onEvent={onEvent} />;
    if (METHODOLOGIES[route])
      return <MethodologyWorkspace route={route} view={view} target={target} guide={guide} onEvent={onEvent} />;
    return <Placeholder route={route} />;
  }

  return (
    <div className="rf-root">
      <Header view={view} onPalette={() => setPalOpen(true)} guide={guide} setGuide={setGuide} />
      <KillChainRail rail={view.rail} />
      <div className="grid">
        <Sidebar route={route} setRoute={setRoute} view={view} />
        {renderRoute()}
      </div>
      <Console log={[...view.log, ...events]} min={consoleMin} setMin={setConsoleMin} />
      <CommandPalette open={palOpen} onClose={() => setPalOpen(false)} onRun={setRoute} />
    </div>
  );
}
