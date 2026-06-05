/* ════════════════════════════════════════════════════════════════
   ReconForge SPA - local-first bug-bounty operations console
   Per docs/UI_UX_REDESIGN_SPEC.md
   ════════════════════════════════════════════════════════════════ */

(function () {
"use strict";

// ── State ────────────────────────────────────────────────────────
const state = {
    booted:         false,
    authed:         false,
    user:           null,
    role:           null,
    apiState:       null,             // last /api/state response
    target:         null,             // active target domain
    program:        null,             // program / engagement name
    workspace:      null,             // workspace name
    vaultPath:      null,             // notes vault export root path
    // Declared + backend-enforced scope. inScope/outScope are plain host
    // strings; `active` flips true once /api/scope confirms scope_guard is
    // wired to these exact rules.
    scope:          { program: "", platform: "", inScope: [], outScope: [], active: false },
    surfaceSubs:    null,             // /api/subdomains cache for the Asset Map
    // Pipeline command-center (shell kill chain driven from the app).
    pipeline:       { data: null },   // last /api/pipeline response
    phaseLog:       { phaseId: null, jobId: null, text: "", open: false },
    pipelinePoll:   null,             // fast log/status poll handle (pipeline page)
    freshNext:      false,            // arm a fresh run timestamp for the next phase
    // Agentic pipeline (six-agent LLM chain) command center.
    agents:         { data: null },   // last /api/agent/state response
    agentLog:       { text: "", open: false },
    agentPoll:      null,             // fast status/log poll handle (agents page)
    riskMode:       "passive",        // "passive" | "active" | "aggressive"
    // Intake form draft. Bound to every field on the Intake page and updated
    // on each keystroke so a re-render (e.g. selecting a risk mode) never wipes
    // in-progress input. Seeded from persisted state on boot.
    intakeDraft:    { target: "", program: "", workspace: "", vault: "", scope: "", oos: "" },
    phase:          "target-intake",  // current methodology phase
    guideMode:      false,             // optional helper text toggle
    consoleEvents:  [],
    consoleState:   "expanded",        // "expanded" | "minimized"
    palette:        { open: false, query: "", selected: 0, items: [] },
    pollHandle:     null,
    config:         null,              // /api/config cache (Settings page)
    // ── [agent: toolchain] ── caches for the Toolchain + Workflows pages.
    toolchain:      null,              // { tools, summary, plan, human, loaded } from /api/v2/tools/*
    workflows:      null,              // { list, expanded, detail } from /api/v2/workflows
    // ── [agent: findings] ── findings board state (consumes /api/v2)
    // slug:    resolved active program slug (null until ensureFindings runs)
    // board:   last findings_board payload {columns,counts,total,program_slug}
    // detail:  expanded finding_detail_v2 payload, or null
    // detailId/loadingDetail: which card is open / its in-flight id
    // status:  "idle" | "loading" | "ready" | "noprogram" | "error"
    findings:       { slug: null, board: null, detail: null, detailId: null,
                      loadingDetail: null, status: "idle", error: null },
    // ── [agent: report] ── Report Export workspace (per-platform draft +
    // CVSS calc + quality gate). reportDraft holds the last generated markdown
    // so a re-render (e.g. switching platform pill) repaints the textarea.
    report:         { platform: "", draft: "", gate: null, gateNote: "" },
};

const LS = {
    get(k, fallback) {
        try { const v = localStorage.getItem("rf:" + k); return v === null ? fallback : JSON.parse(v); }
        catch (_) { return fallback; }
    },
    set(k, v) {
        try { localStorage.setItem("rf:" + k, JSON.stringify(v)); } catch (_) {}
    },
};

// ── Navigation config ────────────────────────────────────────────
const NAV = [
    { id: "dashboard", title: "Dashboard", items: [
        { route: "dashboard",   label: "Mission Control" },
    ]},
    { id: "target", title: "Target", items: [
        { route: "intake",      label: "Intake"          },
        { route: "scope",       label: "Scope"           },
    ]},
    { id: "recon", title: "Recon", items: [
        { route: "agents",      label: "AI Agents"       },
        { route: "pipeline",    label: "Run Pipeline"    },
        { route: "workflows",   label: "Workflows"       },   // ── [agent: toolchain] ──
        { route: "passive",     label: "Passive Recon"   },
        { route: "active",      label: "Active Recon"    },
        { route: "urls",        label: "URL Collection"  },
        { route: "js",          label: "JS Mining"       },
    ]},
    { id: "map", title: "Map", items: [
        { route: "surface",     label: "Asset Map"       },
        { route: "fingerprint", label: "Tech Fingerprint" },
        { route: "params",      label: "Parameter Inventory" },
    ]},
    { id: "test", title: "Test", items: [
        { route: "xss",         label: "XSS"             },
        { route: "cors",        label: "CORS"            },
        { route: "lfi",         label: "LFI"             },
        { route: "sqli",        label: "SQLi"            },
        { route: "auth",        label: "Auth / API"      },
        { route: "takeover",    label: "Subdomain Takeover" },
        { route: "exposure",    label: "Sensitive Exposure" },
    ]},
    { id: "evidence", title: "Evidence", items: [
        { route: "findings",    label: "Findings"        },
        { route: "notes",       label: "Notes"           },
        { route: "artifacts",   label: "Artifacts"       },
        { route: "timeline",    label: "Timeline"        },
    ]},
    { id: "report", title: "Report", items: [
        { route: "export",      label: "Export"          },
        { route: "vault",       label: "Vault Sync" },
    ]},
    { id: "ops", title: "Operations", items: [
        { route: "jobs",        label: "Jobs"            },
        { route: "queue",       label: "Queue"           },
        { route: "workers",     label: "Workers"         },
        { route: "monitors",    label: "Monitors"        },
        { route: "resources",   label: "Resources"       },
    ]},
    { id: "admin", title: "Admin", items: [
        { route: "settings",    label: "Settings"        },
        { route: "toolchain",   label: "Toolchain"       },   // ── [agent: toolchain] ──
        { route: "users",       label: "Users"           },
        { route: "backups",     label: "Backups"         },
        { route: "logs",        label: "System Logs"     },
    ]},
];

const KILL_CHAIN = [
    { id: "target",   label: "Target",   routes: ["intake"] },
    { id: "scope",    label: "Scope",    routes: ["scope"] },
    { id: "passive",  label: "Passive",  routes: ["passive", "urls"] },
    { id: "active",   label: "Active",   routes: ["active"] },
    { id: "map",      label: "Map",      routes: ["surface", "fingerprint", "params", "js"] },
    { id: "test",     label: "Test",     routes: ["xss", "cors", "lfi", "sqli", "auth", "takeover", "exposure"] },
    { id: "evidence", label: "Evidence", routes: ["findings", "notes", "artifacts", "timeline"] },
    { id: "report",   label: "Report",   routes: ["export", "vault"] },
];

// ── API helper ───────────────────────────────────────────────────
async function api(method, path, body) {
    const opts = {
        method, credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
    };
    if (body !== undefined) opts.body = JSON.stringify(body);
    let resp;
    try { resp = await fetch(path, opts); }
    catch (e) { return { ok: false, status: 0, error: String(e) }; }
    let data = null;
    try { data = await resp.json(); } catch (_) {}
    return { ok: resp.ok, status: resp.status, data };
}

// ── Bootstrap ────────────────────────────────────────────────────
async function boot() {
    // Restore from localStorage
    state.guideMode      = LS.get("guideMode", false);
    state.consoleState   = LS.get("consoleState", "expanded");
    state.target         = LS.get("target", null);
    state.program        = LS.get("program", null);
    state.workspace      = LS.get("workspace", null);
    state.vaultPath      = LS.get("vaultPath", null);
    state.riskMode       = LS.get("riskMode", "passive");
    state.scope          = LS.get("scope", state.scope) || state.scope;
    // Seed the intake draft so a returning operator sees their saved target +
    // scope (scope/oos mirror the enforced rules as editable text).
    state.intakeDraft.target     = state.target || "";
    state.intakeDraft.program    = state.program || "";
    state.intakeDraft.workspace  = state.workspace || "";
    state.intakeDraft.vault      = state.vaultPath || "";
    state.intakeDraft.scope      = (state.scope.inScope || []).join("\n");
    state.intakeDraft.oos        = (state.scope.outScope || []).join("\n");

    const r = await api("GET", "/api/state");
    if (r.status === 401 || !r.ok) {
        showLogin();
        return;
    }
    state.authed   = true;
    state.apiState = r.data && (r.data.data || r.data);
    state.user     = (state.apiState && state.apiState.session && state.apiState.session.username) || null;
    state.role     = (state.apiState && state.apiState.session && state.apiState.session.role) || null;
    showShell();
    startPolling();
    consoleLog("info", "operator authenticated: " + (state.user || "—"));
}

function showLogin() {
    document.getElementById("login-screen").style.display = "";
    document.getElementById("app-shell").hidden = true;
    const u = document.getElementById("login-user");
    if (u) setTimeout(() => u.focus(), 50);
}

function showShell() {
    document.getElementById("login-screen").style.display = "none";
    document.getElementById("app-shell").hidden = false;
    renderShellChrome();
    renderSidebar();
    renderKillchain();
    renderConsole();
    applyGuideState();
    handleRouteChange();
    state.booted = true;
}

// ── Login ────────────────────────────────────────────────────────
async function login() {
    const u = document.getElementById("login-user").value;
    const p = document.getElementById("login-pass").value;
    const err = document.getElementById("login-error");
    err.textContent = "";
    if (!u || !p) { err.textContent = "Operator and passphrase required."; return; }
    const r = await api("POST", "/api/login", { username: u, password: p });
    if (r.ok && r.data && r.data.success) {
        state.user = u;
        state.role = (r.data.data && r.data.data.role) || null;
        state.authed = true;
        await boot();
    } else {
        err.textContent = (r.data && r.data.message) || "Authentication failed.";
    }
}

async function logout() {
    try { await api("POST", "/api/logout"); } catch (_) {}
    state.authed = false; state.user = null; state.role = null;
    if (state.pollHandle) { clearInterval(state.pollHandle); state.pollHandle = null; }
    stopPipelinePoll();
    stopAgentPoll();
    showLogin();
}

// ── Polling ──────────────────────────────────────────────────────
function startPolling() {
    if (state.pollHandle) clearInterval(state.pollHandle);
    state.pollHandle = setInterval(async () => {
        const r = await api("GET", "/api/state");
        if (r.status === 401) { logout(); return; }
        if (r.ok) {
            state.apiState = r.data && (r.data.data || r.data);
            // Re-render only operational pages, and never while the operator is
            // typing into a field on that page — a poll-driven innerHTML swap
            // would wipe the in-progress input.
            const route = currentRoute();
            const ae = document.activeElement;
            const editing = ae && (ae.tagName === "INPUT" || ae.tagName === "TEXTAREA");
            if (!editing && ["dashboard","jobs","queue","workers","monitors","resources"].includes(route)) {
                renderWorkspace();
            }
            renderKillchain();
        }
    }, 8000);
}

// ── Routing ──────────────────────────────────────────────────────
function currentRoute() {
    const h = (location.hash || "").replace(/^#\/?/, "");
    return h || "intake";
}

function navigateTo(route) {
    location.hash = "#/" + route;
}

window.addEventListener("hashchange", handleRouteChange);

function handleRouteChange() {
    if (!state.authed) return;
    const route = currentRoute();
    state.phase = routeToPhase(route);
    document.querySelectorAll(".sb-item").forEach(el => {
        el.classList.toggle("active", el.dataset.route === route);
    });
    document.getElementById("hdr-phase").textContent = phaseLabel(state.phase);
    renderKillchain();
    renderWorkspace();
    if (route === "settings") ensureConfig();
    if (route === "surface")  ensureSurface();
    if (route === "findings") ensureFindings();   // ── [agent: findings] ──
    if (route === "scope")    ensureScope();
    if (route === "toolchain") ensureToolchain();   // ── [agent: toolchain] ──
    if (route === "workflows") ensureWorkflows();    // ── [agent: toolchain] ──
    if (route === "pipeline") ensurePipeline();
    else                      stopPipelinePoll();
    if (route === "agents")   ensureAgents();
    else                      stopAgentPoll();
}

function routeToPhase(route) {
    if (route === "pipeline") return "pipeline";
    if (route === "agents")   return "agents";
    for (const step of KILL_CHAIN) {
        if (step.routes.includes(route)) return step.id;
    }
    if (["dashboard"].includes(route)) return "dashboard";
    if (["settings","users","backups","logs"].includes(route)) return "admin";
    if (["jobs","queue","workers","monitors","resources"].includes(route)) return "operations";
    return "target";
}

function phaseLabel(phase) {
    return {
        "target":     "target intake",
        "scope":      "scope validation",
        "passive":    "passive recon",
        "active":     "active recon",
        "map":        "asset mapping",
        "test":       "vulnerability testing",
        "evidence":   "evidence collection",
        "report":     "report export",
        "dashboard":  "mission control",
        "operations": "operations",
        "pipeline":   "kill chain",
        "agents":     "ai agents",
        "admin":      "admin",
    }[phase] || phase;
}

// ── Sidebar ──────────────────────────────────────────────────────
function renderSidebar() {
    const el = document.getElementById("sidebar");
    if (!el) return;
    const current = currentRoute();
    let html = "";
    for (const group of NAV) {
        html += `<div class="sb-group">`;
        html += `<div class="sb-group-title">${group.title}</div>`;
        for (const item of group.items) {
            const active = item.route === current;
            const stateMark = sidebarItemState(item.route);
            html += `<div class="sb-item ${active ? "active" : ""}" data-route="${item.route}" onclick="ReconForge.go('${item.route}')">
              <span>${item.label}</span>
              <span class="sb-state" data-s="${stateMark}"></span>
            </div>`;
        }
        html += `</div>`;
    }
    el.innerHTML = html;
}

function sidebarItemState(route) {
    // Simple state derivation. Items can be: current / complete / processing / inactive / error
    if (route === currentRoute()) return "current";
    // Mark "intake" complete if we have a target stored
    if (route === "intake" && state.target) return "complete";
    if (route === "scope"  && state.target && state.workspace) return "complete";
    return "";
}

// ── Header chrome ────────────────────────────────────────────────
function renderShellChrome() {
    document.getElementById("hdr-target").textContent    = state.target    || "—";
    document.getElementById("hdr-workspace").textContent = state.workspace || "—";
    document.getElementById("hdr-user").textContent      = state.user      || "—";
    const risk = document.getElementById("hdr-risk");
    risk.dataset.risk = state.riskMode;
    risk.textContent = state.riskMode.toUpperCase();
    document.getElementById("hdr-phase").textContent = phaseLabel(routeToPhase(currentRoute()));
}

// ── Kill-chain rail ──────────────────────────────────────────────
function renderKillchain() {
    const el = document.getElementById("killchain-rail");
    if (!el) return;
    const route = currentRoute();
    const stepStates = {};
    for (const step of KILL_CHAIN) {
        if (step.routes.includes(route)) stepStates[step.id] = "current";
        else stepStates[step.id] = "";
    }
    // Mark completed steps based on target/workspace presence
    if (state.target) {
        stepStates.target = stepStates.target === "current" ? "current" : "complete";
    }
    if (state.target && state.workspace) {
        stepStates.scope = stepStates.scope === "current" ? "current" : "complete";
    }
    let html = "";
    KILL_CHAIN.forEach((s, i) => {
        const st = stepStates[s.id] || "";
        const click = `ReconForge.go('${s.routes[0]}')`;
        html += `<span class="kc-step" data-state="${st}" onclick="${click}">
          <span class="kc-dot"></span>${s.label}
        </span>`;
        if (i < KILL_CHAIN.length - 1) html += `<span class="kc-sep">›</span>`;
    });
    el.innerHTML = html;
}

// ── Workspace router ─────────────────────────────────────────────
function renderWorkspace() {
    closeAC();   // detach any open autocomplete before we swap the DOM out
    const route = currentRoute();
    const fn = PAGES[route] || pageNotFound(route);
    const html = fn();
    document.getElementById("workspace").innerHTML = html;
}

// ── Page registry ────────────────────────────────────────────────
const PAGES = {};

PAGES.dashboard = function () {
    const s = state.apiState || {};
    const stats   = s.stats || {};
    const running = Array.isArray(s.running_jobs) ? s.running_jobs.length : (s.running_count || 0);
    const queued  = Array.isArray(s.queued_jobs)  ? s.queued_jobs.length  : (s.queued_count || 0);
    const subs    = stats.total_subdomains || 0;
    const targets = stats.total_domains    || 0;
    const findings = stats.total_findings  || 0;

    return `
      ${renderWorkspaceHead("Mission Control", "Dashboard", "")}
      ${renderMetrics([
        { label: "Running Jobs",   value: running,  kind: running ? "processing" : "" },
        { label: "Queued",         value: queued,   kind: queued  ? "processing" : "" },
        { label: "Tracked Targets",value: targets },
        { label: "Subdomains",     value: subs },
        { label: "Findings",       value: findings, kind: findings ? "success" : "" },
        { label: "Risk Mode",      value: state.riskMode.toUpperCase(), kind: state.riskMode === "aggressive" ? "error" : "" },
      ])}
      <div class="workspace-cols">
        <div>
          ${renderTargetStatusPanel()}
          ${panel("Active jobs", running ? renderJobsTable(s.running_jobs || []) : `<div class="tbl-empty">No jobs running. Submit a target from Operations → Jobs.</div>`)}
        </div>
        <div>
          ${renderReconChecklist()}
          ${renderEvidenceTimeline(state.consoleEvents.slice(0, 8))}
        </div>
      </div>
    `;
};

PAGES.intake = function () {
    const d = state.intakeDraft;
    return `
      ${renderWorkspaceHead("Target Intake", "Target", "Define the engagement before recon begins.")}
      <div class="workspace-cols">
        <div>
          ${panel("Engagement", `
            <form onsubmit="event.preventDefault(); ReconForge.saveIntake(); return false;">
              <div class="form-grid">
                <div>
                  <label class="form-label">Target domain</label>
                  <input id="intake-target" type="text" value="${escapeAttr(d.target)}" placeholder="example.com" spellcheck="false">
                </div>
                <div>
                  <label class="form-label">Program name</label>
                  <input id="intake-program" type="text" value="${escapeAttr(d.program)}" placeholder="Acme Corp" spellcheck="false">
                </div>
                <div>
                  <label class="form-label">Workspace name</label>
                  <input id="intake-workspace" type="text" value="${escapeAttr(d.workspace)}" placeholder="acme-com" spellcheck="false">
                </div>
                <div>
                  <label class="form-label">Vault path</label>
                  <input id="intake-vault" type="text" value="${escapeAttr(d.vault)}" placeholder="ResearchVault/BugBounty/acme.com">
                </div>
                <div class="full">
                  <label class="form-label">Scope rules</label>
                  <textarea id="intake-scope" rows="3" placeholder="*.example.com&#10;api.example.com&#10;app.example.com" style="width:100%; font-family: var(--font-mono);">${escapeHTML(d.scope)}</textarea>
                </div>
                <div class="full">
                  <label class="form-label">Out of scope</label>
                  <textarea id="intake-oos" rows="2" placeholder="careers.example.com&#10;status.example.com" style="width:100%; font-family: var(--font-mono);">${escapeHTML(d.oos)}</textarea>
                </div>
                <div class="full">
                  <label class="form-label">Risk mode</label>
                  <div class="radio-row">
                    ${riskPill("passive",     "Passive only",                state.riskMode === "passive")}
                    ${riskPill("active",      "Passive + Active",            state.riskMode === "active")}
                    ${riskPill("aggressive",  "Full authorized testing",     state.riskMode === "aggressive")}
                  </div>
                </div>
              </div>
              <div class="spacer-md"></div>
              <div style="display:flex; gap:8px;">
                <button type="submit" class="btn btn-primary">▸ Load Target</button>
                <button type="button" class="btn btn-ghost" onclick="ReconForge.clearIntake()">Reset</button>
              </div>
            </form>
          `)}
          ${state.guideMode ? guidePanel("Why this matters", "Defining the target, scope, and risk posture before any probing aligns every downstream command with the authorization boundary. The Risk Mode selector classifies which workflows surface in the methodology panes; scope_guard still enforces program scope on every tool dispatch.") : ""}
        </div>
        <div>
          ${renderTargetStatusPanel()}
          ${panel("Operator", `
            <div class="status-panel">
              <dt>Operator</dt><dd>${escapeHTML(state.user || "—")} <span class="badge badge-muted">${escapeHTML(state.role || "—")}</span></dd>
              <dt>Workspace</dt><dd>${escapeHTML(state.workspace || "—")}</dd>
              <dt>Export root</dt><dd class="mono" style="font-size:11px;">${escapeHTML(state.vaultPath || "—")}</dd>
            </div>
          `)}
        </div>
      </div>
    `;
};

PAGES.scope = function () {
    const sc = state.scope || { inScope: [], outScope: [], active: false };
    const inList  = (sc.inScope  || []).slice();
    const outList = (sc.outScope || []).slice();
    const enforced = !!sc.active && !!state.target;
    const enfBadge = enforced
        ? `<span class="badge badge-success">ENFORCED</span>`
        : `<span class="badge badge-muted">NOT WIRED</span>`;
    return `
      ${renderWorkspaceHead("Scope Validation", "Target", "Confirm authorization before any active probe.")}
      <div class="workspace-cols">
        <div>
          ${renderTargetStatusPanel()}
          ${panel(`Declared scope ${enfBadge}`, `
            <div class="mono" style="font-size:12px;">
              <div class="text-success">in scope (${inList.length})</div>
              <ul class="scope-list">
                ${inList.length ? inList.map(s => `<li>• ${escapeHTML(s)}</li>`).join("")
                                : `<li class="text-mute">— load a target first</li>`}
              </ul>
              <div class="muted-line"></div>
              <div class="text-error">out of scope (${outList.length})</div>
              <ul class="scope-list text-mute">
                ${outList.length ? outList.map(s => `<li>• ${escapeHTML(s)}</li>`).join("")
                                 : `<li>(none declared)</li>`}
              </ul>
            </div>
          `)}
          ${panel("Edit scope", `
            <div class="form-grid">
              <div class="full">
                <label class="form-label">In scope — one host/wildcard/CIDR per line</label>
                <textarea id="scope-in" rows="4" class="mono" style="width:100%;" spellcheck="false"
                  placeholder="*.example.com&#10;example.com&#10;203.0.113.0/24">${escapeHTML(inList.join("\n"))}</textarea>
              </div>
              <div class="full">
                <label class="form-label">Out of scope — wins over in-scope on conflict</label>
                <textarea id="scope-out" rows="3" class="mono" style="width:100%;" spellcheck="false"
                  placeholder="careers.example.com&#10;*.dev.example.com">${escapeHTML(outList.join("\n"))}</textarea>
              </div>
            </div>
            <div class="spacer-md"></div>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
              <button class="btn btn-primary" onclick="ReconForge.saveScope()" ${state.target ? "" : "disabled"}>▸ Save &amp; enforce scope</button>
              <button class="btn btn-ghost" onclick="ReconForge.go('passive')">Proceed to Passive Recon →</button>
            </div>
            ${state.target ? "" : `<div class="form-help">Load a target on the Intake page first.</div>`}
          `)}
        </div>
        <div>
          ${panel("Scope guard", `
            <div class="status-panel">
              <dt>Enforcement</dt><dd>${enforced
                  ? `<span class="badge badge-success">ACTIVE</span>`
                  : `<span class="badge badge-muted">PENDING</span>`}</dd>
              <dt>Active program</dt><dd class="mono" style="font-size:11px;">${escapeHTML(sc.programPath || (enforced ? "scopes/…json" : "—"))}</dd>
              <dt>Module</dt><dd class="mono" style="font-size:11px;">scope_guard.py</dd>
              <dt>Hook</dt><dd>per-tool dispatch</dd>
              <dt>OOS Action</dt><dd><span class="badge badge-error">REFUSE</span></dd>
            </div>
            <div class="form-help">${enforced
                ? "scope_guard validates every dispatched target against these exact rules before any subprocess spawns. Out-of-scope wins over in-scope. This UI cannot override that check."
                : "Scope is declared but not yet wired to the backend. Click <span class=\"mono\">Save &amp; enforce scope</span> to push these rules to scope_guard so they gate every job and tool."}</div>
          `)}
          ${state.guideMode ? guidePanel("Why wire scope", "A wildcard (*.example.com) does NOT include the apex example.com unless you list it. Out-of-scope entries always win over an in-scope match — so a single careers.example.com line will block that host even though it also matches *.example.com.") : ""}
        </div>
      </div>
    `;
};

PAGES.passive = function () { return renderMethodologyPage("passive", "Passive Recon", "Recon", "passive", [
    { label: "subfinder all-source",  cmd: `subfinder -d ${tgt()} -all -recursive -silent -o subs/sf.txt`, risk: "passive", note: "Expand the target surface from public passive sources." },
    { label: "amass passive",         cmd: `amass enum -passive -d ${tgt()} -o subs/am.txt`, risk: "passive" },
    { label: "github-subdomains",     cmd: `github-subdomains -d ${tgt()} -t $GITHUB_TOKEN -e -raw -o subs/gh.txt`, risk: "passive" },
    { label: "crt.sh certificate transparency", cmd: `curl -s "https://crt.sh/?q=%25.${tgt()}&output=json" | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u > subs/crt.txt`, risk: "passive" },
]); };

PAGES.active = function () { return renderMethodologyPage("active", "Active Recon", "Recon", "active", [
    { label: "puredns resolve",   cmd: `puredns resolve subs/all.txt -r resolvers.txt --rate-limit 1000 -w resolved.txt`, risk: "active" },
    { label: "naabu top-1000",    cmd: `naabu -l resolved.txt -tp 1000 -rate 5000 -silent -o ports.txt`, risk: "active" },
    { label: "httpx enrichment",  cmd: `httpx -l ports.txt -silent -title -tech-detect -status-code -follow-redirects -ip -cname -cdn -jarm -j -o httpx.jsonl`, risk: "active" },
]); };

PAGES.urls = function () { return renderMethodologyPage("urls", "URL Collection", "Recon", "passive", [
    { label: "gau archive harvest",    cmd: `echo ${tgt()} | gau --subs --threads 200 | anew gau.txt`, risk: "passive" },
    { label: "waybackurls",            cmd: `echo ${tgt()} | waybackurls | anew way.txt`, risk: "passive" },
    { label: "extract parameter keys", cmd: `cat urls.txt | unfurl -u keys | sort -u > params.txt`, risk: "passive" },
]); };

PAGES.js = function () { return renderMethodologyPage("js", "JavaScript Mining", "Map", "active", [
    { label: "jsluice URL extraction",    cmd: `for f in js-bodies/*.js; do jsluice urls "$f"; done | sort -u > js-urls.txt`, risk: "active", note: "Surface hardcoded endpoints + API paths from bundled JS." },
    { label: "jsluice secret extraction", cmd: `for f in js-bodies/*.js; do jsluice secrets "$f"; done > js-secrets.jsonl`, risk: "passive" },
    { label: "trufflehog filesystem",     cmd: `trufflehog filesystem ./js-bodies --json --no-update --only-verified > trufflehog.jsonl`, risk: "passive" },
]); };

PAGES.surface = function () {
    const sc   = state.scope || {};
    const apex = state.target || "target";
    // Concrete declared hosts (skip wildcards, the apex itself, and CIDRs).
    const declared  = (sc.inScope || []).filter(h => h && !h.startsWith("*.") && h !== apex && h.indexOf("/") === -1);
    const wildcards = (sc.inScope || []).filter(h => h && h.startsWith("*."));
    const discovered = state.surfaceSubs;   // null = loading, [] = none yet

    const nodes = new Map();
    declared.forEach(h => nodes.set(h, { host: h, src: "scope" }));
    if (Array.isArray(discovered)) {
        discovered.forEach(s => {
            const h = (s.subdomain || s.domain || s || "").toString();
            if (!h) return;
            const prev = nodes.get(h);
            nodes.set(h, { host: h, src: prev ? "both" : "recon",
                           status: s.http_status, title: s.http_title, interesting: s.interesting });
        });
    }
    const list = [...nodes.values()].sort((a, b) => a.host.localeCompare(b.host));

    let tree;
    if (discovered === null && !declared.length) {
        tree = `<span class="surface-mute">resolving surface…</span>`;
    } else if (!list.length && !wildcards.length) {
        tree = `<span class="surface-host">${escapeHTML(apex)}</span>\n` +
               `<span class="surface-mute">└── (no hosts yet — declare scope or run a job)</span>`;
    } else {
        tree = `<span class="surface-host">${escapeHTML(apex)}</span>`;
        wildcards.forEach(w => {
            tree += `\n<span class="surface-mute">├──</span> <span class="surface-path">${escapeHTML(w)}</span> <span class="surface-mute">(wildcard)</span>`;
        });
        list.forEach((n, i) => {
            const branch = (i === list.length - 1) ? "└──" : "├──";
            tree += `\n<span class="surface-mute">${branch}</span> <span class="surface-host">${escapeHTML(n.host)}</span>${surfaceTag(n)}`;
        });
    }
    const discCount = Array.isArray(discovered) ? discovered.length : 0;
    const liveCount = Array.isArray(discovered) ? discovered.filter(s => s.http_status).length : 0;
    return `
      ${renderWorkspaceHead("Asset Map", "Map", "Hosts from your declared scope + everything recon has discovered.")}
      ${renderMetrics([
        { label: "Declared hosts", value: declared.length },
        { label: "Discovered",     value: discCount, kind: discCount ? "processing" : "" },
        { label: "Live (HTTP)",    value: liveCount, kind: liveCount ? "success" : "" },
      ])}
      ${panel(`Surface tree — ${escapeHTML(apex)}`, `
        <div class="surface-tree">${tree}</div>
        <div class="surface-actions">
          <button class="btn btn-sm btn-ghost" onclick="ReconForge.refreshSurface()">↻ Refresh</button>
          <button class="btn btn-sm btn-ghost" onclick="ReconForge.go('jobs')">Run a scan →</button>
        </div>
      `)}
      ${state.guideMode ? guidePanel("Where these come from", "Declared hosts are the concrete in-scope entries you typed on the Scope page (wildcards are shown but not expanded). Discovered hosts come from completed pipeline jobs — subfinder/httpx/etc. — via /api/subdomains. Submit a scan on the Jobs tab to populate them.") : ""}
    `;
};

function surfaceTag(n) {
    if (n.status) {
        const cls = n.status < 300 ? "success" : (n.status < 400 ? "processing" : (n.status < 500 ? "muted" : "error"));
        const bang = n.interesting ? ` <span class="badge badge-error">!</span>` : "";
        return ` <span class="badge badge-${cls}">${n.status}</span>${bang}`;
    }
    return ` <span class="badge badge-muted">${n.src === "scope" ? "scope" : "found"}</span>`;
}

async function ensureSurface() {
    if (!state.target) { state.surfaceSubs = []; if (currentRoute() === "surface") renderWorkspace(); return; }
    const r = await api("GET", "/api/subdomains/" + encodeURIComponent(state.target));
    state.surfaceSubs = (r.ok && r.data) ? (r.data.data || r.data || []) : [];
    if (currentRoute() === "surface") renderWorkspace();
}

function refreshSurface() {
    state.surfaceSubs = null;
    renderWorkspace();
    ensureSurface();
}

PAGES.fingerprint = function () { return renderMethodologyPage("fingerprint", "Tech Fingerprint", "Map", "active", [
    { label: "httpx tech-detect (full)", cmd: `httpx -l alive.txt -tech-detect -title -server -jarm -json -o httpx-tech.jsonl`, risk: "active" },
    { label: "tlsx SAN/CN harvest",      cmd: `tlsx -l hosts.txt -san -cn -silent -resp-only -o tls.txt`, risk: "active" },
    { label: "cdncheck classification",  cmd: `cdncheck -i ips.txt -resp -o cdn.txt`, risk: "passive" },
]); };

PAGES.params = function () { return renderMethodologyPage("params", "Parameter Inventory", "Map", "active", [
    { label: "arjun behavioral diff",    cmd: `arjun -i alive.txt -t 10 --rate-limit 5 -oT arjun-params.txt`, risk: "active", note: "Behavioral diff is slow but accurate. Throttle aggressively." },
    { label: "paramspider archives",     cmd: `paramspider -d ${tgt()} -s | anew paramspider.txt`, risk: "passive", note: "ParamSpider v3 dropped --exclude/--output; -s streams URLs to stdout (also saved to results/)." },
    { label: "x8 hidden parameters",     cmd: `x8 -u https://${tgt()} -w $WORDLIST_DIR/burp-parameter-names.txt --output-format url`, risk: "active" },
]); };

PAGES.xss = function () { return renderMethodologyPage("xss", "XSS", "Test", "active", [
    { label: "Gxss reflection sieve",   cmd: `cat gf-xss.txt | Gxss -p Xss -c 100`, risk: "active" },
    { label: "dalfox pipeline",         cmd: `cat reflectors.txt | dalfox pipe -b $BLIND_XSS_URL --silence -o xss-results.txt`, risk: "aggressive" },
    { label: "hard-confirm grep",       cmd: `cat reflectors.txt | qsreplace '"><script>alert(1)</script>' | while read u; do curl -s --path-as-is --insecure "$u" | grep -qs '<script>alert(1)</script>' && echo "VULN: $u"; done`, risk: "aggressive", note: "Triggers on verbatim payload reflection. Zero false positives." },
]); };

PAGES.cors = function () { return renderMethodologyPage("cors", "CORS", "Test", "active", [
    { label: "nuclei CORS templates", cmd: `nuclei -l alive.txt -tags cors -severity medium,high -rl 50 -c 5 -jsonl -o cors.jsonl`, risk: "active" },
    { label: "Origin reflection probe", cmd: `for u in $(cat alive.txt); do curl -sIH "Origin: https://evil.example" "$u" | grep -i "access-control-allow-origin: https://evil.example" && echo "REFLECTED $u"; done`, risk: "active" },
]); };

PAGES.lfi = function () { return renderMethodologyPage("lfi", "LFI", "Test", "aggressive", [
    { label: "/etc/passwd probe",   cmd: `cat gf-lfi.txt | qsreplace "/etc/passwd" | xargs -I% -P25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "LFI %"'`, risk: "aggressive" },
    { label: "PHP wrappers",        cmd: `cat gf-lfi.txt | qsreplace "php://filter/convert.base64-encode/resource=index"`, risk: "aggressive" },
]); };

PAGES.sqli = function () { return renderMethodologyPage("sqli", "SQLi", "Test", "aggressive", [
    { label: "sqlmap from gf list",       cmd: `sed 's/=[^&]*/=FUZZ/g' gf-sqli.txt | sort -u | sqlmap -m - --batch --random-agent --level 5 --risk 3 --dbs`, risk: "aggressive", note: "Intrusive. Confirm program rules on automated SQLi before firing." },
    { label: "tamper stack (WAF bypass)", cmd: `sqlmap -u "URL" -p param --tamper=between,randomcase,space2comment,charunicodeencode --random-agent`, risk: "aggressive" },
]); };

PAGES.auth = function () { return renderMethodologyPage("auth", "Auth / API", "Test", "active", [
    { label: "JWT alg=none probe",   cmd: `# Strip signature, send forged payload\\npython3 -c "import attack.jwt as j; print(j.run('${tgt()}', {'token': '$TOKEN', 'endpoint': '$ENDPOINT'}).to_dict())"`, risk: "active" },
    { label: "GraphQL introspection",cmd: `curl -sS -X POST "https://${tgt()}/graphql" -H 'Content-Type: application/json' -d '{"query":"{__schema{types{name}}}"}'`, risk: "passive" },
    { label: "Two-account IDOR diff",cmd: `bash scripts/vuln/idor.sh   # AUTH_A and AUTH_B required`, risk: "active" },
]); };

PAGES.takeover = function () { return renderMethodologyPage("takeover", "Subdomain Takeover", "Test", "active", [
    { label: "nuclei takeover sweep", cmd: `nuclei -l subs/all.txt -tags takeover -severity high,critical -rl 50 -c 5 -jsonl -o takeover.jsonl`, risk: "active" },
    { label: "manual CNAME audit",    cmd: `dnsx -l subs/all.txt -cname -silent -resp | grep -iE 'github\\.io|herokuapp|s3\\.amazonaws|cloudfront|fastly|azurewebsites|netlify'`, risk: "passive" },
]); };

PAGES.exposure = function () { return renderMethodologyPage("exposure", "Sensitive Exposure", "Test", "passive", [
    { label: "nuclei exposure tags", cmd: `nuclei -l alive.txt -tags exposure,config,backup,git -severity medium,high,critical -jsonl -o exposure.jsonl`, risk: "active" },
    { label: "archive interesting files", cmd: `gau ${tgt()} | grep -iE "\\.(env|bak|sql|tar\\.gz|7z|backup|secret|config|log)$" > interesting.txt`, risk: "passive" },
]); };

// ── [agent: findings] ─────────────────────────────────────────────
// Findings board — consumes the /api/v2 findings API. The page itself is a
// PURE render over state.findings (loaded by ensureFindings); status enum +
// transitions come from the backend (core/findings.py) via finding_detail_v2,
// never invented here.
const FINDINGS_COLUMNS = [
    // Canonical Kanban order from core/findings.py KANBAN_COLUMNS, plus the
    // analyst-flagged "dup" bucket the board tracks separately.
    { key: "new",            label: "New",            kind: "processing" },
    { key: "needs_review",   label: "Needs Review",   kind: "processing" },
    { key: "confirmed",      label: "Confirmed",      kind: "success"    },
    { key: "draft_ready",    label: "Draft Ready",    kind: "success"    },
    { key: "submitted",      label: "Submitted",      kind: "success"    },
    { key: "retesting",      label: "Retesting",      kind: "processing" },
    { key: "closed",         label: "Closed",         kind: "muted"      },
    { key: "false_positive", label: "False Positive", kind: "error"      },
    { key: "dup",            label: "Duplicate",      kind: "muted"      },
];

function findingStatusLabel(s) {
    const c = FINDINGS_COLUMNS.find(c => c.key === s);
    return c ? c.label : String(s || "—").replace(/_/g, " ");
}
function findingStatusBadge(s) {
    const c = FINDINGS_COLUMNS.find(c => c.key === s);
    return `<span class="badge badge-${c ? c.kind : "muted"}">${escapeHTML(findingStatusLabel(s))}</span>`;
}
// CVSS score → severity band (CVSS 3.1/4.0 cutoffs) for the card badge.
function severityFromCvss(score) {
    const n = Number(score);
    if (!isFinite(n) || n <= 0) return { label: "—", kind: "muted" };
    if (n >= 9.0) return { label: "CRIT " + n.toFixed(1), kind: "error" };
    if (n >= 7.0) return { label: "HIGH " + n.toFixed(1), kind: "error" };
    if (n >= 4.0) return { label: "MED " + n.toFixed(1),  kind: "processing" };
    return { label: "LOW " + n.toFixed(1), kind: "muted" };
}
function confidenceBadge(label) {
    const kind = label === "high" ? "success" : (label === "medium" ? "processing" : "muted");
    return `<span class="badge badge-${kind}">${escapeHTML((label || "low") + " conf")}</span>`;
}

PAGES.findings = function () {
    const f  = state.findings || {};
    const st = f.status;

    // Empty / transient states — friendly, never throws.
    if (st === "loading" || st === "idle") {
        return `
          ${renderWorkspaceHead("Findings", "Evidence", "Confirmed and in-review findings.")}
          ${panel("Findings board", `<div class="tbl-empty">Loading findings…</div>`)}
        `;
    }
    if (st === "noprogram") {
        return `
          ${renderWorkspaceHead("Findings", "Evidence", "Confirmed and in-review findings.")}
          ${panel("Findings board", `<div class="tbl-empty">No program selected yet. Define a target + scope on the <span class="mono">Intake</span> / <span class="mono">Scope</span> pages, then findings for that program appear here.</div>`)}
          ${state.guideMode ? guidePanel("Pipeline", "Findings are filtered to the active program's scope. The board resolves the program slug from your workspace/target (or /api/scope) and reads GET /api/v2/programs/<slug>/findings_board.") : ""}
        `;
    }
    if (st === "error") {
        return `
          ${renderWorkspaceHead("Findings", "Evidence", "Confirmed and in-review findings.")}
          ${panel("Findings board", `
            <div class="tbl-empty">Couldn't load findings${f.error ? " — " + escapeHTML(f.error) : "."}</div>
            <div class="findings-actions"><button class="btn btn-sm btn-ghost" onclick="ReconForge.refreshFindings()">↻ Retry</button></div>
          `)}
        `;
    }

    const board   = f.board || {};
    const columns = board.columns || {};
    const counts  = board.counts || {};
    const total   = board.total || 0;
    const slug    = f.slug || board.program_slug || "—";

    // Summary metrics: total + a count per non-empty status column.
    const metrics = [{ label: "Total", value: total, kind: total ? "success" : "" }];
    FINDINGS_COLUMNS.forEach(c => {
        const n = counts[c.key] || 0;
        if (n) metrics.push({ label: c.label, value: n, kind: c.kind === "muted" ? "" : c.kind });
    });

    let boardHTML;
    if (!total) {
        boardHTML = `<div class="tbl-empty">No findings for <span class="mono">${escapeHTML(slug)}</span> yet. They'll appear here as the pipeline + agent layer produce them.</div>`;
    } else {
        // One section per status column that has cards. Columns with a count
        // but no cards (truncated by limit_per_column) still show a header.
        boardHTML = `<div class="findings-board">` + FINDINGS_COLUMNS.map(c => {
            const cards = Array.isArray(columns[c.key]) ? columns[c.key] : [];
            const n = counts[c.key] || 0;
            if (!n && !cards.length) return "";
            return `
              <section class="findings-col">
                <div class="findings-col-head">
                  <span class="findings-col-title">${escapeHTML(c.label)}</span>
                  <span class="badge badge-${c.kind}">${n}</span>
                </div>
                ${cards.length
                    ? cards.map(renderFindingCard).join("")
                    : `<div class="findings-col-empty">${n} hidden (limit)</div>`}
              </section>`;
        }).join("") + `</div>`;
    }

    return `
      ${renderWorkspaceHead("Findings", "Evidence", "Findings for " + escapeHTML(slug) + " — grouped by triage status.")}
      ${renderMetrics(metrics)}
      ${panel(`Findings board · ${escapeHTML(slug)}`, `
        <div class="findings-actions">
          <button class="btn btn-sm btn-ghost" onclick="ReconForge.refreshFindings()">↻ Refresh</button>
        </div>
        ${boardHTML}
      `)}
      ${state.guideMode ? guidePanel("Pipeline", "Confirmed findings flow: pipeline/agents -> /api/v2 findings -> this board. Select a card to inspect evidence + change status. Status moves new -> needs_review -> confirmed -> draft_ready -> submitted -> closed.") : ""}
    `;
};

// One finding card. When this card is the selected one, its detail panel
// (finding_detail_v2 + evidence + status controls) renders inline beneath it.
function renderFindingCard(card) {
    if (!card) return "";
    const id   = card.id;
    const open = state.findings && state.findings.detailId === id;
    const sev  = severityFromCvss(card.cvss_score);
    const bounty = card.bounty_estimate_usd
        ? `<span class="finding-bounty">$${escapeHTML(String(card.bounty_estimate_usd))}</span>` : "";
    const drafts = card.draft_count
        ? `<span class="badge badge-muted">${card.draft_count} draft${card.draft_count === 1 ? "" : "s"}</span>` : "";
    return `
      <div class="finding-card ${open ? "open" : ""}" onclick="ReconForge.selectFinding(${id})">
        <div class="finding-card-top">
          <span class="badge badge-${sev.kind}">${escapeHTML(sev.label)}</span>
          ${card.vuln_class ? `<span class="finding-vclass mono">${escapeHTML(card.vuln_class)}</span>` : ""}
          ${bounty}
        </div>
        <div class="finding-title">${escapeHTML(card.title || ("Finding #" + id))}</div>
        <div class="finding-card-meta">
          ${card.domain ? `<span class="mono finding-asset">${escapeHTML(card.domain)}</span>` : ""}
          ${confidenceBadge(card.confidence_label)}
          ${drafts}
        </div>
      </div>
      ${open ? renderFindingDetail(id) : ""}
    `;
}

// Inline detail + evidence panel for the selected finding.
function renderFindingDetail(id) {
    const f = state.findings || {};
    if (f.loadingDetail === id && (!f.detail || f.detail.id !== id)) {
        return `<div class="finding-detail"><div class="tbl-empty">Loading finding #${id}…</div></div>`;
    }
    const d = f.detail;
    if (!d || d.id !== id) {
        return `<div class="finding-detail"><div class="tbl-empty">Detail unavailable.
          <button class="btn btn-sm btn-ghost" onclick="event.stopPropagation(); ReconForge.selectFinding(${id})">↻ Retry</button></div></div>`;
    }

    // Status controls: forward transitions are surfaced as primary buttons;
    // the full allowed set (minus current) is offered for overrides. Both
    // come straight from the backend enum — nothing invented client-side.
    const cur      = d.status;
    const forward  = Array.isArray(d.forward_transitions) ? d.forward_transitions : [];
    const allowed  = Array.isArray(d.valid_statuses) ? d.valid_statuses : [];
    const others   = allowed.filter(s => s !== cur && forward.indexOf(s) === -1);
    const fwdBtns  = forward.map(s =>
        `<button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); ReconForge.setFindingStatus(${id}, '${escapeAttr(s)}')">→ ${escapeHTML(findingStatusLabel(s))}</button>`
    ).join("");
    const otherBtns = others.map(s =>
        `<button class="btn btn-sm btn-ghost" onclick="event.stopPropagation(); ReconForge.setFindingStatus(${id}, '${escapeAttr(s)}')">${escapeHTML(findingStatusLabel(s))}</button>`
    ).join("");

    return `
      <div class="finding-detail" onclick="event.stopPropagation();">
        <div class="finding-detail-head">
          <div>
            <span class="finding-detail-id mono">#${id}${d.bug_id ? " · " + escapeHTML(d.bug_id) : ""}</span>
            ${findingStatusBadge(cur)}
          </div>
          <button class="btn btn-sm btn-ghost" onclick="ReconForge.closeFinding()">✕ Close</button>
        </div>
        <div class="finding-detail-grid">
          <div><span class="kv-k">Vuln class</span><span class="kv-v mono">${escapeHTML(d.vuln_class || "—")}</span></div>
          <div><span class="kv-k">Asset</span><span class="kv-v mono">${escapeHTML(d.domain || "—")}</span></div>
          <div><span class="kv-k">CVSS</span><span class="kv-v">${d.cvss_score != null ? escapeHTML(String(d.cvss_score)) : "—"}${d.cvss_vector ? ` <span class="mono text-sec">${escapeHTML(d.cvss_vector)}</span>` : ""}</span></div>
          <div><span class="kv-k">Bounty est.</span><span class="kv-v">${d.bounty_estimate_usd ? "$" + escapeHTML(String(d.bounty_estimate_usd)) : "—"}</span></div>
        </div>
        ${d.description ? `<div class="finding-desc">${escapeHTML(d.description)}</div>` : ""}
        <div class="finding-status-controls">
          <span class="kv-k">Set status</span>
          <div class="finding-status-btns">${fwdBtns || ""}${otherBtns || ""}${(!fwdBtns && !otherBtns) ? `<span class="text-sec">terminal state</span>` : ""}</div>
        </div>
        ${renderFindingEvidence(id, d.evidence, d.readiness)}
      </div>
    `;
}

// Evidence bands (observed / inferred / ai_hypothesis / verified). Only
// ai_hypothesis rows get a verify action — matches core/evidence.py rules.
function renderFindingEvidence(id, evidence, readiness) {
    const ev = evidence || {};
    const bands = [
        { key: "observed",      label: "Observed",      kind: "success"    },
        { key: "inferred",      label: "Inferred",      kind: "processing" },
        { key: "ai_hypothesis", label: "AI Hypothesis", kind: "error"      },
        { key: "verified",      label: "Verified",      kind: "success"    },
    ];
    const total = bands.reduce((n, b) => n + (Array.isArray(ev[b.key]) ? ev[b.key].length : 0), 0);

    let readyHTML = "";
    if (readiness && typeof readiness === "object") {
        const labels = {
            affected_url: "Affected URL", reproduction_steps: "Repro steps",
            impact: "Impact", remediation: "Remediation", screenshot: "Screenshot",
        };
        const keys = Object.keys(readiness);
        if (keys.length) {
            readyHTML = `<div class="evidence-readiness">` + keys.map(k => {
                const ok = !!readiness[k];
                return `<span class="rdy ${ok ? "ok" : "no"}">${ok ? "✓" : "✗"} ${escapeHTML(labels[k] || k)}</span>`;
            }).join("") + `</div>`;
        }
    }

    let bodyHTML;
    if (!total) {
        bodyHTML = `<div class="tbl-empty">No structured evidence recorded yet.</div>`;
    } else {
        bodyHTML = bands.map(b => {
            const rows = Array.isArray(ev[b.key]) ? ev[b.key] : [];
            if (!rows.length) return "";
            return `
              <div class="evidence-band" data-src="${b.key}">
                <div class="evidence-band-head"><span class="badge badge-${b.kind}">${escapeHTML(b.label)}</span><span class="text-sec">${rows.length}</span></div>
                ${rows.map(r => renderEvidenceRow(id, b.key, r)).join("")}
              </div>`;
        }).join("");
    }
    return `
      <div class="finding-evidence">
        <div class="finding-evidence-head"><span class="kv-k">Evidence</span>${readyHTML}</div>
        ${bodyHTML}
      </div>
    `;
}

function renderEvidenceRow(findingId, source, row) {
    if (!row) return "";
    let val = row.value;
    if (val != null && typeof val === "object") {
        try { val = JSON.stringify(val); } catch (_) { val = String(val); }
    }
    const verified = source === "verified" || !!row.verified_by;
    // Only ai_hypothesis rows are promotable to verified (core/evidence.py).
    const canVerify = source === "ai_hypothesis";
    return `
      <div class="evidence-row">
        <div class="evidence-row-main">
          <span class="evidence-key mono">${escapeHTML(row.key || "—")}</span>
          <span class="evidence-val mono">${escapeHTML(val == null ? "" : String(val))}</span>
        </div>
        <div class="evidence-row-side">
          ${verified && row.verified_by ? `<span class="badge badge-success">✓ ${escapeHTML(row.verified_by)}</span>` : ""}
          ${canVerify ? `<button class="btn btn-sm btn-ghost" onclick="event.stopPropagation(); ReconForge.verifyFindingEvidence(${findingId}, ${row.id})">Verify</button>` : ""}
        </div>
      </div>
    `;
}

// Resolve the active program slug, then load its findings board.
// Slug resolution order: (1) match a program from /api/v2/programs against
// workspace/target/program; (2) fall back to /api/scope program name +
// slugify (same regex as core/programs.slugify).
async function ensureFindings() {
    const f = state.findings;
    f.status = "loading";
    if (currentRoute() === "findings") renderWorkspace();

    const slug = await resolveProgramSlug();
    if (!slug) {
        f.slug = null; f.board = null; f.status = "noprogram";
        if (currentRoute() === "findings") renderWorkspace();
        return;
    }
    f.slug = slug;
    const r = await api("GET", "/api/v2/programs/" + encodeURIComponent(slug) + "/findings_board");
    // v2 endpoints return the payload at the top level (no _ok data.data wrap).
    if (r.ok && r.data && r.data.columns) {
        f.board = r.data; f.status = "ready"; f.error = null;
    } else if (r.status === 404) {
        // Program slug didn't resolve server-side — treat as no-program.
        f.board = null; f.status = "noprogram";
    } else {
        f.board = null; f.status = "error";
        f.error = (r.data && r.data.error) || ("HTTP " + r.status);
    }
    if (currentRoute() === "findings") renderWorkspace();
}

// Slugify identical to core/programs.slugify: lowercase, non-[a-z0-9-] runs
// → "-", trim leading/trailing "-".
function slugifyName(name) {
    const s = String(name || "").trim().toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "");
    return s || "program";
}

async function resolveProgramSlug() {
    // Fast path: the bridged slug carried back on /api/scope (POST or GET) — the
    // exact v2 `programs` row scope-save wrote, so no slugify-parity guessing.
    if (state.scope && state.scope.programSlug) return state.scope.programSlug;
    // Candidate names from current engagement state.
    const wantNames = [state.workspace, state.program, (state.scope && state.scope.program), state.target]
        .filter(Boolean).map(s => String(s).toLowerCase());
    const wantSlugs = wantNames.map(slugifyName);

    const r = await api("GET", "/api/v2/programs");
    const list = (r.ok && r.data && Array.isArray(r.data.programs)) ? r.data.programs : [];
    if (list.length) {
        // 1. Exact slug match, then name match, against our candidates.
        for (const p of list) {
            const pslug = (p.slug || "").toLowerCase();
            const pname = (p.name || "").toLowerCase();
            if (wantSlugs.indexOf(pslug) !== -1) return p.slug;
            if (wantNames.indexOf(pname) !== -1) return p.slug;
            if (wantSlugs.indexOf(slugifyName(pname)) !== -1) return p.slug;
        }
        // 2. No engagement context but exactly one program exists → use it.
        if (!wantNames.length && list.length === 1) return list[0].slug;
    }

    // 3. Fall back to /api/scope program name (this is _ok-wrapped → data.data).
    const sc = await api("GET", "/api/scope");
    const scd = (sc.ok && sc.data) ? (sc.data.data || sc.data) : null;
    const progName = scd && scd.program && scd.program.name;
    if (progName) {
        const slug = slugifyName(progName);
        // Prefer an actual program row whose slug matches, else return the
        // slugified name (findings_board 404s cleanly if it doesn't exist).
        const hit = list.find(p => (p.slug || "").toLowerCase() === slug);
        return hit ? hit.slug : slug;
    }
    return null;
}

function refreshFindings() {
    const f = state.findings;
    f.board = null; f.detail = null; f.detailId = null;
    f.status = "loading";
    renderWorkspace();
    ensureFindings();
}

// Select a finding card → load finding_detail_v2 (bundles evidence + taxonomy
// + valid_statuses + forward_transitions in one round-trip).
async function selectFinding(id) {
    const f = state.findings;
    if (f.detailId === id && f.detail && f.detail.id === id) return;  // already open
    f.detailId = id; f.loadingDetail = id; f.detail = null;
    renderWorkspace();
    const r = await api("GET", "/api/v2/findings/" + encodeURIComponent(id));
    // Guard against a race: operator clicked another card while this loaded.
    if (state.findings.detailId !== id) return;
    f.loadingDetail = null;
    if (r.ok && r.data && r.data.id != null) {
        f.detail = r.data;
    } else {
        f.detail = null;
        toast("Couldn't load finding #" + id + ".", "error");
    }
    renderWorkspace();
}

function closeFinding() {
    const f = state.findings;
    f.detail = null; f.detailId = null; f.loadingDetail = null;
    renderWorkspace();
}

// POST a status change, then refresh both the detail and the board so the
// card moves to its new column.
async function setFindingStatus(id, status) {
    const r = await api("POST", "/api/v2/findings/" + encodeURIComponent(id) + "/status",
                        { status, operator: state.user || "operator" });
    if (r.ok && r.data && r.data.ok) {
        consoleLog("success", "finding #" + id + " status: " + (r.data.from || "?") + " → " + status);
        toast("Status updated → " + findingStatusLabel(status), "success");
        // Refresh the board (re-buckets the card) and re-open this finding.
        const f = state.findings;
        if (f.slug) {
            const br = await api("GET", "/api/v2/programs/" + encodeURIComponent(f.slug) + "/findings_board");
            if (br.ok && br.data && br.data.columns) f.board = br.data;
        }
        const dr = await api("GET", "/api/v2/findings/" + encodeURIComponent(id));
        if (dr.ok && dr.data && dr.data.id != null && f.detailId === id) f.detail = dr.data;
        renderWorkspace();
    } else {
        const msg = (r.data && r.data.error) || ("HTTP " + r.status);
        consoleLog("error", "status change failed for #" + id + ": " + msg);
        toast("Status change rejected: " + msg, "error");
    }
}

// Promote an ai_hypothesis evidence row to verified, then refresh the detail.
async function verifyFindingEvidence(findingId, evidenceId) {
    const r = await api("POST",
        "/api/v2/findings/" + encodeURIComponent(findingId) + "/evidence/" + encodeURIComponent(evidenceId) + "/verify",
        { operator: state.user || "operator" });
    if (r.ok && r.data && r.data.ok) {
        consoleLog("success", "evidence #" + evidenceId + " verified on finding #" + findingId);
        toast("Evidence verified.", "success");
        const dr = await api("GET", "/api/v2/findings/" + encodeURIComponent(findingId));
        if (dr.ok && dr.data && dr.data.id != null && state.findings.detailId === findingId) {
            state.findings.detail = dr.data;
        }
        renderWorkspace();
    } else {
        const msg = (r.data && r.data.error) || ("HTTP " + r.status);
        consoleLog("error", "verify failed: " + msg);
        toast("Verify failed: " + msg, "error");
    }
}
// ── [agent: findings] ── end

PAGES.notes = function () {
    const notes = LS.get(wsKey("notes"), "") || "";
    const ws = state.workspace || state.target || "default";
    return `
      ${renderWorkspaceHead("Notes", "Evidence", "Session notes and operator commentary.")}
      ${panel(`Session notes · ${escapeHTML(ws)}`, `
        <textarea id="notes-area" class="mono" style="width:100%; min-height: 280px;"
          placeholder="paste payloads, observations, follow-ups…&#10;&#10;(commands sent here via 'Add to Notes' land at the bottom)">${escapeHTML(notes)}</textarea>
        <div class="spacer-sm"></div>
        <div style="display:flex; gap:8px;">
          <button class="btn btn-primary" onclick="ReconForge.saveNotes()">▸ Save</button>
          <button class="btn btn-ghost" onclick="ReconForge.copyNotes()">Copy all</button>
          <button class="btn btn-ghost" onclick="ReconForge.clearNotes()">Clear</button>
        </div>
        <div class="form-help">Notes persist in this browser, scoped to the active workspace.</div>
      `)}
    `;
};

PAGES.artifacts = function () {
    return `
      ${renderWorkspaceHead("Artifacts", "Evidence", "Screenshots, raw req/resp, HAR captures.")}
      ${panel("Per-run artifacts", `<div class="tbl-empty">Drop files via scripts/report/evidence-pack.sh.</div>`)}
    `;
};

PAGES.timeline = function () {
    return `
      ${renderWorkspaceHead("Timeline", "Evidence", "Chronological log of operator and system events.")}
      ${renderEvidenceTimeline(state.consoleEvents)}
    `;
};

// ── [agent: report] ── Report Export workspace ───────────────────
PAGES.export = function () {
    const rep      = state.report || { platform: "", draft: "" };
    const apex     = state.target || "";
    const firstAsset = reportInScopeAsset();
    const draft    = rep.draft || "";
    return `
      ${renderWorkspaceHead("Report Export", "Report", "Score, draft, and quality-gate a submission-ready report.")}
      <div class="workspace-cols">
        <div>
          ${panel("CVSS 4.0 calculator", `
            <div class="form-grid">
              <div class="full">
                <label class="form-label">CVSS 4.0 vector</label>
                <input id="export-cvss" type="text" class="mono"
                  value="${escapeAttr(reportDefaultVector())}"
                  oninput="ReconForge.scoreCvss()"
                  placeholder="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
                  spellcheck="false" autocomplete="off">
              </div>
            </div>
            <div class="spacer-sm"></div>
            <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
              <button class="btn btn-sm btn-primary" onclick="ReconForge.scoreCvss()">▸ Score</button>
              <div id="cvss-result" class="cvss-result">${renderCvssResult(reportDefaultVector())}</div>
            </div>
            <div class="form-help">Base + Threat (E) metrics, scored client-side with the same approximation as <span class="mono">core/cvss.py</span> (±0.4 of FIRST). Required: AV AC AT PR UI VC VI VA SC SI SA; optional E.</div>
          `)}
          ${panel("Per-platform draft", `
            <div class="form-grid">
              <div class="full">
                <label class="form-label">Platform</label>
                <div class="radio-row">
                  ${["hackerone","intigriti","bugcrowd","yeswehack","synack"].map(p =>
                    `<label class="radio-pill ${rep.platform === p ? "selected" : ""}" onclick="ReconForge.setPlatform('${p}')">${p}</label>`
                  ).join("")}
                </div>
              </div>
              <div>
                <label class="form-label">Vuln class</label>
                <input id="export-class" type="text" value="${escapeAttr(rep.vulnClass || "")}" placeholder="ssrf, xss, idor…" spellcheck="false">
              </div>
              <div>
                <label class="form-label">Affected asset (in-scope)</label>
                <input id="export-asset" type="text" value="${escapeAttr(rep.asset != null ? rep.asset : firstAsset)}" placeholder="api.example.com" spellcheck="false">
              </div>
            </div>
            <div class="spacer-md"></div>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
              <button class="btn btn-primary" onclick="ReconForge.generateDraft()" ${apex ? "" : "disabled"}>▸ Generate draft</button>
              <button class="btn btn-ghost" onclick="ReconForge.copyDraft()" ${draft ? "" : "disabled"}>Copy draft</button>
            </div>
            ${apex ? "" : `<div class="form-help">Load a target on <span class="mono">Target → Intake</span> first to pre-fill the scaffold.</div>`}
            <div class="spacer-sm"></div>
            <textarea id="export-draft" class="mono report-draft" spellcheck="false"
              placeholder="Select a platform and click Generate draft — a markdown scaffold pre-filled with your target, in-scope asset, vuln class, and the CVSS vector + score appears here.">${escapeHTML(draft)}</textarea>
          `)}
          ${state.guideMode ? guidePanel("Report doctrine", "Title must name vuln class + asset + impact. Every repro step numbered, one instruction per line. CVSS score provided AND justified. Impact = real-world consequence, never theoretical. Triagers downgrade padded severity — understated honest beats inflated.") : ""}
        </div>
        <div>
          ${renderQualityGatePanel()}
          ${renderVaultPanel()}
        </div>
      </div>
    `;
};

// In-scope asset to pre-fill the report (first concrete host, else apex).
function reportInScopeAsset() {
    const sc = state.scope || {};
    const apex = state.target || "";
    const concrete = (sc.inScope || []).find(h =>
        h && !h.startsWith("*.") && h.indexOf("/") === -1);
    return concrete || apex || "";
}

function reportDefaultVector() {
    // Reuse whatever is in the live field on re-render, else a sane CVSS 4.0 base.
    const el = (typeof document !== "undefined") && document.getElementById("export-cvss");
    if (el && el.value) return el.value;
    return (state.report && state.report.vector) ||
           "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N";
}

// ── CVSS 4.0 scoring (ported from core/cvss.py — keep math in lockstep) ──
const CVSS_AV = { N: 1.00, A: 0.62, L: 0.55, P: 0.20 };
const CVSS_AC = { L: 1.00, H: 0.77 };
const CVSS_AT = { N: 1.00, P: 0.70 };
const CVSS_PR = { N: 1.00, L: 0.68, H: 0.50 };
const CVSS_UI = { N: 1.00, P: 0.85, A: 0.62 };
const CVSS_IMPACT = { H: 1.00, L: 0.40, N: 0.00 };
const CVSS_E = { A: 1.00, P: 0.95, U: 0.85, X: 1.00 };
const CVSS_REQUIRED = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"];
const CVSS_VALID = {
    AV: CVSS_AV, AC: CVSS_AC, AT: CVSS_AT, PR: CVSS_PR, UI: CVSS_UI,
    VC: CVSS_IMPACT, VI: CVSS_IMPACT, VA: CVSS_IMPACT,
    SC: CVSS_IMPACT, SI: CVSS_IMPACT, SA: CVSS_IMPACT, E: CVSS_E,
};

// Parse a CVSS:4.0 vector. Returns { metrics } or { error }.
function cvss40Parse(vector) {
    if (typeof vector !== "string") return { error: "vector must be a string" };
    const v = vector.trim();
    const m = /^CVSS:4\.0((?:\/[A-Z]+:[A-Z])+)$/.exec(v);
    if (!m) {
        if (/^(CVSS:3\.[01]|AV:)/.test(v) && !/^CVSS:4\.0/.test(v)) {
            return { error: "only CVSS:4.0 vectors are scored (matches core/cvss.py)" };
        }
        return { error: "not a CVSS:4.0 vector" };
    }
    const metrics = {};
    for (const chunk of m[1].split("/")) {
        if (!chunk) continue;
        const [k, val] = chunk.split(":");
        if (k in metrics) return { error: "duplicate metric " + k };
        if (!(k in CVSS_VALID)) return { error: "unknown metric " + k };
        if (!(val in CVSS_VALID[k])) return { error: "invalid value for " + k + ": " + val };
        metrics[k] = val;
    }
    const missing = CVSS_REQUIRED.filter(k => !(k in metrics));
    if (missing.length) return { error: "missing required metrics: " + missing.join(", ") };
    if (!("E" in metrics)) metrics.E = "X";
    return { metrics };
}

function cvss40Score(vector) {
    const p = cvss40Parse(vector);
    if (p.error) return { error: p.error };
    const m = p.metrics;
    const exploitability =
        CVSS_AV[m.AV] * CVSS_AC[m.AC] * CVSS_AT[m.AT] * CVSS_PR[m.PR] * CVSS_UI[m.UI];
    const vc = CVSS_IMPACT[m.VC], vi = CVSS_IMPACT[m.VI], va = CVSS_IMPACT[m.VA];
    const sc = CVSS_IMPACT[m.SC], si = CVSS_IMPACT[m.SI], sa = CVSS_IMPACT[m.SA];
    const vulnMax = Math.max(vc, vi, va);
    const vulnBonus = 0.05 * [vc, vi, va].filter(x => x >= CVSS_IMPACT.H && x !== vulnMax).length;
    const vulnImpact = Math.min(1.0, vulnMax + vulnBonus);
    const subMax = Math.max(sc, si, sa);
    const subContrib = 0.5 * subMax;
    const impact = Math.max(vulnImpact, subContrib);
    let base = 10.0 * exploitability * impact;
    base *= CVSS_E[m.E];
    const scoreVal = Math.round(Math.min(10.0, Math.max(0.0, base)) * 10) / 10;
    return { score: scoreVal, severity: cvss40Severity(scoreVal) };
}

function cvss40Severity(s) {
    if (s <= 0.0) return "None";
    if (s < 4.0)  return "Low";
    if (s < 7.0)  return "Medium";
    if (s < 9.0)  return "High";
    return "Critical";
}

// Map severity → an existing badge variant for visual consistency.
function cvssSeverityBadge(sev) {
    const cls = { Critical: "error", High: "error", Medium: "processing",
                  Low: "muted", None: "muted" }[sev] || "muted";
    return `<span class="badge badge-${cls}">${escapeHTML(sev)}</span>`;
}

function renderCvssResult(vector) {
    const r = cvss40Score(vector);
    if (r.error) {
        return `<span class="cvss-score-num text-mute">—</span> <span class="text-error" style="font-size:11px;">${escapeHTML(r.error)}</span>`;
    }
    return `<span class="cvss-score-num">${r.score.toFixed(1)}</span> ${cvssSeverityBadge(r.severity)}`;
}

// Score handler — reads the field, writes the result element by id. No full
// re-render, so the operator can keep typing the vector mid-score.
function scoreCvss() {
    const el  = document.getElementById("export-cvss");
    const out = document.getElementById("cvss-result");
    if (!el || !out) return;
    if (state.report) state.report.vector = el.value;
    out.innerHTML = renderCvssResult(el.value);
}

function setPlatform(p) {
    if (!["hackerone","intigriti","bugcrowd","yeswehack","synack"].includes(p)) return;
    if (!state.report) state.report = { platform: "", draft: "" };
    // Capture in-progress field values before the re-render repaints them.
    const vc = document.getElementById("export-class");
    const vct = document.getElementById("export-cvss");
    const as = document.getElementById("export-asset");
    if (vc)  state.report.vulnClass = vc.value;
    if (vct) state.report.vector = vct.value;
    if (as)  state.report.asset = as.value;
    state.report.platform = p;
    consoleLog("select", "report platform: " + p);
    if (currentRoute() === "export") renderWorkspace();
}

// Build a platform-tailored markdown scaffold (Agent 6 — Reporter formats).
function buildReportDraft(platform, ctx) {
    const { target, asset, vulnClass, vector, score, severity } = ctx;
    const klass = vulnClass || "[vuln class]";
    const klassTitle = klass.toUpperCase();
    const assetLine = asset || target || "[asset]";
    const sevLabel  = severity || "—";
    const scoreLabel = (score == null) ? "X.X" : score.toFixed(1);
    const vecLine = vector || "CVSS:4.0/…";
    const title = `${klassTitle} in ${assetLine} allows [impact]`;

    if (platform === "hackerone") {
        return `Title: ${title}
Severity: ${sevLabel} — CVSS 4.0 score: ${scoreLabel}
Weakness: CWE-XXX ([name])
Asset type: ${assetLine}

## Summary
[2-3 sentence executive summary. What is it (${klass}), where is it (${assetLine}), what can an attacker do.]

## Steps to Reproduce
1. [Step]
2. [Step]
3. [Step]

## Proof of Concept
\`\`\`
[Working payload / request / response]
\`\`\`

## Impact
[Specific data/access/action an attacker gains on ${target || assetLine}. Business risk.]

## CVSS Justification
${vecLine}
Score: ${scoreLabel} (${sevLabel}). [One sentence justifying each metric choice.]

## Remediation
[Specific fix recommendation]
`;
    }

    if (platform === "intigriti") {
        return `## Executive Summary
[1 paragraph. Asset ${assetLine}, class ${klass}, severity ${sevLabel}, business impact.]

## Technical Details
[Full technical explanation of the root cause.]

### Reproduction Steps
1. [Step]
2. [Step]
3. [Step]

### Proof of Concept
\`\`\`
[payload or request — include your X-Intigriti-Username header on every target request]
\`\`\`

## CVSS Score
${vecLine}
Numeric: ${scoreLabel} (${sevLabel}) — [per-metric justification].

## Impact
[What an attacker can do. Data exposure, privilege gained, blast radius.]

## Remediation
[Specific actionable fix.]

## Evidence
[Inline screenshots with captions. Raw request/response pairs.]
`;
    }

    if (platform === "bugcrowd") {
        return `VRT category: [select required VRT category — determines base severity]
Title: [VRT category] — ${klassTitle} in ${assetLine}

## Description
[${klass} on ${assetLine}. Root cause + what an attacker achieves. Limit 25,000 chars.]

## Steps to Reproduce
1. [Step]
2. [Step]
3. [Step]

## Proof of Concept
\`\`\`
[Working payload / request / response]
\`\`\`

## Impact
[Specific consequence on ${target || assetLine}. Business risk.]

## CVSS
${vecLine}
Score: ${scoreLabel} (${sevLabel}). [Justify — Bugcrowd overrides researcher severity; defend yours.]

## Remediation
[Specific fix.]

> Note: no edits after submission. Screenshot minimum; video strongly preferred.
`;
    }

    if (platform === "yeswehack") {
        return `Title: ${title}

## Summary
[1 paragraph. ${klass} on ${assetLine}.]

## OWASP Category
[Map to OWASP category, e.g. A01:2021 — Broken Access Control]

## Technical Details
[Root cause explanation.]

## Steps to Reproduce
1. [Step]
2. [Step]
3. [Step]

## Proof of Concept
\`\`\`
[payload or request]
\`\`\`

## Business Impact
[Non-technical narrative: explain to a non-technical reader what the business risk is on ${target || assetLine}.]

## CVSS Score
${vecLine}
Score: ${scoreLabel} (${sevLabel}).

## Remediation
[Specific actionable fix.]

> Check the program brief for country/region restrictions before testing.
`;
    }

    if (platform === "synack") {
        return `Title: ${title}
Severity: ${sevLabel} — CVSS 4.0: ${scoreLabel}
Vector: ${vecLine}
Affected asset: ${assetLine}

## Vulnerability Description
[${klass} on ${assetLine}. Root cause.]

## Steps to Reproduce
1. [Step — attach sequential screenshot #1]
2. [Step — attach sequential screenshot #2]
3. [Step — attach sequential screenshot #3]

## Proof of Concept
\`\`\`
[payload or request]
\`\`\`

## Impact
[What an attacker gains on ${target || assetLine}.]

## Remediation
[Specific fix.]

> Invite-only: verify program enrollment. Follow the program template exactly;
> evidence chain = sequential screenshots numbered to match each PoC step.
`;
    }
    return "";
}

function generateDraft() {
    if (!state.report) state.report = { platform: "", draft: "" };
    const platform = state.report.platform;
    if (!platform) { toast("Pick a platform first.", "error"); return; }
    const vulnClass = (val("export-class") || "").trim();
    const asset     = (val("export-asset") || "").trim() || reportInScopeAsset();
    const vector    = (val("export-cvss") || "").trim();
    const scored    = cvss40Score(vector);
    state.report.vulnClass = vulnClass;
    state.report.vector    = vector;
    state.report.asset     = asset;
    const ctx = {
        target:    state.target || "",
        asset, vulnClass, vector,
        score:     scored.error ? null : scored.score,
        severity:  scored.error ? null : scored.severity,
    };
    state.report.draft = buildReportDraft(platform, ctx);
    consoleLog("success", "report draft generated: " + platform);
    toast("Draft generated for " + platform + ".", "success");
    renderWorkspace();
}

function copyDraft() {
    const el = document.getElementById("export-draft");
    const txt = el ? el.value : (state.report && state.report.draft) || "";
    copyToClipboard(txt);
}

// ── Quality gate ─────────────────────────────────────────────────
// The 10 deterministic checks (mirrors core/report_gate.py) — shown as a
// static description when no draft id is supplied.
const QUALITY_GATE_CHECKS = [
    ["Title present + descriptive", "≥12 chars; names vuln class + asset + impact"],
    ["Summary present",            "a Summary / Executive Summary section with content"],
    ["Affected asset present",     "an Affected Asset / Endpoint section"],
    ["Reproduction steps present", "a Steps to Reproduce / Reproduction section"],
    ["Impact statement present",   "an Impact section with content"],
    ["Evidence captured",          "≥1 observed or verified evidence row on the finding"],
    ["Remediation suggested",      "a Remediation / Fix section"],
    ["Scope verified",             "the finding's domain is still in program scope"],
    ["No secrets in body",         "regex sweep for keys, JWTs, creds (no hits)"],
    ["Operator reviewed",          "the manual checklist tab was viewed + acknowledged"],
];

function renderQualityGatePanel() {
    const rep = state.report || {};
    const gate = rep.gate;
    let body;
    if (gate && Array.isArray(gate.checks)) {
        const pct = gate.total ? Math.round((gate.passed_count / gate.total) * 100) : 0;
        const head = `
          <div class="gate-summary">
            <span class="badge badge-${gate.passed ? "success" : "error"}">${gate.passed ? "READY" : "BLOCKED"}</span>
            <span class="mono">${gate.passed_count}/${gate.total} checks</span>
            <div class="gate-bar"><div class="gate-bar-fill" style="width:${pct}%"></div></div>
          </div>`;
        const rows = gate.checks.map(c => `
          <li class="gate-check ${c.passed ? "pass" : "fail"}">
            <span class="gate-mark">${c.passed ? "✓" : "✕"}</span>
            <span class="gate-label">${escapeHTML(c.label)}</span>
            ${!c.passed && c.reason ? `<span class="gate-reason">${escapeHTML(c.reason)}</span>` : ""}
          </li>`).join("");
        body = head + `<ul class="gate-list">${rows}</ul>`;
    } else {
        const rows = QUALITY_GATE_CHECKS.map(([label, desc]) => `
          <li class="gate-check">
            <span class="gate-mark">•</span>
            <span class="gate-label">${escapeHTML(label)}</span>
            <span class="gate-reason">${escapeHTML(desc)}</span>
          </li>`).join("");
        const note = rep.gateNote
            ? `<div class="form-help text-error">${escapeHTML(rep.gateNote)}</div>`
            : `<div class="form-help">No draft loaded. Enter a submission draft id to run the live gate, or review the 10 checks below (from <span class="mono">core/report_gate.py</span>).</div>`;
        body = `<ul class="gate-list">${rows}</ul>` + note;
    }
    return panel("Submission quality gate", `
      ${body}
      <div class="spacer-sm"></div>
      <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
        <input id="gate-draft-id" type="number" min="1" placeholder="draft id" style="width:110px;"
          value="${escapeAttr(state.report && state.report.gateId != null ? String(state.report.gateId) : "")}">
        <label class="radio-pill ${state.report && state.report.gateReviewed ? "selected" : ""}" style="font-size:10px;">
          <input id="gate-reviewed" type="checkbox" ${state.report && state.report.gateReviewed ? "checked" : ""} style="margin-right:6px;">reviewed
        </label>
        <button class="btn btn-sm btn-primary" onclick="ReconForge.runQualityGate()">▸ Run gate</button>
      </div>
    `);
}

async function runQualityGate() {
    const idEl = document.getElementById("gate-draft-id");
    const revEl = document.getElementById("gate-reviewed");
    const raw = (idEl && idEl.value || "").trim();
    if (!state.report) state.report = { platform: "", draft: "" };
    state.report.gateReviewed = !!(revEl && revEl.checked);
    const id = parseInt(raw, 10);
    if (!raw || isNaN(id) || id < 1) {
        state.report.gate = null;
        state.report.gateNote = "Enter a numeric submission draft id to run the live gate.";
        renderWorkspace();
        return;
    }
    state.report.gateId = id;
    const reviewed = state.report.gateReviewed ? "1" : "0";
    const r = await api("GET", "/api/v2/submissions/" + id + "/quality_gate?reviewed=" + reviewed);
    if (r.ok && r.data) {
        const gate = r.data.data || r.data;
        if (gate && Array.isArray(gate.checks)) {
            state.report.gate = gate;
            state.report.gateNote = "";
            consoleLog("success", "quality gate: " + gate.passed_count + "/" + gate.total + " (draft " + id + ")");
        } else {
            state.report.gate = null;
            state.report.gateNote = "Unexpected gate response.";
        }
    } else {
        state.report.gate = null;
        state.report.gateNote = (r.status === 404)
            ? ("No submission draft #" + id + " — drafts come from the agent layer / report scripts.")
            : ("Gate request failed (HTTP " + r.status + ").");
        consoleLog("error", "quality gate failed: " + state.report.gateNote);
    }
    renderWorkspace();
}

PAGES.vault = function () {
    return `
      ${renderWorkspaceHead("Vault Sync", "Report", "Push workspace artifacts into your notes vault.")}
      <div class="workspace-cols">
        <div>
          ${renderVaultPanel()}
        </div>
        <div>
          ${panel("Sync controls", `
            <div class="status-panel">
              <dt>Vault root</dt><dd class="mono" style="font-size:11px;">${escapeHTML(state.vaultPath || "—")}</dd>
              <dt>Last sync</dt><dd class="text-mute">never</dd>
              <dt>Pending</dt><dd>0 files</dd>
            </div>
            <div class="spacer-md"></div>
            <button class="btn btn-primary" onclick="ReconForge.toast('Vault sync triggered.', 'success')">▸ Sync now</button>
          `)}
        </div>
      </div>
    `;
};

PAGES.jobs = function () {
    const s = state.apiState || {};
    const running = s.running_jobs || [];
    const queued  = s.queued_jobs  || [];
    const done    = s.completed_jobs|| [];
    return `
      ${renderWorkspaceHead("Jobs", "Operations", "Running, queued, and completed pipeline runs.")}
      ${panel("Submit new scan", `
        <form onsubmit="event.preventDefault(); ReconForge.submitJob(); return false;" style="display:flex; gap:8px;">
          <input id="job-domain" type="text" placeholder="example.com" spellcheck="false" style="flex:1;">
          <button type="submit" class="btn btn-primary">▸ Submit</button>
        </form>
      `)}
      ${panel("Running", running.length ? renderJobsTable(running) : `<div class="tbl-empty">No running jobs.</div>`)}
      ${panel("Queued", queued.length ? renderJobsTable(queued) : `<div class="tbl-empty">Queue empty.</div>`)}
      ${panel("Recent (last 20)", done.length ? renderJobsTable(done) : `<div class="tbl-empty">No completed jobs yet.</div>`)}
    `;
};

PAGES.queue = function () {
    const s = state.apiState || {};
    const queued = s.queued_jobs || [];
    return `
      ${renderWorkspaceHead("Queue", "Operations", "Pending job queue.")}
      ${panel("Pending", queued.length ? renderJobsTable(queued) : `<div class="tbl-empty">Queue empty.</div>`)}
    `;
};

PAGES.workers = function () {
    const s = state.apiState || {};
    const workers = s.workers || {};
    const keys = Object.keys(workers).sort();
    if (!keys.length) {
        return `
          ${renderWorkspaceHead("Workers", "Operations", "Per-tool concurrency gates.")}
          ${panel("Tool gates", `<div class="tbl-empty">No workers reported yet. Gates initialise on first job dispatch.</div>`)}
        `;
    }
    const totalRunning = keys.reduce((a, k) => a + (workers[k].running || 0), 0);
    const totalWaiting = keys.reduce((a, k) => a + (workers[k].waiting || 0), 0);
    const cards = keys.map(k => {
        const w = workers[k] || {};
        const running = w.running || 0;
        const waiting = w.waiting || 0;
        const max     = w.max || w.max_concurrent || 0;   // backend emits `max`
        const busyPct = max ? Math.min(100, Math.round((running / max) * 100)) : 0;
        const st = running ? "busy" : (waiting ? "waiting" : "idle");
        const pill = running ? "BUSY" : (waiting ? "WAIT" : "IDLE");
        return `
          <div class="worker-card" data-state="${st}">
            <div class="worker-card-head">
              <span class="worker-name mono">${escapeHTML(k)}</span>
              <span class="worker-pill" data-state="${st}">${pill}</span>
            </div>
            <div class="worker-stats">
              <div><span class="worker-stat-val">${running}</span><span class="worker-stat-lbl">running</span></div>
              <div><span class="worker-stat-val">${waiting}</span><span class="worker-stat-lbl">waiting</span></div>
              <div><span class="worker-stat-val">${max || "—"}</span><span class="worker-stat-lbl">max</span></div>
            </div>
            <div class="worker-bar"><div class="worker-bar-fill" style="width:${busyPct}%"></div></div>
          </div>
        `;
    }).join("");
    return `
      ${renderWorkspaceHead("Workers", "Operations", "Per-tool concurrency gates — live.")}
      ${renderMetrics([
        { label: "Tool gates",  value: keys.length },
        { label: "Running now",  value: totalRunning, kind: totalRunning ? "processing" : "" },
        { label: "Waiting",      value: totalWaiting, kind: totalWaiting ? "error" : "" },
      ])}
      <div class="worker-cards">${cards}</div>
    `;
};

PAGES.monitors = function () {
    const rows = (state.apiState && state.apiState.schedule) || [];
    const table = rows.length ? `
      <table class="tbl">
        <thead><tr><th>Target</th><th>Status</th><th>Cadence</th><th>Next run</th><th>Quiet</th><th>Last Δ</th><th></th></tr></thead>
        <tbody>
          ${rows.map(r => `
            <tr>
              <td class="mono">${escapeHTML(r.domain)}</td>
              <td>${r.enabled ? `<span class="badge badge-success">ON</span>` : `<span class="badge badge-muted">PAUSED</span>`}</td>
              <td class="mono">${fmtInterval(r.interval_seconds)}</td>
              <td class="mono text-sec">${escapeHTML(fmtWhen(r.next_run_at))}</td>
              <td class="mono text-sec">${fmtQuiet(r.last_new_asset_at)}</td>
              <td>${r.last_delta_count > 0 ? `<span class="badge badge-success">+${r.last_delta_count}</span>` : `<span class="text-mute">0</span>`}</td>
              <td style="text-align:right; white-space:nowrap;">
                <button class="btn btn-ghost btn-sm" onclick="ReconForge.toggleMonitor(${r.id}, ${r.enabled ? 0 : 1})">${r.enabled ? "pause" : "resume"}</button>
                <button class="btn btn-ghost btn-sm" onclick="ReconForge.removeMonitor(${r.id})">remove</button>
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    ` : `<div class="tbl-empty">No targets enrolled. Add one below to start continuous monitoring.</div>`;

    const enroll = `
      <div style="display:flex; gap:8px; margin-top:10px;">
        <input id="mon-domain" type="text" placeholder="example.com" spellcheck="false" style="flex:1;">
        <button class="btn btn-primary" onclick="ReconForge.enrollMonitor()">▸ Monitor target</button>
      </div>
      <div class="form-help">Passive enum + httpx on a 4h->7d adaptive cadence. New assets reset the cadence to 4h, fire a <span class="mono">notify</span> alert, and flow to the notes vault as review drafts. Scope Guard gates every scan.</div>
    `;

    return `
      ${renderWorkspaceHead("Monitors", "Operations", "Continuous attack-surface monitoring.")}
      ${panel("Enrolled targets", table + enroll)}
      ${state.guideMode ? guidePanel("Adaptive cadence", "Each target is scanned every 4h while it keeps producing new assets. After ~3 quiet days the interval steps up (8h → 12h → 24h → 48h → 96h) to a 7-day ceiling; any new asset snaps it back to 4h. Monitor scans are passive + httpx only — loud active testing stays in the exploit cards.") : ""}
    `;
};

function fmtInterval(secs) {
    secs = secs || 0;
    if (secs >= 86400 && secs % 86400 === 0) return (secs / 86400) + "d";
    return Math.round(secs / 3600) + "h";
}
function fmtWhen(s) {
    if (!s) return "due now";
    const d = new Date(s.replace(" ", "T") + "Z");
    if (isNaN(d.getTime())) return s;
    const diff = d.getTime() - Date.now();
    if (diff <= 0) return "due now";
    const h = Math.floor(diff / 3600000), m = Math.floor((diff % 3600000) / 60000);
    return h > 0 ? `in ${h}h ${m}m` : `in ${m}m`;
}
function fmtQuiet(s) {
    if (!s) return "—";
    const d = new Date(s.replace(" ", "T") + "Z");
    if (isNaN(d.getTime())) return "—";
    return Math.max(0, Math.floor((Date.now() - d.getTime()) / 86400000)) + "d";
}

PAGES.resources = function () {
    const s = state.apiState || {};
    const r = s.resources || {};
    const cpu  = r.cpu  ?? 0;
    const mem  = r.memory ?? 0;
    const disk = r.disk ?? 0;
    return `
      ${renderWorkspaceHead("Resources", "Operations", "Live host resource usage.")}
      ${renderMetrics([
        { label: "CPU",    value: cpu  + "%", kind: cpu  > 80 ? "error" : (cpu  > 50 ? "processing" : "") },
        { label: "Memory", value: mem  + "%", kind: mem  > 85 ? "error" : (mem  > 70 ? "processing" : "") },
        { label: "Disk",   value: disk + "%", kind: disk > 90 ? "error" : (disk > 80 ? "processing" : "") },
      ])}
    `;
};

// ── Agents command center (six-agent LLM chain) ──────────────────
const AGENT_CHAIN_FALLBACK = [
    { name: "scope_guard", label: "Scope Guard", desc: "Pure-logic scope gate (no LLM call)" },
    { name: "strategist",  label: "Strategist",  desc: "Ranks scope into an executable attack plan" },
    { name: "recon",       label: "Recon",       desc: "Drives adaptive tool selection on discoveries" },
    { name: "hunter",      label: "Hunter",      desc: "Identifies + scores exploitable vuln classes" },
    { name: "analyst",     label: "Analyst",     desc: "CVSS, bounty estimate, chains, dup detection" },
    { name: "reporter",    label: "Reporter",    desc: "Drafts platform-ready submissions" },
];
const AGENT_MODES = ["passive_recon","active_recon","content_discovery","vuln_triage",
                     "evidence_collection","report_drafting","retest"];

PAGES.agents = function () {
    if (!state.target) {
        return `${renderWorkspaceHead("AI Agents", "Recon", "Run the six-agent LLM chain on your target.")}
          ${panel("No target loaded", `<div class="tbl-empty">Load a target on <span class="mono">Target → Intake</span> first.</div>`)}`;
    }
    return `
      ${renderWorkspaceHead("AI Agents", "Recon", "ScopeGuard → Strategist → Recon → Hunter → Analyst → Reporter. Live logs + cost below.")}
      <div id="agent-live">${renderAgentLive()}</div>
      ${renderAgentLogPanel()}
      ${renderAgentBackendPanel()}
      ${state.guideMode ? guidePanel("How this runs", "ScopeGuard is pure logic (no LLM). The other five call your configured backend — Claude API or local Ollama. A per-run cost cap stops new LLM calls once spent; a single agent failing degrades the run instead of aborting it. Findings the agents create show up on the Findings board.") : ""}
    `;
};

function renderAgentLive() {
    const d = state.agents.data || {};
    const backend = d.backend || "api";
    const running = !!d.running;
    const cap = d.cost_cap != null ? d.cost_cap : 5;
    const cost = d.total_cost || 0;
    const overall = d.status;
    const scopeOk = d.scope_active != null ? d.scope_active : !!(state.scope && state.scope.active);
    const keyBadge = backend === "local"
        ? `<span class="badge badge-muted">local</span>`
        : (d.api_key_set ? `<span class="badge badge-success">KEY SET</span>` : `<span class="badge badge-error">NO API KEY</span>`);
    return `
      <div class="agent-bar">
        <div>
          target <span class="mono text-purple">${escapeHTML(state.target)}</span> ·
          ${backend === "local" ? `<span class="badge badge-processing">OLLAMA</span>` : `<span class="badge badge-active">CLAUDE API</span>`} ${keyBadge} ·
          ${scopeOk ? `<span class="badge badge-success">SCOPE ENFORCED</span>` : `<span class="badge badge-error">SCOPE NOT WIRED</span>`}
          ${overall ? ` · <span class="badge badge-${agentOverallCls(overall)}">${escapeHTML(overall.toUpperCase())}</span>` : ""}
        </div>
        <div class="agent-cost">cost <span class="mono">$${(cost || 0).toFixed(4)}</span> <span class="text-mute">/ cap $${(cap || 0).toFixed(2)}</span></div>
      </div>
      <div class="agent-controls">
        <label class="form-label" style="margin:0;">Mode</label>
        <select id="agent-mode" ${running ? "disabled" : ""}>
          ${AGENT_MODES.map(m => `<option value="${m}">${m}</option>`).join("")}
        </select>
        ${running
          ? `<button class="btn btn-ghost" disabled>● running…</button>`
          : `<button class="btn btn-primary" onclick="ReconForge.startAgentRun()">▸ Start agentic run</button>`}
        <button class="btn btn-ghost btn-sm" onclick="ReconForge.refreshAgents()">↻</button>
      </div>
      ${renderAgentChain()}
    `;
}

function renderAgentChain() {
    const d = state.agents.data;
    const chain = (d && Array.isArray(d.chain) && d.chain.length) ? d.chain : AGENT_CHAIN_FALLBACK;
    return `<div class="agent-chain">${chain.map((a, i) => `
      <div class="agent-node" data-state="${a.status || "idle"}">
        <div class="agent-node-head">
          <span class="agent-idx mono">${i + 1}</span>
          <span class="agent-name">${escapeHTML(a.label || a.name)}</span>
          ${agentStatusBadge(a.status)}
        </div>
        <div class="agent-desc">${escapeHTML(a.desc || "")}</div>
        ${(a.cost || a.error) ? `<div class="agent-node-foot">
          ${a.cost ? `<span class="agent-cost-chip mono">$${(a.cost || 0).toFixed(4)}</span>` : ""}
          ${a.error ? `<span class="agent-err" title="${escapeAttr(a.error)}">${escapeHTML(String(a.error).slice(0, 70))}</span>` : ""}
        </div>` : ""}
      </div>${i < chain.length - 1 ? `<div class="agent-arrow">↓</div>` : ""}`).join("")}</div>`;
}

function agentStatusBadge(s) {
    const map = { running:["processing","RUNNING"], completed:["success","DONE"],
                  failed:["error","FAILED"], degraded:["error","DEGRADED"],
                  pending:["muted","PENDING"], skipped:["muted","SKIPPED"] };
    const [c, l] = map[s] || ["muted", "IDLE"];
    return `<span class="badge badge-${c}">${l}</span>`;
}
function agentOverallCls(s) {
    return { completed:"success", degraded:"error", rejected:"muted", failed:"error", running:"processing" }[s] || "muted";
}

function renderAgentLogPanel() {
    const pl = state.agentLog;
    return `
      <div class="panel">
        <div class="panel-head"><span>live log</span>
          <button class="console-btn" onclick="ReconForge.toggleAgentLog()">${pl.open ? "hide" : "show"}</button></div>
        <div class="panel-body"><pre id="agent-log-pre" class="phase-log" ${pl.open ? "" : "hidden"}>${escapeHTML(pl.text || "(no run yet)")}</pre></div>
      </div>`;
}

function renderAgentBackendPanel() {
    if (state.role !== "admin") {
        // Non-admins can't read /api/config; show the backend from agent-state.
        const backend = (state.agents.data && state.agents.data.backend) || "api";
        return panel("LLM backend", `<div class="status-panel">
            <dt>Backend</dt><dd>${backend === "local" ? "Local Ollama" : "Claude API"}</dd>
            <dt>Configured by</dt><dd class="text-mute">admin only</dd>
          </div>`);
    }
    const c = state.config || {};
    const mode = c["llm.mode"] || "api";
    const keyset = !!c["llm.api_key"];
    const capVal = (c["llm.max_cost_usd"] != null) ? c["llm.max_cost_usd"] : 5;
    const fields = mode === "api" ? `
        <div class="full"><label class="form-label">Anthropic API key ${keyset ? `<span class="badge badge-success">SET</span>` : ""}</label>
          <input id="llm-key" type="password" autocomplete="off" placeholder="${keyset ? "•••••••• (blank = keep current)" : "sk-ant-…"}"></div>
        <div><label class="form-label">Opus model</label><input id="llm-opus" type="text" value="${escapeAttr(c["llm.opus_model"] || "claude-opus-4-8")}"></div>
        <div><label class="form-label">Haiku model</label><input id="llm-haiku" type="text" value="${escapeAttr(c["llm.haiku_model"] || "claude-haiku-4-5-20251001")}"></div>
      ` : `
        <div><label class="form-label">Ollama URL</label><input id="llm-ourl" type="text" value="${escapeAttr(c["llm.ollama_url"] || "http://127.0.0.1:11434")}"></div>
        <div><label class="form-label">Ollama model</label><input id="llm-omodel" type="text" value="${escapeAttr(c["llm.ollama_default_model"] || "llama3.1:8b")}"></div>
      `;
    return `
      <div class="panel">
        <div class="panel-head"><span>llm backend</span></div>
        <div class="panel-body">
          <div class="radio-row">
            <label class="radio-pill ${mode === "api" ? "selected" : ""}" onclick="ReconForge.setAgentBackend('api')">Claude API</label>
            <label class="radio-pill ${mode === "local" ? "selected" : ""}" onclick="ReconForge.setAgentBackend('local')">Local Ollama</label>
          </div>
          <div class="spacer-md"></div>
          <div class="form-grid">
            ${fields}
            <div><label class="form-label">Cost cap (USD / run)</label><input id="llm-cap" type="number" step="0.5" min="0" value="${escapeAttr(String(capVal))}"></div>
          </div>
          <div class="spacer-md"></div>
          <button class="btn btn-primary" onclick="ReconForge.saveAgentConfig()">▸ Save backend</button>
          <div class="form-help">Stored in this app's local config. Claude API is billed per token; the cost cap stops new LLM calls once a run reaches it. The key is never shown back here once saved.</div>
        </div>
      </div>`;
}

async function ensureConfigSilent() {
    // /api/config is admin-only and returns secrets masked — only admins fetch it.
    if (state.config || state.role !== "admin") return;
    const r = await api("GET", "/api/config");
    if (r.ok) state.config = r.data && (r.data.data || r.data);
}
async function ensureAgents() {
    if (!state.agents) state.agents = { data: null };
    if (!state.target) { if (currentRoute() === "agents") renderWorkspace(); return; }
    await ensureConfigSilent();
    const r = await api("GET", "/api/agent/state?target=" + encodeURIComponent(state.target));
    if (r.ok) state.agents.data = r.data.data || r.data;
    if (currentRoute() === "agents") renderWorkspace();
    if (state.agents.data && state.agents.data.running) startAgentPoll();
}
function refreshAgents() { ensureAgents(); }

async function startAgentRun() {
    if (!state.target) { toast("Load a target first.", "error"); return; }
    const sel = document.getElementById("agent-mode");
    const mode = (sel && sel.value) || "passive_recon";
    const r = await api("POST", "/api/agent/run", { target: state.target, mode });
    if (r.ok && r.data && r.data.success) {
        state.agentLog = { text: "(starting…)", open: true };
        consoleLog("success", "agentic run queued (" + mode + ")");
        toast("Agentic run started · " + mode, "success");
        await ensureAgents();
        startAgentPoll();
    } else {
        const msg = (r.data && r.data.message) || ("HTTP " + r.status);
        consoleLog("error", "agentic run refused: " + msg);
        toast("Refused: " + msg, "error");
    }
}

function toggleAgentLog() {
    state.agentLog.open = !state.agentLog.open;
    renderWorkspace();
    if (state.agentLog.open) agentTick();
}

async function setAgentBackend(mode) {
    const r = await api("PUT", "/api/config", { "llm.mode": mode });
    if (r.ok) {
        if (state.config) state.config["llm.mode"] = mode;
        toast("Backend: " + (mode === "local" ? "Local Ollama" : "Claude API"), "info");
        ensureAgents();
    } else { toast("Switch failed (admin only).", "error"); }
}

async function saveAgentConfig() {
    const c = state.config || {};
    const mode = c["llm.mode"] || "api";
    const num = (id, dflt) => { const el = document.getElementById(id); const v = parseFloat(el && el.value); return isNaN(v) ? dflt : v; };
    const txt = (id) => { const el = document.getElementById(id); return ((el && el.value) || "").trim(); };
    const payload = { "llm.max_cost_usd": num("llm-cap", 5) };
    if (mode === "api") {
        const k = txt("llm-key"); if (k) payload["llm.api_key"] = k;   // only overwrite if provided
        const o = txt("llm-opus"); if (o) payload["llm.opus_model"] = o;
        const h = txt("llm-haiku"); if (h) payload["llm.haiku_model"] = h;
    } else {
        const u = txt("llm-ourl"); if (u) payload["llm.ollama_url"] = u;
        const m = txt("llm-omodel"); if (m) payload["llm.ollama_default_model"] = m;
    }
    const r = await api("PUT", "/api/config", payload);
    if (r.ok) {
        // Don't keep the raw key in client state — drop it before caching.
        delete payload["llm.api_key"];
        state.config = Object.assign({}, state.config || {}, payload);
        consoleLog("success", "llm backend saved");
        toast("Backend saved.", "success");
        ensureAgents();
    } else { toast("Save failed (admin only).", "error"); }
}

function startAgentPoll() { stopAgentPoll(); state.agentPoll = setInterval(agentTick, 1500); }
function stopAgentPoll() { if (state.agentPoll) { clearInterval(state.agentPoll); state.agentPoll = null; } }
async function agentTick() {
    if (currentRoute() !== "agents") { stopAgentPoll(); return; }
    if (state.target) {
        const r = await api("GET", "/api/agent/state?target=" + encodeURIComponent(state.target));
        if (r.ok) state.agents.data = r.data.data || r.data;
    }
    if (state.agentLog.open && state.target) {
        const lr = await api("GET", "/api/agent/logs?target=" + encodeURIComponent(state.target));
        if (lr.ok) {
            const dd = (lr.data && (lr.data.data || lr.data)) || {};
            const logs = dd.logs || [];
            state.agentLog.text = Array.isArray(logs) ? logs.join("\n") : String(logs);
        }
    }
    // Update only the live region + log pre (leaves the backend-config inputs alone).
    const live = document.getElementById("agent-live");
    if (live) live.innerHTML = renderAgentLive();
    const pre = document.getElementById("agent-log-pre");
    if (pre && state.agentLog.open) { pre.textContent = state.agentLog.text || "(no run yet)"; pre.scrollTop = pre.scrollHeight; }
    if (!(state.agents.data && state.agents.data.running)) stopAgentPoll();
}

// ── Pipeline command center (drives scripts/recon/NN-*.sh) ───────
PAGES.pipeline = function () {
    if (!state.target) {
        return `
          ${renderWorkspaceHead("Run Pipeline", "Recon", "Execute the kill chain phase by phase.")}
          ${panel("No target loaded", `<div class="tbl-empty">Load a target on <span class="mono">Target → Intake</span> first, then run phases here.</div>`)}`;
    }
    const d = state.pipeline.data;
    const scopeOk = !!(state.scope && state.scope.active);
    const runInfo = (d && d.datestamp) ? `run <span class="mono">${escapeHTML(d.datestamp)}</span>` : "no run yet";
    return `
      ${renderWorkspaceHead("Run Pipeline", "Recon", "Drive the shell kill chain — live logs stream here and results land in the app.")}
      <div class="pipeline-bar">
        <div>
          target <span class="mono text-purple">${escapeHTML(state.target)}</span> · ${runInfo} ·
          ${scopeOk ? `<span class="badge badge-success">SCOPE ENFORCED</span>`
                    : `<span class="badge badge-error">SCOPE NOT WIRED</span>`}
          ${state.freshNext ? ` · <span class="badge badge-processing">FRESH RUN ARMED</span>` : ""}
        </div>
        <div style="display:flex; gap:6px;">
          <button class="btn btn-sm btn-ghost" onclick="ReconForge.pipelineNewRun()">New run</button>
          <button class="btn btn-sm btn-ghost" onclick="ReconForge.refreshPipeline()">↻ Refresh</button>
        </div>
      </div>
      ${renderPipelineLogPanel()}
      <div id="pipeline-list">${renderPipelineList()}</div>
      ${state.guideMode ? guidePanel("How this runs", "Each Run executes scripts/recon/NN-*.sh on the host as a job. scope_guard gates the target before anything spawns; the script also receives SCOPE_FILE. Logs stream here live; phases marked DB ingest their hosts/findings so the Asset Map and reports populate. Phases share one run timestamp until you click New run.") : ""}
    `;
};

function renderPipelineLogPanel() {
    const pl = state.phaseLog;
    const label = pl.phaseId ? pipelinePhaseLabel(pl.phaseId) : "—";
    return `
      <div class="panel" id="pipeline-log-wrap" ${pl.open ? "" : "hidden"}>
        <div class="panel-head">
          <span>live log · ${escapeHTML(label)}</span>
          <button class="console-btn" onclick="ReconForge.closePhaseLog()">hide</button>
        </div>
        <div class="panel-body"><pre id="phase-log-pre" class="phase-log">${escapeHTML(pl.text || "(waiting for output…)")}</pre></div>
      </div>`;
}

function pipelinePhaseLabel(id) {
    const d = state.pipeline.data;
    const p = (d && d.phases || []).find(x => x.id === id);
    return p ? `${p.num} ${p.label}` : id;
}

function renderPipelineList() {
    const d = state.pipeline.data;
    if (!d) return `<div class="tbl-empty">Loading phases…</div>`;
    return `<div class="phase-cards">${(d.phases || []).map(renderPhaseCard).join("")}</div>`;
}

function renderPhaseCard(p) {
    const st = p.status || "";
    const running = st === "running";
    const tools = (p.tools || []).map(t => `<span class="phase-tool">${escapeHTML(t)}</span>`).join("");
    return `
      <div class="phase-card" data-state="${st}">
        <div class="phase-card-head">
          <span class="phase-num mono">${escapeHTML(p.num)}</span>
          <span class="phase-label">${escapeHTML(p.label)}</span>
          <span class="risk-badge" data-risk="${p.risk}">${p.risk.toUpperCase()}</span>
          ${p.ingests ? `<span class="badge badge-muted" title="results ingest into the database">DB</span>` : ""}
          ${phaseStatusBadge(st, p.added)}
        </div>
        <div class="phase-tools">${tools}</div>
        <div class="phase-actions">
          ${running
            ? `<button class="btn btn-sm btn-ghost" onclick="ReconForge.cancelPhase('${p.job_id}')">■ Cancel</button>`
            : `<button class="btn btn-sm btn-primary" onclick="ReconForge.runPhase('${p.id}')">▸ Run</button>`}
          ${p.job_id ? `<button class="btn btn-sm btn-ghost" onclick="ReconForge.openPhaseLog('${p.id}')">logs</button>` : ""}
        </div>
      </div>`;
}

function phaseStatusBadge(st, added) {
    if (st === "running")   return `<span class="badge badge-processing">RUNNING</span>`;
    if (st === "completed") return `<span class="badge badge-success">DONE${added ? ` +${added}` : ""}</span>`;
    if (st === "failed")    return `<span class="badge badge-error">FAILED</span>`;
    if (st === "cancelled") return `<span class="badge badge-muted">CANCELLED</span>`;
    return `<span class="badge badge-muted">IDLE</span>`;
}

async function ensurePipeline() {
    if (!state.pipeline) state.pipeline = { data: null };
    if (!state.target) { if (currentRoute() === "pipeline") renderWorkspace(); return; }
    const r = await api("GET", "/api/pipeline?target=" + encodeURIComponent(state.target));
    if (r.ok) state.pipeline.data = r.data.data || r.data;
    if (currentRoute() === "pipeline") renderWorkspace();
    if (((state.pipeline.data && state.pipeline.data.phases) || []).some(p => p.status === "running")) {
        startPipelinePoll();
    }
}
function refreshPipeline() { ensurePipeline(); }

async function runPhase(phaseId) {
    if (!state.target) { toast("Load a target first.", "error"); return; }
    const r = await api("POST", "/api/pipeline/run",
                        { target: state.target, phase: phaseId, fresh: !!state.freshNext });
    if (r.ok && r.data && r.data.success) {
        state.freshNext = false;
        state.phaseLog = { phaseId, text: "(waiting for output…)", open: true };
        consoleLog("success", "phase queued: " + phaseId);
        toast("Phase queued: " + phaseId, "success");
        await ensurePipeline();
        startPipelinePoll();
    } else {
        const msg = (r.data && r.data.message) || ("HTTP " + r.status);
        consoleLog("error", "phase run refused: " + msg);
        toast("Run refused: " + msg, "error");
    }
}

async function cancelPhase(jobId) {
    if (!jobId) return;
    await api("POST", "/api/jobs/" + jobId + "/cancel");
    consoleLog("log", "phase cancel requested");
    ensurePipeline();
}

function openPhaseLog(phaseId) {
    state.phaseLog = { phaseId, text: "(loading…)", open: true };
    renderWorkspace();
    pipelineTick();
}
function closePhaseLog() { state.phaseLog.open = false; renderWorkspace(); }
function pipelineNewRun() { state.freshNext = true; toast("Next phase starts a fresh run.", "info"); renderWorkspace(); }

function startPipelinePoll() { stopPipelinePoll(); state.pipelinePoll = setInterval(pipelineTick, 1500); }
function stopPipelinePoll() { if (state.pipelinePoll) { clearInterval(state.pipelinePoll); state.pipelinePoll = null; } }

async function pipelineTick() {
    if (currentRoute() !== "pipeline") { stopPipelinePoll(); return; }
    if (state.target) {
        const pr = await api("GET", "/api/pipeline?target=" + encodeURIComponent(state.target));
        if (pr.ok) state.pipeline.data = pr.data.data || pr.data;
    }
    if (state.phaseLog.phaseId && state.phaseLog.open && state.target) {
        const lr = await api("GET", "/api/pipeline/logs?target=" + encodeURIComponent(state.target) +
                                    "&phase=" + encodeURIComponent(state.phaseLog.phaseId));
        if (lr.ok) {
            const dd = (lr.data && (lr.data.data || lr.data)) || {};
            const logs = dd.logs || [];
            state.phaseLog.text = Array.isArray(logs) ? logs.join("\n") : String(logs);
        }
    }
    // Targeted DOM updates so the live tick doesn't rebuild the whole page.
    const listEl = document.getElementById("pipeline-list");
    if (listEl) listEl.innerHTML = renderPipelineList();
    const pre = document.getElementById("phase-log-pre");
    if (pre && state.phaseLog.open) { pre.textContent = state.phaseLog.text || "(waiting for output…)"; pre.scrollTop = pre.scrollHeight; }
    const anyRunning = ((state.pipeline.data && state.pipeline.data.phases) || []).some(p => p.status === "running");
    if (!anyRunning) stopPipelinePoll();
}

PAGES.settings = function () {
    const c = state.config || {};
    const proxy = c.opsec_http_proxy || "";
    const rl = (c.opsec_rate_limit == null ? 50 : c.opsec_rate_limit);
    const delay = c.opsec_delay || "";
    const randUA = (c.opsec_random_agent !== false);
    return `
      ${renderWorkspaceHead("Settings", "Admin", "System configuration.")}
      ${panel("OPSEC — rule #1 (applied to every target-touching scan)", `
        <div class="form-grid">
          <div><label class="form-label">HTTP/SOCKS proxy</label><input id="opsec-proxy" type="text" value="${escapeAttr(proxy)}" placeholder="socks5://127.0.0.1:9050" spellcheck="false"></div>
          <div><label class="form-label">Rate limit (req/s)</label><input id="opsec-rl" type="number" value="${escapeAttr(String(rl))}" min="1"></div>
          <div><label class="form-label">Per-request delay / jitter</label><input id="opsec-delay" type="text" value="${escapeAttr(delay)}" placeholder="200ms (monitor default)" spellcheck="false"></div>
          <div><label class="form-label">Random User-Agent</label>
            <label class="radio-pill ${randUA ? "selected" : ""}"><input id="opsec-rua" type="checkbox" ${randUA ? "checked" : ""} style="margin-right:6px;">rotate UA (off when a program UA is pinned)</label>
          </div>
        </div>
        <div class="form-help">Proxy routes <em>every</em> tool (curl, httpx, nuclei, dnsx, nikto, agent runner). Rate limit + jitter throttle target-touching tools. Program-identity headers (e.g. <span class="mono">X-Intigriti-Username</span>) are attached automatically from your platform handles. Passive sources never touch the target.</div>
        <div class="spacer-md"></div>
        <button class="btn btn-primary" onclick="ReconForge.saveOpsec()">▸ Save OPSEC</button>
      `)}
      ${panel("API keys", `
        <div class="form-grid">
          <div><label class="form-label">GitHub token</label><input type="password" placeholder="ghp_..."></div>
          <div><label class="form-label">Chaos key</label><input type="password" placeholder="..."></div>
          <div><label class="form-label">Shodan key</label><input type="password" placeholder="..."></div>
          <div><label class="form-label">SecurityTrails key</label><input type="password" placeholder="..."></div>
          <div><label class="form-label">Interactsh URL</label><input type="text" placeholder="oast.yourdomain.com"></div>
          <div><label class="form-label">AWS profile</label><input type="text" placeholder="default"></div>
        </div>
        <div class="spacer-md"></div>
        <button class="btn btn-primary" onclick="ReconForge.toast('Settings saved.', 'success')">▸ Save</button>
      `)}
      ${panel("Pipeline tuning", `
        <div class="form-grid">
          <div><label class="form-label">Threads</label><input type="number" value="10"></div>
          <div><label class="form-label">Rate limit (req/s)</label><input type="number" value="50"></div>
          <div><label class="form-label">First sub timeout (s)</label><input type="number" value="600"></div>
          <div><label class="form-label">Min enum tools required</label><input type="number" value="2"></div>
        </div>
      `)}
    `;
};

PAGES.users = function () {
    return `
      ${renderWorkspaceHead("Users", "Admin", "Operators with console access.")}
      ${panel("Operator roster", `<div class="tbl-empty">Loading…</div>`)}
    `;
};

PAGES.backups = function () {
    return `
      ${renderWorkspaceHead("Backups", "Admin", "Database snapshots.")}
      ${panel("Snapshots", `<div class="tbl-empty">No snapshots yet.</div>`)}
    `;
};

PAGES.logs = function () {
    return `
      ${renderWorkspaceHead("System Logs", "Admin", "Server diagnostic stream.")}
      ${panel("Stream", `<div class="tbl-empty">See Activity Console at the bottom for live events.</div>`)}
    `;
};

// ════════════════════════════════════════════════════════════════
// ── [agent: toolchain] ── Toolchain health + Workflows pages
// Wire the otherwise-unused /api/v2/tools/* and /api/v2/workflows
// endpoints. v2 responses are sent RAW (no _ok envelope), so the
// payload is r.data directly; we still fall back to r.data.data so a
// future envelope change can't break these.
// ════════════════════════════════════════════════════════════════

// Human-readable labels for the tool category keys emitted by tools/detect.py.
const TOOLCHAIN_CATEGORY_LABELS = {
    subdomain:  "Subdomain enumeration",
    dns_http:   "DNS / HTTP",
    screenshot: "Screenshots",
    vuln:       "Vulnerability scanning",
    fuzz:       "Crawl / fuzz",
    api:        "API / Swagger",
    graphql:    "GraphQL",
    cloud:      "Cloud",
    js:         "JS analysis",
    other:      "Other",
};

// ── Toolchain page ───────────────────────────────────────────────
PAGES.toolchain = function () {
    const tc = state.toolchain;
    if (!tc || !tc.loaded) {
        return `
          ${renderWorkspaceHead("Toolchain Health", "Admin", "Which of the integrated recon tools are installed on this host.")}
          ${panel("Detecting tools…", `<div class="tbl-empty">Scanning PATH for the tool catalog…</div>`)}`;
    }
    const tools   = Array.isArray(tc.tools) ? tc.tools : [];
    const summary = tc.summary || {};
    const total     = summary.total     != null ? summary.total     : tools.length;
    const installed = summary.installed != null ? summary.installed : tools.filter(t => t && t.installed).length;
    const missing   = summary.missing   != null ? summary.missing   : (total - installed);

    // Map missing-tool name → install command from the install_plan (best
    // match: detect.py emits each tool's own install_cmd, but the plan
    // coalesces apt installs, so we prefer the per-tool install_cmd and fall
    // back to the human plan block below).
    const head = renderWorkspaceHead("Toolchain Health", "Admin",
        "Which of the integrated recon tools are installed on this host.");
    const metrics = renderMetrics([
        { label: "Tools integrated", value: total },
        { label: "Installed",        value: installed, kind: installed ? "success" : "" },
        { label: "Missing",          value: missing,   kind: missing ? "error" : "" },
    ]);

    let body = "";
    if (!tools.length) {
        body = panel("Tool catalog", `<div class="tbl-empty">No tools reported by the detector.</div>`);
    } else {
        // Group tools by category, preserving a stable category order.
        const groups = {};
        tools.forEach(t => {
            const cat = (t && t.category) || "other";
            (groups[cat] = groups[cat] || []).push(t);
        });
        const order = Object.keys(TOOLCHAIN_CATEGORY_LABELS).filter(c => groups[c]);
        Object.keys(groups).forEach(c => { if (!order.includes(c)) order.push(c); });

        body = order.map(cat => {
            const rows = groups[cat].slice().sort((a, b) =>
                String((a && a.name) || "").localeCompare(String((b && b.name) || "")));
            const instCount = rows.filter(t => t && t.installed).length;
            const label = TOOLCHAIN_CATEGORY_LABELS[cat] || cat;
            return panel(`${label} · ${instCount}/${rows.length}`, `
              <table class="tbl tc-tbl">
                <thead><tr><th>Tool</th><th>Status</th><th>Binary</th><th>Install</th></tr></thead>
                <tbody>
                  ${rows.map(renderToolRow).join("")}
                </tbody>
              </table>
            `);
        }).join("");
    }

    return `
      ${head}
      ${metrics}
      ${panel("Detection", `
        <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
          <button class="btn btn-sm btn-primary" onclick="ReconForge.refreshToolchain()">↻ Refresh</button>
          <span class="text-sec" style="font-size:12px;">${escapeHTML(String(installed))} of ${escapeHTML(String(total))} tools detected on PATH.</span>
        </div>
        ${missing ? `<div class="form-help">Missing tools show a copy-paste install command. Commands run on the host — ReconForge never installs anything itself.</div>` : ""}
      `)}
      ${body}
      ${state.guideMode ? guidePanel("Why this matters", "ReconForge integrates dozens of recon tools but only runs the ones present on PATH. A missing tool is silently skipped by the pipeline — so a gap here is a blind spot in your recon. Install the missing binaries (go/apt/pip commands shown) to light up the full kill chain.") : ""}
    `;
};

function renderToolRow(t) {
    if (!t) return "";
    const name   = (t.name || t.binary || "—").toString();
    const binary = (t.binary || "").toString();
    if (t.installed) {
        const ver = t.version ? `<span class="badge badge-success">v${escapeHTML(String(t.version))}</span>`
                              : `<span class="badge badge-success">INSTALLED</span>`;
        return `
          <tr>
            <td>${escapeHTML(name)}</td>
            <td>${ver}</td>
            <td class="mono text-sec">${escapeHTML(binary)}</td>
            <td class="text-mute" style="font-size:11px;">—</td>
          </tr>`;
    }
    // Missing → surface the per-tool install command with a copy button.
    const cmdArr = Array.isArray(t.install_cmd) ? t.install_cmd : null;
    const cmd    = cmdArr ? cmdArr.join(" ") : "";
    const method = (t.install_method || "manual").toString();
    const installCell = cmd
        ? `<code class="tc-install mono">${escapeHTML(cmd)}</code>
           <button class="btn btn-sm btn-ghost" onclick="ReconForge.copyToolInstall('${escapeAttr(binary)}')">copy</button>`
        : `<span class="text-mute" style="font-size:11px;">${escapeHTML(t.notes || "manual install")}</span>`;
    return `
      <tr>
        <td>${escapeHTML(name)}</td>
        <td><span class="badge badge-muted">MISSING</span> <span class="badge badge-muted">${escapeHTML(method)}</span></td>
        <td class="mono text-sec">${escapeHTML(binary)}</td>
        <td class="tc-install-cell">${installCell}</td>
      </tr>`;
}

async function ensureToolchain() {
    // Fetch detection + install plan in parallel. v2 payload is raw (r.data).
    const [health, plan] = await Promise.all([
        api("GET",  "/api/v2/tools/health"),
        api("POST", "/api/v2/tools/install_plan"),
    ]);
    const hd = (health.ok && health.data) ? (health.data.data || health.data) : {};
    const pd = (plan.ok   && plan.data)   ? (plan.data.data   || plan.data)   : {};
    state.toolchain = {
        tools:   Array.isArray(hd.tools) ? hd.tools : [],
        summary: hd.summary || {},
        plan:    Array.isArray(pd.plan) ? pd.plan : [],
        human:   pd.human || "",
        loaded:  true,
    };
    if (!health.ok) consoleLog("error", "tool health fetch failed: HTTP " + health.status);
    if (currentRoute() === "toolchain") renderWorkspace();
}

function refreshToolchain() {
    state.toolchain = null;
    renderWorkspace();
    // Force a server-side re-scan rather than the 60s cache.
    (async () => {
        const [health, plan] = await Promise.all([
            api("GET",  "/api/v2/tools/health?refresh=1"),
            api("POST", "/api/v2/tools/install_plan"),
        ]);
        const hd = (health.ok && health.data) ? (health.data.data || health.data) : {};
        const pd = (plan.ok   && plan.data)   ? (plan.data.data   || plan.data)   : {};
        state.toolchain = {
            tools:   Array.isArray(hd.tools) ? hd.tools : [],
            summary: hd.summary || {},
            plan:    Array.isArray(pd.plan) ? pd.plan : [],
            human:   pd.human || "",
            loaded:  true,
        };
        if (health.ok) { consoleLog("success", "toolchain re-scanned"); }
        else { toast("Tool detection failed.", "error"); }
        if (currentRoute() === "toolchain") renderWorkspace();
    })();
}

function copyToolInstall(binary) {
    const tc = state.toolchain || {};
    const t = (tc.tools || []).find(x => x && x.binary === binary);
    const cmd = (t && Array.isArray(t.install_cmd)) ? t.install_cmd.join(" ") : "";
    if (!cmd) { toast("No install command for this tool.", "error"); return; }
    copyToClipboard(cmd);
}

// ── Workflows page ───────────────────────────────────────────────
PAGES.workflows = function () {
    const wf = state.workflows;
    if (!wf || !wf.loaded) {
        return `
          ${renderWorkspaceHead("Workflows", "Recon", "Named tool bundles the pipeline can run, with their safety envelope.")}
          ${panel("Loading workflows…", `<div class="tbl-empty">Fetching registered workflows…</div>`)}`;
    }
    const list = Array.isArray(wf.list) ? wf.list : [];
    const head = renderWorkspaceHead("Workflows", "Recon",
        "Named tool bundles the pipeline can run, with their safety envelope.");
    if (!list.length) {
        return `${head}${panel("Registered workflows", `<div class="tbl-empty">No workflows registered.</div>`)}`;
    }
    const metrics = renderMetrics([
        { label: "Workflows",   value: list.length },
        { label: "Auto-run",    value: list.filter(w => w && !w.requires_approval).length, kind: "success" },
        { label: "Need approval", value: list.filter(w => w && w.requires_approval).length, kind: "processing" },
    ]);
    const cards = list.map(renderWorkflowCard).join("");
    return `
      ${head}
      ${metrics}
      <div class="wf-cards">${cards}</div>
      ${state.guideMode ? guidePanel("How workflows run", "A workflow bundles a mode + an ordered tool list + a safety envelope (traffic level, default rate-limit, scope requirement). The pipeline and pre-flight modal read these to know what a job will do before it runs. Workflows marked APPROVAL pause for an explicit operator confirm; SCOPE workflows refuse to dispatch until Scope Guard passes.") : ""}
    `;
};

function trafficBadge(level) {
    const map = {
        none:      ["success",    "NO TRAFFIC"],
        low:       ["success",    "LOW TRAFFIC"],
        moderate:  ["processing", "MODERATE"],
        intrusive: ["error",      "INTRUSIVE"],
    };
    const [cls, label] = map[level] || ["muted", String(level || "—").toUpperCase()];
    return `<span class="badge badge-${cls}">${label}</span>`;
}

function renderWorkflowCard(w) {
    if (!w) return "";
    const id    = (w.id || "").toString();
    const name  = (w.name || id || "workflow").toString();
    const desc  = (w.description || "").toString();
    const mode  = (w.mode || "").toString();
    const safety = w.safety || {};
    const steps  = Array.isArray(w.tools) ? w.tools : [];
    const inputs  = Array.isArray(w.inputs)  ? w.inputs  : [];
    const outputs = Array.isArray(w.outputs) ? w.outputs : [];
    const expanded = state.workflows && state.workflows.expanded === id;

    const tags = [
        trafficBadge(safety.traffic_level),
        w.requires_approval ? `<span class="badge badge-processing">APPROVAL</span>` : `<span class="badge badge-success">AUTO</span>`,
        w.scope_required    ? `<span class="badge badge-muted">SCOPE</span>` : "",
        (safety.default_rate_limit_rps != null && safety.default_rate_limit_rps > 0)
            ? `<span class="badge badge-muted">${escapeHTML(String(safety.default_rate_limit_rps))} rps</span>` : "",
    ].filter(Boolean).join(" ");

    const stepList = steps.length
        ? `<div class="wf-steps">${steps.map(s => {
              const sid = (s && s.id) || "?";
              const opt = (s && s.optional) ? ` <span class="wf-step-opt">opt</span>` : "";
              return `<span class="wf-step mono" title="${escapeAttr((s && s.description) || "")}">${escapeHTML(sid)}${opt}</span>`;
          }).join("")}</div>`
        : `<div class="wf-steps wf-steps-empty text-mute">no tools declared — operator selects per run</div>`;

    const detail = expanded ? `
      <div class="wf-detail">
        <dl class="forge-meta">
          <dt>Mode</dt>    <dd class="mono">${escapeHTML(mode || "—")}</dd>
          <dt>Inputs</dt>  <dd class="mono text-sec">${inputs.length ? escapeHTML(inputs.join(", ")) : "—"}</dd>
          <dt>Outputs</dt> <dd class="mono text-sec">${outputs.length ? escapeHTML(outputs.join(", ")) : "—"}</dd>
          <dt>Scope</dt>   <dd>${w.scope_required ? "required before dispatch" : "not required"}</dd>
          <dt>Approval</dt><dd>${w.requires_approval ? "operator must confirm" : "runs automatically"}</dd>
        </dl>
        ${steps.length ? `
          <table class="tbl wf-step-tbl">
            <thead><tr><th>Tool</th><th>Role</th><th>Step</th></tr></thead>
            <tbody>
              ${steps.map(s => `
                <tr>
                  <td class="mono">${escapeHTML((s && s.id) || "—")}</td>
                  <td class="text-sec">${escapeHTML((s && s.description) || "—")}</td>
                  <td>${(s && s.optional) ? `<span class="badge badge-muted">OPTIONAL</span>` : `<span class="badge badge-success">CORE</span>`}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        ` : ""}
      </div>
    ` : "";

    return `
      <div class="wf-card ${expanded ? "open" : ""}">
        <div class="wf-card-head">
          <span class="wf-name">${escapeHTML(name)}</span>
          <span class="wf-tags">${tags}</span>
        </div>
        ${desc ? `<div class="wf-desc text-sec">${escapeHTML(desc)}</div>` : ""}
        ${stepList}
        ${detail}
        <div class="wf-actions">
          <button class="btn btn-sm btn-ghost" onclick="ReconForge.toggleWorkflow('${escapeAttr(id)}')">${expanded ? "▾ Hide detail" : "▸ Detail"}</button>
        </div>
      </div>`;
}

async function ensureWorkflows() {
    const r = await api("GET", "/api/v2/workflows");
    const d = (r.ok && r.data) ? (r.data.data || r.data) : {};
    const prev = state.workflows || {};
    state.workflows = {
        list:     Array.isArray(d.workflows) ? d.workflows : [],
        expanded: prev.expanded || null,   // preserve an open card across reloads
        loaded:   true,
    };
    if (!r.ok) consoleLog("error", "workflows fetch failed: HTTP " + r.status);
    if (currentRoute() === "workflows") renderWorkspace();
}

function toggleWorkflow(id) {
    if (!state.workflows) return;
    state.workflows.expanded = (state.workflows.expanded === id) ? null : id;
    renderWorkspace();
}
// ── [agent: toolchain] ── end Toolchain + Workflows block ─────────

// ── Components ────────────────────────────────────────────────────
function renderWorkspaceHead(title, eyebrow, sub) {
    return `
      <div class="workspace-header">
        <div>
          <div class="workspace-eyebrow">${escapeHTML(eyebrow)}</div>
          <h1 class="workspace-title">${escapeHTML(title)}</h1>
          ${sub ? `<div class="text-sec" style="margin-top:4px;">${escapeHTML(sub)}</div>` : ""}
        </div>
        <div class="workspace-actions">
          <button class="btn btn-ghost btn-sm" onclick="ReconForge.openPalette()">⌘K palette</button>
          <button class="btn btn-ghost btn-sm" onclick="ReconForge.toggleGuide()">${state.guideMode ? "guide on" : "guide off"}</button>
        </div>
      </div>
    `;
}

function renderMetrics(metrics) {
    return `<div class="metrics-grid">${metrics.map(m => `
      <div class="metric ${m.kind || ""}">
        <div class="metric-label">${escapeHTML(m.label)}</div>
        <div class="metric-value">${escapeHTML(String(m.value))}</div>
        ${m.sub ? `<div class="metric-sub">${escapeHTML(m.sub)}</div>` : ""}
      </div>
    `).join("")}</div>`;
}

function renderTargetStatusPanel() {
    return panel("Target status", `
      <div class="status-panel">
        <dt>Target</dt>    <dd>${escapeHTML(state.target || "—")}</dd>
        <dt>Scope</dt>     <dd>${state.target ? `<span class="badge badge-success">VALIDATED</span>` : `<span class="badge badge-muted">PENDING</span>`}</dd>
        <dt>Risk mode</dt> <dd><span class="risk-badge" data-risk="${state.riskMode}">${state.riskMode.toUpperCase()}</span></dd>
        <dt>Workspace</dt> <dd>${escapeHTML(state.workspace || "—")}</dd>
        <dt>Export</dt>    <dd class="mono" style="font-size: 11px;">${escapeHTML(state.vaultPath || "—")}</dd>
      </div>
    `);
}

function renderReconChecklist() {
    const items = [
        { id: "target",    label: "Target loaded",          done: !!state.target,                   current: !state.target },
        { id: "scope",     label: "Scope defined",          done: !!(state.target && state.workspace), current: !!state.target && !state.workspace },
        { id: "passive",   label: "Passive recon",          done: false, current: false },
        { id: "active",    label: "Active recon",           done: false, current: false },
        { id: "urls",      label: "URL collection",         done: false, current: false },
        { id: "js",        label: "JS mining",              done: false, current: false },
        { id: "params",    label: "Parameter discovery",    done: false, current: false },
        { id: "findings",  label: "Findings drafted",       done: false, current: false },
        { id: "export",    label: "Evidence exported",      done: false, current: false },
    ];
    return panel("Recon checklist", `
      <ul class="checklist">
        ${items.map(i => `
          <li class="${i.done ? "done" : ""}">
            <span class="check ${i.done ? "done" : ""} ${i.current ? "current" : ""}">${i.done ? "✓" : (i.current ? "•" : " ")}</span>
            <span class="label">${escapeHTML(i.label)}</span>
          </li>
        `).join("")}
      </ul>
    `);
}

function renderEvidenceTimeline(events) {
    if (!events || !events.length) {
        return panel("Timeline", `<div class="tbl-empty">No events yet.</div>`);
    }
    return panel("Timeline", `
      <ul class="timeline">
        ${events.map(e => `
          <li>
            <span class="t-time">${escapeHTML(e.time)}</span>
            <span class="t-msg"><span class="t-kind">${escapeHTML(e.kind || "log")}</span>${escapeHTML(e.text)}</span>
          </li>
        `).join("")}
      </ul>
    `);
}

function renderVaultPanel() {
    const root = state.vaultPath || "ResearchVault/BugBounty/" + (state.workspace || "<workspace>");
    return panel("Vault export", `
      <div class="vault">
        <div class="vault-path">${escapeHTML(root)}</div>
        <ul>
          <li class="${state.target ? "done" : "todo"}">00_Target.md</li>
          <li class="${state.workspace ? "done" : "todo"}">01_Scope.md</li>
          <li class="todo">02_Recon.md</li>
          <li class="todo">03_Assets.md</li>
          <li class="todo">04_Testing.md</li>
          <li class="todo">05_Evidence.md</li>
          <li class="todo">06_Report_Draft.md</li>
          <li class="todo">commands/</li>
          <li class="todo">findings/</li>
          <li class="todo">artifacts/</li>
        </ul>
      </div>
    `);
}

function renderJobsTable(rows) {
    return `
      <table class="tbl">
        <thead><tr><th>Domain</th><th>Status</th><th>Step</th><th>Subdomains</th><th>Started</th></tr></thead>
        <tbody>
          ${rows.map(j => `
            <tr>
              <td class="mono">${escapeHTML(j.domain || "—")}</td>
              <td>${statusBadge(j.status)}</td>
              <td class="mono text-sec">${escapeHTML(j.current_step || "—")}</td>
              <td>${j.subdomain_count || 0}</td>
              <td class="mono text-sec">${escapeHTML(j.started_at || j.queued_at || "—")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
}

function statusBadge(s) {
    const map = {
        running:   ["processing", "RUNNING"],
        pending:   ["muted",      "PENDING"],
        completed: ["success",    "DONE"],
        failed:    ["error",      "FAILED"],
        cancelled: ["muted",      "CANCELLED"],
    };
    const [cls, label] = map[s] || ["muted", String(s || "—").toUpperCase()];
    return `<span class="badge badge-${cls}">${label}</span>`;
}

function panel(title, body) {
    return `
      <div class="panel">
        <div class="panel-head"><span>${escapeHTML(title)}</span></div>
        <div class="panel-body">${body}</div>
      </div>
    `;
}

function guidePanel(title, body) {
    return `
      <div class="panel" style="border-color: var(--accent-purple);">
        <div class="panel-head" style="color: var(--accent-purple);">
          <span>guide · ${escapeHTML(title)}</span>
          <span class="panel-tag">optional</span>
        </div>
        <div class="panel-body text-sec">${escapeHTML(body)}</div>
      </div>
    `;
}

function riskPill(value, label, selected) {
    return `
      <label class="radio-pill ${selected ? "selected" : ""}" onclick="ReconForge.setRisk('${value}')">
        ${escapeHTML(label)}
      </label>
    `;
}

function pageNotFound(route) {
    return () => `
      ${renderWorkspaceHead(route.toUpperCase(), "Coming Online", "This module is registered but not yet wired.")}
      ${panel("Status", `<div class="tbl-empty">Module <span class="mono">${escapeHTML(route)}</span> placeholder. Wire via PAGES.${escapeHTML(route)} in <span class="mono">ui/spa/app.js</span>.</div>`)}
    `;
}

// Methodology page template — used by passive/active/urls/js/test/* pages.
// Each command is an editable builder (inline-edit + autocomplete); baselines
// are the exact commands defined per page and are restorable via Reset.
function renderMethodologyPage(routeId, title, group, defaultRisk, commands) {
    let html = renderWorkspaceHead(title, group,
        "Editable command builders — type to get flag suggestions, ↵/Tab to accept, then copy or save.");
    html += `<div class="workspace-cols"><div>`;
    commands.forEach((c, i) => {
        html += renderForge({
            phase: title,
            risk: c.risk || defaultRisk,
            target: state.target || "<target>",
            outputDir: vaultSub(routeId),
            label: c.label,
            cmd: c.cmd,
            note: c.note,
            cmdId: routeId + "-" + i,
        });
    });
    html += `</div><div>`;
    html += renderTargetStatusPanel();
    html += renderSavedCommands();
    html += `</div></div>`;
    return html;
}

function renderForge(opts) {
    const riskBadge = `<span class="risk-badge" data-risk="${opts.risk}">${opts.risk.toUpperCase()}</span>`;
    const cmdId = opts.cmdId;
    CMD_BASELINES[cmdId] = opts.cmd;
    CMD_LABELS[cmdId]    = opts.label;
    const saved  = cmdEditGet(cmdId);
    const cmd    = (saved != null) ? saved : opts.cmd;
    const edited = (saved != null && saved !== opts.cmd);
    return `
      <div class="forge">
        <div class="forge-head">
          <span>${escapeHTML(opts.label)}${edited ? ` <span class="forge-edited">edited</span>` : ""}</span>
          ${riskBadge}
        </div>
        <dl class="forge-meta">
          <dt>Phase</dt>  <dd>${escapeHTML(opts.phase)}</dd>
          <dt>Target</dt> <dd>${escapeHTML(opts.target)}</dd>
          <dt>Output</dt> <dd class="text-mute">${escapeHTML(opts.outputDir)}</dd>
        </dl>
        <div class="forge-cmd-wrap">
          <span class="forge-cmd-prompt">$</span>
          <textarea class="forge-cmd-edit mono" data-cmd="${cmdId}" spellcheck="false" autocomplete="off"
            rows="${cmdRows(cmd)}"
            oninput="ReconForge.onCmdInput(event)"
            onkeydown="ReconForge.onCmdKey(event)"
            onblur="ReconForge.onCmdBlur(event)">${escapeHTML(cmd)}</textarea>
        </div>
        <div class="forge-actions">
          <button class="btn btn-sm btn-primary" onclick="ReconForge.copyCmd('${cmdId}')">▸ Copy</button>
          <button class="btn btn-sm btn-ghost" onclick="ReconForge.saveCmdToWorkspace('${cmdId}')">Save to Workspace</button>
          <button class="btn btn-sm btn-ghost" onclick="ReconForge.addCmdToNotes('${cmdId}')">Add to Notes</button>
          ${edited ? `<button class="btn btn-sm btn-ghost" onclick="ReconForge.resetCmd('${cmdId}')">Reset</button>` : ""}
        </div>
        ${state.guideMode && opts.note ? `
          <div class="forge-guide">
            <div class="forge-guide-title">why this matters</div>
            ${escapeHTML(opts.note)}
          </div>
        ` : ""}
      </div>
    `;
}

// ── Command builder: persistence + saved-command list ─────────────
const CMD_BASELINES = {};   // cmdId -> baseline command text (for Reset)
const CMD_LABELS    = {};   // cmdId -> human label

function cmdRows(text) {
    const n = String(text || "").split("\n").length;
    return Math.max(2, Math.min(8, n + 1));
}
function cmdEditKey(cmdId) { return "cmdedit:" + (state.workspace || state.target || "default") + ":" + cmdId; }
function cmdEditGet(cmdId) { return LS.get(cmdEditKey(cmdId), null); }
function cmdEditSet(cmdId, text) {
    // Drop the override when it equals the baseline so the card stops showing
    // "edited" / Reset once the operator types it back to default.
    LS.set(cmdEditKey(cmdId), text === CMD_BASELINES[cmdId] ? null : text);
}
function cmdFieldEl(cmdId)    { return document.querySelector('.forge-cmd-edit[data-cmd="' + cmdId + '"]'); }
function currentCmdText(cmdId) {
    const el = cmdFieldEl(cmdId);
    if (el) return el.value;
    const saved = cmdEditGet(cmdId);
    return (saved != null) ? saved : (CMD_BASELINES[cmdId] || "");
}

function copyCmd(cmdId)  { copyToClipboard(currentCmdText(cmdId)); }
function resetCmd(cmdId) {
    LS.set(cmdEditKey(cmdId), null);
    consoleLog("log", "command reset to baseline");
    renderWorkspace();
}
function saveCmdToWorkspace(cmdId) {
    const cmd = currentCmdText(cmdId).trim();
    if (!cmd) { toast("Nothing to save.", "error"); return; }
    const arr = wsList("commands");
    arr.unshift({ label: CMD_LABELS[cmdId] || "", cmd, route: currentRoute(), ts: Date.now() });
    if (arr.length > 100) arr.length = 100;
    wsSetList("commands", arr);
    consoleLog("success", "saved command → workspace");
    toast("Saved to workspace.", "success");
    renderWorkspace();
}
function addCmdToNotes(cmdId) {
    const cmd = currentCmdText(cmdId).trim();
    if (!cmd) { toast("Nothing to add.", "error"); return; }
    const k = wsKey("notes");
    const prev  = LS.get(k, "") || "";
    const stamp = new Date().toISOString().slice(0, 16).replace("T", " ");
    LS.set(k, prev + `\n## ${CMD_LABELS[cmdId] || "command"} (${stamp})\n${cmd}\n`);
    consoleLog("success", "appended command → notes");
    toast("Added to notes.", "success");
}

// Workspace-scoped localStorage (saved commands + notes live per workspace).
function wsKey(kind)        { return "ws:" + (state.workspace || state.target || "default") + ":" + kind; }
function wsList(kind)       { return LS.get(wsKey(kind), []) || []; }
function wsSetList(kind, a) { LS.set(wsKey(kind), a); }

function renderSavedCommands() {
    const saved = wsList("commands");
    if (!saved.length) {
        return panel("Saved commands", `<div class="tbl-empty">Save a command to pin it to this workspace.</div>`);
    }
    return panel(`Saved commands (${saved.length})`, `
      <ul class="saved-cmds">
        ${saved.map((c, i) => `
          <li>
            <div class="saved-cmd-top">
              <span class="saved-cmd-label">${escapeHTML(c.label || c.route || "command")}</span>
              <span class="saved-cmd-actions">
                <button class="btn btn-sm btn-ghost" onclick="ReconForge.copySaved(${i})">copy</button>
                <button class="btn btn-sm btn-ghost" onclick="ReconForge.removeSaved(${i})">✕</button>
              </span>
            </div>
            <code class="saved-cmd-text mono">${escapeHTML(c.cmd)}</code>
          </li>
        `).join("")}
      </ul>
    `);
}
function copySaved(i)   { const a = wsList("commands"); if (a[i]) copyToClipboard(a[i].cmd); }
function removeSaved(i) { const a = wsList("commands"); a.splice(i, 1); wsSetList("commands", a); renderWorkspace(); }

// ── Command autocomplete (inline flag suggestions) ────────────────
const AC = { box: null, field: null, items: [], sel: 0, open: false, word: "", wordStart: 0 };

// Curated catalog. "*" = global pipe/redirect helpers; per-tool keys list the
// flags worth reaching for. The page baselines already encode sane defaults —
// these just let the operator tune in-place without leaving the field.
const CMD_SUGGEST = {
    "*": [
        { t: "| anew out.txt", h: "dedupe + append-only-new" },
        { t: "| sort -u", h: "unique sort" },
        { t: "| tee out.txt", h: "save while streaming" },
        { t: "| httpx -silent", h: "probe live" },
        { t: "> out.txt", h: "redirect to file" },
    ],
    subfinder:  [ {t:"-all",h:"every source"},{t:"-recursive",h:"recurse"},{t:"-silent",h:"hosts only"},{t:"-active",h:"resolve live"},{t:"-rl 100",h:"rate limit"},{t:"-t 50",h:"threads"},{t:"-nW",h:"drop wildcards"},{t:"-o subs/sf.txt",h:"output"} ],
    amass:      [ {t:"enum",h:""},{t:"-passive",h:"no active DNS"},{t:"-active",h:"+ resolution"},{t:"-brute",h:"brute force"},{t:"-d",h:"domain"},{t:"-o out.txt",h:"output"},{t:"-config config.ini",h:"datasources"} ],
    "github-subdomains": [ {t:"-t $GITHUB_TOKEN",h:"token"},{t:"-e",h:"extended"},{t:"-raw",h:"raw output"},{t:"-o subs/gh.txt",h:"output"} ],
    httpx:      [ {t:"-title",h:""},{t:"-tech-detect",h:""},{t:"-status-code",h:""},{t:"-follow-redirects",h:""},{t:"-ip",h:""},{t:"-cname",h:""},{t:"-cdn",h:""},{t:"-jarm",h:"TLS fp"},{t:"-json",h:""},{t:"-silent",h:""},{t:"-mc 200,403",h:"match codes"},{t:"-rl 50",h:"rate limit"},{t:"-threads 50",h:""},{t:"-web-server",h:""},{t:"-location",h:""} ],
    nuclei:     [ {t:"-severity low,medium,high,critical",h:""},{t:"-tags cve,exposure",h:""},{t:"-rl 150",h:"rate limit"},{t:"-c 25",h:"concurrency"},{t:"-jsonl",h:""},{t:"-o out.jsonl",h:""},{t:"-t ~/nuclei-templates",h:"templates"},{t:"-etags fuzz",h:"exclude"},{t:"-timeout 10",h:""},{t:"-retries 2",h:""} ],
    dnsx:       [ {t:"-resp",h:"records"},{t:"-a",h:""},{t:"-cname",h:""},{t:"-silent",h:""},{t:"-rl 1000",h:""},{t:"-t 100",h:"threads"},{t:"-o out.txt",h:""} ],
    naabu:      [ {t:"-tp 1000",h:"top ports"},{t:"-p -",h:"all ports"},{t:"-rate 5000",h:""},{t:"-silent",h:""},{t:"-nmap-cli 'nmap -sV'",h:"hand to nmap"},{t:"-o ports.txt",h:""} ],
    puredns:    [ {t:"resolve",h:""},{t:"-r resolvers.txt",h:""},{t:"--rate-limit 1000",h:""},{t:"-w resolved.txt",h:"write"},{t:"--skip-wildcard-filter",h:""} ],
    gau:        [ {t:"--subs",h:"include subs"},{t:"--threads 200",h:""},{t:"--fc 404",h:"filter codes"},{t:"--blacklist png,jpg,css",h:""} ],
    waybackurls:[ {t:"| anew way.txt",h:"dedupe out"} ],
    unfurl:     [ {t:"-u keys",h:"unique keys"},{t:"-u domains",h:""},{t:"-u paths",h:""},{t:"-u values",h:""} ],
    katana:     [ {t:"-d 3",h:"depth"},{t:"-jc",h:"JS crawl"},{t:"-kf all",h:"known files"},{t:"-silent",h:""},{t:"-o urls.txt",h:""},{t:"-hl",h:"headless"} ],
    jsluice:    [ {t:"urls",h:""},{t:"secrets",h:""},{t:"tree",h:""} ],
    trufflehog: [ {t:"filesystem",h:""},{t:"git",h:""},{t:"--json",h:""},{t:"--no-update",h:""},{t:"--only-verified",h:"verified only"} ],
    tlsx:       [ {t:"-san",h:""},{t:"-cn",h:""},{t:"-silent",h:""},{t:"-resp-only",h:""},{t:"-o tls.txt",h:""} ],
    cdncheck:   [ {t:"-resp",h:""},{t:"-cdn",h:""},{t:"-waf",h:""},{t:"-cloud",h:""},{t:"-o cdn.txt",h:""} ],
    arjun:      [ {t:"-t 10",h:"threads"},{t:"--rate-limit 5",h:""},{t:"-oT params.txt",h:""},{t:"-m GET,POST",h:"methods"},{t:"--stable",h:"slow/accurate"} ],
    paramspider:[ {t:"-d",h:"domain"},{t:"-s",h:"stream stdout"} ],
    x8:         [ {t:"-w wordlist.txt",h:""},{t:"--output-format url",h:""},{t:"-X POST",h:""},{t:"-b 'k=v'",h:"body"} ],
    dalfox:     [ {t:"pipe",h:"stdin urls"},{t:"url",h:"single url"},{t:"-b $BLIND_XSS_URL",h:"blind"},{t:"--silence",h:""},{t:"--deep-domxss",h:""},{t:"--skip-bav",h:""},{t:"--worker 100",h:""},{t:"-o xss.txt",h:""} ],
    sqlmap:     [ {t:"--batch",h:"no prompts"},{t:"--random-agent",h:""},{t:"--level 5",h:""},{t:"--risk 3",h:""},{t:"--dbs",h:"enum dbs"},{t:"--tamper=between,space2comment",h:"WAF bypass"},{t:"--threads 10",h:""},{t:"--crawl=2",h:""} ],
    Gxss:       [ {t:"-p Xss",h:"param"},{t:"-c 100",h:"concurrency"},{t:"-o refl.txt",h:""} ],
    qsreplace:  [ {t:"'\"><script>alert(1)</script>'",h:"xss probe"},{t:"FUZZ",h:"placeholder"},{t:"/etc/passwd",h:"lfi probe"} ],
    curl:       [ {t:"-s",h:"silent"},{t:"-sI",h:"head only"},{t:"-k",h:"insecure TLS"},{t:"-X POST",h:""},{t:"-H 'Content-Type: application/json'",h:""},{t:"--path-as-is",h:""},{t:"-d '{}'",h:"body"} ],
    nikto:      [ {t:"-h",h:"host"},{t:"-ssl",h:""},{t:"-Tuning 1234",h:"test classes"},{t:"-o nikto.txt",h:""} ],
    ffuf:       [ {t:"-w wordlist.txt",h:""},{t:"-u https://HOST/FUZZ",h:""},{t:"-mc 200,301,403",h:""},{t:"-rate 50",h:""},{t:"-o ffuf.json",h:""} ],
};

function ensureACBox() {
    if (AC.box) return AC.box;
    const box = document.createElement("div");
    box.className = "cmd-suggest";
    box.hidden = true;
    document.body.appendChild(box);
    AC.box = box;
    return box;
}
function acCurrentWord(field) {
    const pos  = field.selectionStart || 0;
    const upto = field.value.slice(0, pos);
    const m    = upto.match(/(\S*)$/);
    const word = m ? m[1] : "";
    return { word, start: pos - word.length };
}
function onCmdInput(e) {
    const field = e.target;
    const cmdId = field.getAttribute("data-cmd");
    if (cmdId) cmdEditSet(cmdId, field.value);
    acUpdate(field);
}
function acUpdate(field) {
    AC.field = field;
    const { word, start } = acCurrentWord(field);
    const tool = (field.value.trim().split(/\s+/)[0] || "").replace(/^.*\//, "");
    const pool = (CMD_SUGGEST[tool] || []).concat(CMD_SUGGEST["*"]);
    const w = word.toLowerCase();
    let items = w ? pool.filter(s => s.t.toLowerCase().includes(w)) : pool;
    const seen = new Set();
    items = items.filter(s => (seen.has(s.t) ? false : seen.add(s.t))).slice(0, 8);
    if (!items.length) { closeAC(); return; }
    AC.items = items; AC.sel = 0; AC.word = word; AC.wordStart = start; AC.open = true;
    renderAC(field);
}
function renderAC(field) {
    const box = ensureACBox();
    box.innerHTML = AC.items.map((s, i) => `
      <div class="cmd-suggest-item ${i === AC.sel ? "active" : ""}" onmousedown="ReconForge.acPick(event, ${i})">
        <span class="cmd-suggest-text mono">${escapeHTML(s.t)}</span>
        ${s.h ? `<span class="cmd-suggest-hint">${escapeHTML(s.h)}</span>` : ""}
      </div>
    `).join("");
    const r = field.getBoundingClientRect();
    box.style.left     = Math.round(r.left) + "px";
    box.style.top      = Math.round(r.bottom + 4) + "px";
    box.style.minWidth = Math.round(Math.min(r.width, 540)) + "px";
    box.hidden = false;
}
function closeAC() {
    AC.open = false; AC.items = []; AC.field = null;
    if (AC.box) AC.box.hidden = true;
}
function acInsert(i) {
    const field = AC.field;
    if (!field) return;
    const s = AC.items[i];
    if (!s) return;
    const pos    = field.selectionStart || (AC.wordStart + AC.word.length);
    const before = field.value.slice(0, AC.wordStart);
    const after  = field.value.slice(pos);
    const sep    = (before && !/\s$/.test(before)) ? " " : "";
    const trail  = (after === "" || /^\s/.test(after)) ? "" : " ";
    field.value  = before + sep + s.t + trail + after;
    const caret  = (before + sep + s.t).length;
    field.setSelectionRange(caret, caret);
    const cmdId = field.getAttribute("data-cmd");
    if (cmdId) cmdEditSet(cmdId, field.value);
    field.focus();
    acUpdate(field);   // re-filter from the new caret position
}
function acPick(e, i) { e.preventDefault(); acInsert(i); }
function onCmdKey(e) {
    if (!AC.open) {
        if ((e.ctrlKey || e.metaKey) && e.code === "Space") { e.preventDefault(); acUpdate(e.target); }
        return;
    }
    if (e.key === "ArrowDown")      { e.preventDefault(); AC.sel = Math.min(AC.items.length - 1, AC.sel + 1); renderAC(e.target); }
    else if (e.key === "ArrowUp")   { e.preventDefault(); AC.sel = Math.max(0, AC.sel - 1); renderAC(e.target); }
    else if (e.key === "Enter" || e.key === "Tab") { e.preventDefault(); acInsert(AC.sel); }
    else if (e.key === "Escape")    { e.preventDefault(); e.stopPropagation(); closeAC(); }
}
function onCmdBlur() { setTimeout(closeAC, 120); }

function vaultSub(route) {
    const base = state.vaultPath || ("ResearchVault/BugBounty/" + (state.workspace || "<workspace>"));
    return base + "/02_Recon/" + route + "/";
}

// ── Console ──────────────────────────────────────────────────────
function consoleLog(kind, text) {
    const now = new Date();
    const t = now.toTimeString().slice(0, 8);
    state.consoleEvents.unshift({ kind, text, time: t });
    if (state.consoleEvents.length > 200) state.consoleEvents.length = 200;
    renderConsole();
}

function renderConsole() {
    const console_el = document.getElementById("activity-console");
    console_el.dataset.state = state.consoleState;
    const count = state.consoleEvents.length;
    document.getElementById("console-count").textContent = `${count} event${count === 1 ? "" : "s"}`;
    const last = state.consoleEvents[0];
    document.getElementById("console-summary").textContent =
        last ? `Last: ${last.text}` : "Console idle";
    document.getElementById("console-toggle-label").textContent =
        state.consoleState === "expanded" ? "minimize" : "expand";

    const stream = document.getElementById("console-stream");
    stream.innerHTML = state.consoleEvents.map(e => `
      <div class="console-line" data-c="${e.kind}">
        <span class="c-time">${escapeHTML(e.time)}</span>
        <span>${escapeHTML(e.text)}</span>
      </div>
    `).join("");
}

function toggleConsole() {
    state.consoleState = state.consoleState === "expanded" ? "minimized" : "expanded";
    LS.set("consoleState", state.consoleState);
    renderConsole();
}

function clearConsole() {
    state.consoleEvents = [];
    renderConsole();
}

// ── Guide mode ───────────────────────────────────────────────────
function toggleGuide() {
    state.guideMode = !state.guideMode;
    LS.set("guideMode", state.guideMode);
    applyGuideState();
    renderWorkspace();
}

function applyGuideState() {
    const btn = document.getElementById("guide-state");
    if (btn) btn.textContent = state.guideMode ? "guide on" : "guide off";
    const wrap = btn ? btn.parentElement : null;
    if (wrap) wrap.classList.toggle("on", state.guideMode);
}

// ── Command palette ──────────────────────────────────────────────
function paletteItems() {
    const items = [];
    // Navigation items
    for (const group of NAV) {
        for (const it of group.items) {
            items.push({ kind: "nav", tag: group.title, label: it.label, route: it.route });
        }
    }
    // Quick actions
    items.push({ kind: "action", tag: "action", label: "Toggle guide mode", action: () => { toggleGuide(); } });
    items.push({ kind: "action", tag: "action", label: "Toggle bottom console", action: () => { toggleConsole(); } });
    items.push({ kind: "action", tag: "action", label: "Clear activity console", action: () => { clearConsole(); } });
    items.push({ kind: "action", tag: "action", label: "Sign out", action: () => { logout(); } });
    return items;
}

function openPalette() {
    state.palette.open = true;
    state.palette.query = "";
    state.palette.selected = 0;
    document.getElementById("palette").hidden = false;
    const input = document.getElementById("palette-input");
    input.value = "";
    setTimeout(() => input.focus(), 30);
    renderPalette();
}

function closePalette() {
    state.palette.open = false;
    document.getElementById("palette").hidden = true;
}

function renderPalette() {
    const q = state.palette.query.toLowerCase().trim();
    const items = paletteItems().filter(it =>
        !q || it.label.toLowerCase().includes(q) || (it.tag || "").toLowerCase().includes(q)
    );
    state.palette.items = items;
    if (state.palette.selected >= items.length) state.palette.selected = Math.max(0, items.length - 1);
    const results = document.getElementById("palette-results");
    if (!items.length) {
        results.innerHTML = `<div class="palette-empty">no results for "${escapeHTML(q)}"</div>`;
        return;
    }
    results.innerHTML = items.map((it, i) => `
      <div class="palette-result ${i === state.palette.selected ? "active" : ""}" onclick="ReconForge.executePalette(${i})">
        <span>${escapeHTML(it.label)}</span>
        <span class="palette-tag">${escapeHTML(it.tag || "")}</span>
      </div>
    `).join("");
}

function executePalette(i) {
    const item = state.palette.items[i];
    if (!item) return;
    closePalette();
    if (item.kind === "nav") navigateTo(item.route);
    else if (item.kind === "action" && typeof item.action === "function") item.action();
}

// ── Intake handlers ──────────────────────────────────────────────
function val(id) { const el = document.getElementById(id); return el ? (el.value || "") : ""; }
function parseScopeLines(text) {
    return String(text || "").split(/[\n,]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
}

async function saveIntake() {
    const target    = val("intake-target").trim().toLowerCase();
    const program   = val("intake-program").trim();
    const workspace = val("intake-workspace").trim() || target;
    const vault     = val("intake-vault").trim();
    const inScope   = parseScopeLines(val("intake-scope"));
    const outScope  = parseScopeLines(val("intake-oos"));
    if (!target) { toast("Target domain required.", "error"); return; }
    // Empty in-scope defaults to apex + wildcard (matches the backend default).
    const effIn = inScope.length ? inScope : [target, "*." + target];

    state.target    = target;
    state.program   = program;
    state.workspace = workspace;
    state.vaultPath = vault || ("ResearchVault/BugBounty/" + target);
    state.scope     = { program, platform: (state.scope && state.scope.platform) || "",
                        inScope: effIn, outScope, active: false, programPath: "" };
    state.intakeDraft = { target, program, workspace, vault: state.vaultPath,
                          scope: effIn.join("\n"), oos: outScope.join("\n") };
    LS.set("target", target);   LS.set("program", program);
    LS.set("workspace", workspace); LS.set("vaultPath", state.vaultPath);
    LS.set("scope", state.scope);
    consoleLog("select", "target loaded: " + target);
    renderShellChrome(); renderSidebar(); renderKillchain();

    // Wire the declared scope into the backend so scope_guard enforces it.
    const ok = await pushScope(effIn, outScope);
    toast(ok ? ("Target " + target + " loaded · scope enforced.")
             : ("Target " + target + " loaded · backend scope wiring failed."),
          ok ? "success" : "error");
    navigateTo("scope");
}

function clearIntake() {
    state.target = null; state.program = null; state.workspace = null; state.vaultPath = null;
    state.scope = { program: "", platform: "", inScope: [], outScope: [], active: false };
    state.surfaceSubs = null;
    state.intakeDraft = { target: "", program: "", workspace: "", vault: "", scope: "", oos: "" };
    LS.set("target", null); LS.set("program", null); LS.set("workspace", null);
    LS.set("vaultPath", null); LS.set("scope", null);
    consoleLog("log", "target cleared");
    renderShellChrome(); renderSidebar(); renderKillchain(); renderWorkspace();
}

// ── Scope wiring (backend-enforced) ──────────────────────────────
async function pushScope(inScope, outScope) {
    if (!state.target) return false;
    const r = await api("POST", "/api/scope", {
        target:    state.target,
        program:   state.program || "",
        workspace: state.workspace || state.target,
        platform:  (state.scope && state.scope.platform) || "",
        in_scope:  inScope,
        out_of_scope: outScope,
    });
    if (r.ok && r.data && r.data.success && r.data.data && r.data.data.program) {
        const p = r.data.data.program;
        state.scope = {
            program:  p.name || state.program || "",
            platform: p.platform || "",
            inScope:  (p.in_scope || []).map(e => e.value || e),
            outScope: (p.out_of_scope || []).map(e => e.value || e),
            active:   true,
            programPath: r.data.data.active_program || "",
            programSlug: r.data.data.program_slug || "",   // v2 row the bridge wrote
        };
        LS.set("scope", state.scope);
        consoleLog("success", "scope enforced: " + state.scope.inScope.length +
                              " in / " + state.scope.outScope.length + " out");
        return true;
    }
    consoleLog("error", "scope wiring failed: " + ((r.data && r.data.message) || r.status));
    return false;
}

async function saveScope() {
    if (!state.target) { toast("Load a target first.", "error"); return; }
    const inScope  = parseScopeLines(val("scope-in"));
    const outScope = parseScopeLines(val("scope-out"));
    const ok = await pushScope(inScope, outScope);
    toast(ok ? "Scope saved & enforced." : "Scope save failed.", ok ? "success" : "error");
    renderWorkspace();
}

async function ensureScope() {
    const r = await api("GET", "/api/scope");
    if (!r.ok || !r.data) return;
    const d = r.data.data || r.data;
    const prog = d && d.program;
    if (!prog || !prog.in_scope) return;
    // Only adopt the backend program if it authorizes the active target — avoids
    // surfacing a stale engagement from a previous session.
    const inVals = (prog.in_scope || []).map(e => (e.value || e || "").toString());
    const matches = !state.target || inVals.some(v =>
        v === state.target || v === "*." + state.target || v.endsWith("." + state.target));
    if (!matches) return;
    state.scope = {
        program:  prog.name || "",
        platform: prog.platform || "",
        inScope:  inVals,
        outScope: (prog.out_of_scope || []).map(e => (e.value || e || "").toString()),
        active:   true,
        programPath: d.active_program || "",
        programSlug: d.program_slug || "",   // v2 row the bridge wrote
    };
    LS.set("scope", state.scope);
    if (currentRoute() === "scope") renderWorkspace();
}

// ── Notes (workspace-scoped, local) ──────────────────────────────
function saveNotes() {
    const el = document.getElementById("notes-area"); if (!el) return;
    LS.set(wsKey("notes"), el.value);
    consoleLog("success", "notes saved"); toast("Notes saved.", "success");
}
function copyNotes() {
    const el = document.getElementById("notes-area");
    copyToClipboard(el ? el.value : (LS.get(wsKey("notes"), "") || ""));
}
function clearNotes() {
    LS.set(wsKey("notes"), "");
    renderWorkspace(); toast("Notes cleared.", "info");
}

function setRisk(mode) {
    if (!["passive", "active", "aggressive"].includes(mode)) return;
    state.riskMode = mode;
    LS.set("riskMode", mode);
    consoleLog("log", "risk mode: " + mode);
    renderShellChrome();
    renderWorkspace();
}

// ── Continuous monitoring (recon schedule) ───────────────────────
async function refreshState() {
    const r = await api("GET", "/api/state");
    if (r.ok) { state.apiState = r.data && (r.data.data || r.data); renderWorkspace(); }
}
async function enrollMonitor() {
    const el = document.getElementById("mon-domain");
    const domain = ((el && el.value) || "").trim().toLowerCase();
    if (!domain) { toast("Domain required.", "error"); return; }
    const r = await api("POST", "/api/schedule", { domain });
    if (r.ok) { consoleLog("success", "monitoring " + domain); toast("Monitoring " + domain, "success"); await refreshState(); }
    else { toast("Enroll failed.", "error"); }
}
async function toggleMonitor(id, enabled) {
    await api("PUT", "/api/schedule/" + id, { enabled: !!enabled });
    await refreshState();
}
async function removeMonitor(id) {
    await api("DELETE", "/api/schedule/" + id);
    consoleLog("log", "monitor removed");
    await refreshState();
}

// ── OPSEC settings ───────────────────────────────────────────────
async function ensureConfig() {
    const r = await api("GET", "/api/config");
    if (r.ok) { state.config = r.data && (r.data.data || r.data); renderWorkspace(); }
}
async function saveOpsec() {
    const rlEl = document.getElementById("opsec-rl");
    const payload = {
        opsec_http_proxy:   (document.getElementById("opsec-proxy").value || "").trim(),
        opsec_rate_limit:   parseInt(rlEl.value, 10) || 50,
        opsec_delay:        (document.getElementById("opsec-delay").value || "").trim(),
        opsec_random_agent: document.getElementById("opsec-rua").checked,
    };
    const r = await api("PUT", "/api/config", payload);
    if (r.ok) {
        state.config = Object.assign({}, state.config || {}, payload);
        consoleLog("success", "OPSEC config saved");
        toast("OPSEC settings saved.", "success");
    } else { toast("Save failed.", "error"); }
}

async function submitJob() {
    const domain = (document.getElementById("job-domain").value || "").trim();
    if (!domain) { toast("Domain required.", "error"); return; }
    const r = await api("POST", "/api/jobs", { domain });
    if (r.ok && r.data && r.data.success) {
        consoleLog("success", "job queued: " + domain);
        toast("Job queued: " + domain, "success");
        renderWorkspace();
    } else {
        consoleLog("error", "job submit failed: " + (r.data && r.data.message || r.status));
        toast("Submit failed.", "error");
    }
}

// ── Copy / clipboard ─────────────────────────────────────────────
function copyToClipboard(txt) {
    if (!txt) { toast("Nothing to copy.", "error"); return; }
    if (navigator.clipboard) {
        navigator.clipboard.writeText(txt).then(
            () => { consoleLog("success", "command copied"); toast("Copied to clipboard.", "success"); },
            () => { fallbackCopy(txt); }
        );
    } else { fallbackCopy(txt); }
}

function fallbackCopy(txt) {
    const t = document.createElement("textarea");
    t.value = txt; document.body.appendChild(t); t.select();
    try { document.execCommand("copy"); consoleLog("success", "command copied"); toast("Copied to clipboard.", "success"); }
    catch (_) { toast("Copy failed.", "error"); }
    document.body.removeChild(t);
}

// ── Toast ────────────────────────────────────────────────────────
function toast(msg, kind) {
    kind = kind || "info";
    const stack = document.getElementById("toast-stack");
    const el = document.createElement("div");
    el.className = "toast " + kind;
    el.textContent = msg;
    stack.appendChild(el);
    setTimeout(() => {
        el.style.transition = "opacity 0.3s";
        el.style.opacity = "0";
        setTimeout(() => el.remove(), 320);
    }, 3000);
}

// ── Utils ────────────────────────────────────────────────────────
function escapeHTML(s) {
    return String(s == null ? "" : s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}
function escapeAttr(s) { return escapeHTML(s); }
function tgt() { return state.target || "example.com"; }

// ── Keyboard handlers ────────────────────────────────────────────
document.addEventListener("keydown", (e) => {
    const inPalette = state.palette.open;
    const inInput = e.target && (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA");

    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault(); openPalette(); return;
    }
    if (e.key === "/" && !inInput && !inPalette) {
        e.preventDefault(); openPalette(); return;
    }
    if (e.key === "Escape" && inPalette) {
        closePalette(); return;
    }
    if (inPalette) {
        if (e.key === "ArrowDown") {
            e.preventDefault();
            state.palette.selected = Math.min(state.palette.items.length - 1, state.palette.selected + 1);
            renderPalette();
        } else if (e.key === "ArrowUp") {
            e.preventDefault();
            state.palette.selected = Math.max(0, state.palette.selected - 1);
            renderPalette();
        } else if (e.key === "Enter") {
            e.preventDefault();
            executePalette(state.palette.selected);
        }
    }
});

// Map of intake field id → draft key. Keeps the in-progress engagement form
// in state so any re-render (selecting a risk mode, the 8s poll) repopulates
// every field instead of blanking it.
const INTAKE_FIELDS = {
    "intake-target":     "target",
    "intake-program":    "program",
    "intake-workspace":  "workspace",
    "intake-vault": "vault",
    "intake-scope":      "scope",
    "intake-oos":        "oos",
};

document.addEventListener("input", (e) => {
    if (!e.target) return;
    if (e.target.id === "palette-input") {
        state.palette.query = e.target.value;
        state.palette.selected = 0;
        renderPalette();
        return;
    }
    const key = INTAKE_FIELDS[e.target.id];
    if (key) state.intakeDraft[key] = e.target.value;
});

// Dismiss the command autocomplete when clicking outside it / its field.
document.addEventListener("mousedown", (e) => {
    if (!AC.open) return;
    const t = e.target;
    if (t && t.closest && (t.closest(".cmd-suggest") || t.closest(".forge-cmd-edit"))) return;
    closeAC();
});

// ── Public API exposed on window.ReconForge ──────────────────────
window.ReconForge = {
    login, logout,
    go: navigateTo,
    saveIntake, clearIntake, setRisk, setPlatform, submitJob,
    saveScope, refreshSurface,
    // ── [agent: report] ── report export workspace
    scoreCvss, generateDraft, copyDraft, runQualityGate,
    // pipeline command center
    runPhase, cancelPhase, openPhaseLog, closePhaseLog, refreshPipeline, pipelineNewRun,
    // agents command center
    startAgentRun, refreshAgents, toggleAgentLog, setAgentBackend, saveAgentConfig,
    enrollMonitor, toggleMonitor, removeMonitor,
    saveOpsec,
    // ── [agent: toolchain] ── toolchain health + workflows
    refreshToolchain, copyToolInstall, toggleWorkflow,
    openPalette, closePalette, executePalette,
    toggleConsole, clearConsole,
    toggleGuide,
    // command builder
    copyCmd, saveCmdToWorkspace, addCmdToNotes, resetCmd,
    onCmdInput, onCmdKey, onCmdBlur, acPick,
    copySaved, removeSaved,
    // notes
    saveNotes, copyNotes, clearNotes,
    // ── [agent: findings] ── findings board handlers
    refreshFindings, selectFinding, closeFinding, setFindingStatus, verifyFindingEvidence,
    toast,
};

// ── Boot ─────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", boot);

})();
