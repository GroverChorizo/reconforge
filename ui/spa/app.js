// ReconForge v3 SPA — Phase 17 program-workspace shell.
//
// Routes:
//   #onboarding                    (auto when no programs exist)
//   #workspace/{section}           — section ∈ {dashboard,scope,assets,findings,
//                                              attack,reports,tools,agents,settings}
//
// The active program lives in localStorage; the section follows the hash.
// We keep the hash short — "#workspace/findings" not "#workspace/<slug>/findings" —
// because the slug is already global state. Deep-linking by slug is a follow-up.

const API = {
  // legacy v1
  agents:      (jobId) => fetch(`/api/agents/runs?job=${encodeURIComponent(jobId)}`).then(r => r.json()),
  heatmap:     (jobId) => fetch(`/api/attack/heatmap?job=${encodeURIComponent(jobId)}`).then(r => r.json()),
  findings:    (jobId) => fetch(`/api/findings?job=${encodeURIComponent(jobId)}`).then(r => r.json()),
  finding:     (id)    => fetch(`/api/findings/${id}`).then(r => r.json()),
  submission:  (id)    => fetch(`/api/submissions/${id}`).then(r => r.json()),
  approve:     (id, v) => fetch(`/api/submissions/${id}/approve`, {
    method: "POST", body: JSON.stringify({approved: v}),
    headers: {"Content-Type": "application/json"},
  }).then(r => r.json()),
  // v2 programs + scope
  programs:       ()           => fetch(`/api/v2/programs`).then(r => r.json()),
  programGet:     (slug)       => fetch(`/api/v2/programs/${encodeURIComponent(slug)}`).then(r => r.json()),
  programCreate:  (body)       => fetch(`/api/v2/programs`, {
    method: "POST", body: JSON.stringify(body),
    headers: {"Content-Type": "application/json"},
  }).then(async r => ({status: r.status, body: await r.json()})),
  scopeCheck:     (slug, target) => fetch(
    `/api/v2/programs/${encodeURIComponent(slug)}/scope_check`,
    {method: "POST", body: JSON.stringify({target}),
     headers: {"Content-Type": "application/json"}},
  ).then(r => r.json()),
  blockedTargets: (slug, limit=20) => fetch(
    `/api/v2/programs/${encodeURIComponent(slug)}/blocked_targets?limit=${limit}`,
  ).then(r => r.json()),
  dashboard:      (slug)       => fetch(
    `/api/v2/programs/${encodeURIComponent(slug)}/dashboard`,
  ).then(r => r.json()),
  // v2 assets
  assets:         (slug, qs={}) => {
    const q = new URLSearchParams(qs).toString();
    return fetch(`/api/v2/programs/${encodeURIComponent(slug)}/assets${q ? '?'+q : ''}`)
      .then(r => r.json());
  },
  assetDetail:    (sid)        => fetch(`/api/v2/assets/${sid}`).then(r => r.json()),
  findingsBoard:  (slug)       => fetch(
    `/api/v2/programs/${encodeURIComponent(slug)}/findings_board`,
  ).then(r => r.json()),
  findingDetail:  (fid)        => fetch(`/api/v2/findings/${fid}`).then(r => r.json()),
  findingStatus:  (fid, status, op="operator") => fetch(
    `/api/v2/findings/${fid}/status`,
    {method: "POST", body: JSON.stringify({status, operator: op}),
     headers: {"Content-Type": "application/json"}},
  ).then(async r => ({status: r.status, body: await r.json()})),
  qualityGate:    (did, reviewed=false) => fetch(
    `/api/v2/submissions/${did}/quality_gate${reviewed ? '?reviewed=1' : ''}`,
  ).then(r => r.json()),
  // v2 evidence + tools + workflows
  evidence:       (fid)        => fetch(`/api/v2/findings/${fid}/evidence`).then(r => r.json()),
  verifyEvidence: (fid, eid, op="operator") => fetch(
    `/api/v2/findings/${fid}/evidence/${eid}/verify`,
    {method: "POST", body: JSON.stringify({operator: op}),
     headers: {"Content-Type": "application/json"}},
  ).then(r => r.json()),
  toolHealth:     (refresh=false) => fetch(
    `/api/v2/tools/health${refresh ? '?refresh=1' : ''}`,
  ).then(r => r.json()),
  workflows:      ()         => fetch(`/api/v2/workflows`).then(r => r.json()),
  preflight:      (body)     => fetch(`/api/v2/jobs/preflight`, {
    method: "POST", body: JSON.stringify(body),
    headers: {"Content-Type": "application/json"},
  }).then(r => r.json()),
};

const TACTICS = [
  ["TA0043","Reconnaissance"], ["TA0042","Resource Development"],
  ["TA0001","Initial Access"], ["TA0002","Execution"],
  ["TA0003","Persistence"],    ["TA0004","Privilege Escalation"],
  ["TA0005","Defense Evasion"],["TA0006","Credential Access"],
  ["TA0007","Discovery"],      ["TA0008","Lateral Movement"],
  ["TA0009","Collection"],     ["TA0011","Command and Control"],
  ["TA0010","Exfiltration"],   ["TA0040","Impact"],
];

const LS_PROGRAM = "rf.activeProgramSlug";

// ── program context ─────────────────────────────────────────────
const ProgramState = {
  list: [],
  activeSlug: null,
  active: null,
  workflows: [],
};

function selectedProgramSlug() {
  return localStorage.getItem(LS_PROGRAM) || "";
}

function setSelectedProgramSlug(slug) {
  if (slug) localStorage.setItem(LS_PROGRAM, slug);
  else localStorage.removeItem(LS_PROGRAM);
}

async function refreshPrograms() {
  let data;
  try { data = await API.programs(); }
  catch (e) { data = {programs: [], count: 0}; }
  ProgramState.list = data.programs || [];

  let slug = selectedProgramSlug();
  if (!ProgramState.list.find(p => p.slug === slug)) {
    slug = ProgramState.list[0]?.slug || "";
    setSelectedProgramSlug(slug);
  }
  ProgramState.activeSlug = slug || null;
  ProgramState.active = ProgramState.list.find(p => p.slug === slug) || null;
  renderProgramSelector();
  renderScopeIndicator();
}

async function refreshWorkflows() {
  try {
    const data = await API.workflows();
    ProgramState.workflows = data.workflows || [];
  } catch (e) {
    ProgramState.workflows = [];
  }
}

function renderProgramSelector() {
  const sel = document.getElementById("program-select");
  const chip = document.getElementById("program-platform");
  if (!sel) return;
  if (ProgramState.list.length === 0) {
    sel.innerHTML = `<option value="">— no programs —</option>`;
    chip.textContent = "";
    return;
  }
  sel.innerHTML = ProgramState.list.map(p =>
    `<option value="${p.slug}" ${p.slug === ProgramState.activeSlug ? "selected" : ""}>
       ${escapeHtml(p.name)}
     </option>`
  ).join("");
  chip.textContent = ProgramState.active?.platform || "";
  chip.className = "platform-chip platform-" + (ProgramState.active?.platform || "other");
}

// Topbar scope indicator — updated lazily once we have a dashboard payload.
let _scopeIndicatorState = null;
function renderScopeIndicator(summary) {
  const wrap = document.getElementById("scope-indicator");
  if (!wrap) return;
  if (summary) _scopeIndicatorState = summary;
  if (!_scopeIndicatorState) { wrap.hidden = true; return; }
  const s = _scopeIndicatorState;
  const tone = s.assets_blocked > 0 ? "warn" : "ok";
  wrap.hidden = false;
  wrap.className = `scope-indicator ${tone}`;
  wrap.querySelector(".label").textContent =
    `${s.assets_in} in · ${s.assets_blocked} blocked · ${s.rule_in_count} rules`;
}

// ── <scope-badge> Web Component (unchanged from Phase 16) ───────
class ScopeBadge extends HTMLElement {
  static get observedAttributes() { return ["program-slug", "target"]; }
  connectedCallback() { this._render("unknown", ""); this._refresh(); }
  attributeChangedCallback() { if (this.isConnected) this._refresh(); }
  async _refresh() {
    const slug   = this.getAttribute("program-slug") || "";
    const target = (this.getAttribute("target") || "").trim();
    if (!slug || !target) { this._render("unknown", ""); return; }
    const cacheKey = `rf.scope:${slug}|${target}`;
    const cached = sessionStorage.getItem(cacheKey);
    if (cached) {
      try {
        const c = JSON.parse(cached);
        this._render(c.scope_status, c.reason);
        return;
      } catch (_) {}
    }
    try {
      const result = await API.scopeCheck(slug, target);
      sessionStorage.setItem(cacheKey, JSON.stringify({
        scope_status: result.scope_status, reason: result.reason,
      }));
      this._render(result.scope_status || "unknown", result.reason || "");
    } catch (e) { this._render("unknown", String(e)); }
  }
  _render(status, reason) {
    const labels = {in:"IN SCOPE", blocked:"BLOCKED", ambiguous:"REVIEW", unknown:"UNKNOWN"};
    this.dataset.status = status;
    this.setAttribute("title", reason || labels[status] || labels.unknown);
    this.textContent = labels[status] || labels.unknown;
  }
}
customElements.define("scope-badge", ScopeBadge);

// ── Pre-flight modal (unchanged from Phase 16) ──────────────────
async function openPreflightModal({ programSlug, target, mode, tool }) {
  const result = await API.preflight({
    program_slug: programSlug, target, mode, tool,
  });
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    const dlg = document.createElement("div");
    dlg.className = "modal-dialog preflight";
    dlg.setAttribute("role", "dialog");
    dlg.setAttribute("aria-labelledby", "preflight-title");

    const allowed = !!result.allowed;
    const scopeMatched = result.scope?.matched || {};
    const allowedMethods    = (result.allowed_methods    || []).join(", ") || "(none specified)";
    const disallowedMethods = (result.disallowed_methods || []).join(", ") || "(none specified)";
    const roe = result.rules_of_engagement_excerpt || "";

    dlg.innerHTML = `
      <header>
        <h2 id="preflight-title">Pre-flight — ${escapeHtml(tool)} on ${escapeHtml(target)}</h2>
        <span class="status-pill ${allowed ? 'ok' : 'block'}">${allowed ? 'APPROVED TO RUN' : 'BLOCKED'}</span>
      </header>
      <section class="reason"><p>${escapeHtml(result.reason || '')}</p></section>
      <dl class="kv">
        <dt>Program</dt><dd>${escapeHtml(programSlug)}</dd>
        <dt>Mode</dt><dd>${escapeHtml(mode)}</dd>
        <dt>Traffic class</dt><dd>${escapeHtml(result.traffic_class || result.safety_class || 'unknown')}</dd>
        <dt>Rate limit</dt><dd>${result.rate_limit_rps ?? '—'} req/s${
          result.rate_limit_hint ? ` <span class="dim">(program hint: ${result.rate_limit_hint})</span>` : ''
        }</dd>
        <dt>Scope rule</dt><dd>${scopeMatched.type ? `${escapeHtml(scopeMatched.type)} = <code>${escapeHtml(scopeMatched.value || '')}</code>` : '<span class="dim">none matched</span>'}</dd>
        <dt>Allowed methods</dt><dd><code>${escapeHtml(allowedMethods)}</code></dd>
        <dt>Disallowed methods</dt><dd><code>${escapeHtml(disallowedMethods)}</code></dd>
        <dt>ATT&amp;CK</dt><dd>${escapeHtml(result.technique || '—')}</dd>
        <dt>Timeout</dt><dd>${result.timeout_s ?? '—'}s</dd>
      </dl>
      ${result.scope_rule_notes ? `
        <section class="scope-rule-notes">
          <h3>Scope rule notes</h3>
          <p>${escapeHtml(result.scope_rule_notes)}</p>
        </section>` : ''}
      ${roe ? `
        <details class="roe">
          <summary>Rules of Engagement excerpt</summary>
          <pre>${escapeHtml(roe)}</pre>
        </details>` : ''}
      <section class="cmd-preview">
        <h3>Command preview</h3>
        <pre><code>${(result.command_preview || []).map(escapeHtml).join(' ')}</code></pre>
        <p class="hint">Variables like <code>$INPUT_FILE$</code>, <code>$OUTPUT$</code>, <code>$THREADS$</code> are resolved at run time.</p>
      </section>
      ${allowed ? `
        <label class="ack">
          <input type="checkbox" id="preflight-ack">
          I confirm this target is in scope and authorized for this test.
        </label>` : ''}
      <footer>
        <button type="button" class="btn-cancel" autofocus>Cancel</button>
        ${allowed ? `<button type="button" class="btn-confirm" disabled>Confirm and run</button>` : ''}
      </footer>
    `;
    overlay.appendChild(dlg);
    document.body.appendChild(overlay);
    const close = (ok) => { document.body.removeChild(overlay); resolve(ok); };
    dlg.querySelector(".btn-cancel").addEventListener("click", () => close(false));
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(false); });
    document.addEventListener("keydown", function onKey(e) {
      if (e.key === "Escape") { document.removeEventListener("keydown", onKey); close(false); }
    });
    if (allowed) {
      const ack = dlg.querySelector("#preflight-ack");
      const btn = dlg.querySelector(".btn-confirm");
      ack.addEventListener("change", () => { btn.disabled = !ack.checked; });
      btn.addEventListener("click", () => close(true));
    }
  });
}
window.RF = window.RF || {};
window.RF.preflight = openPreflightModal;

// ── views ───────────────────────────────────────────────────────
function activeJobId() {
  return new URLSearchParams(location.search).get("job") || "demo";
}

function setActiveSection(section) {
  document.querySelectorAll("#leftnav a").forEach(a => {
    a.classList.toggle("active", a.dataset.section === section);
  });
}

function viewOnboarding() {
  setActiveSection(null);
  const root = document.getElementById("view-root");
  root.innerHTML = `
    <section class="onboarding">
      <h2>Welcome to ReconForge</h2>
      <p>No programs yet. Paste a scope JSON below to create your first one.
         The scope format mirrors the one consumed by <code>scope_guard</code>.</p>
      <form id="onboarding-form">
        <label>Name <input type="text" name="name" required
                            placeholder="e.g. Rivian"></label>
        <label>Platform
          <select name="platform" required>
            <option value="intigriti">Intigriti</option>
            <option value="hackerone">HackerOne</option>
            <option value="bugcrowd">Bugcrowd</option>
            <option value="yeswehack">YesWeHack</option>
            <option value="synack">Synack</option>
            <option value="other">Other</option>
          </select>
        </label>
        <label>Platform handle (used for required headers)
               <input type="text" name="platform_handle" placeholder="grover"></label>
        <label>Scope JSON
          <textarea name="scope_json" rows="10" placeholder='{"in_scope": [...], "out_of_scope": [...]}'></textarea>
        </label>
        <div class="form-error" id="onboarding-error"></div>
        <button type="submit">Create program</button>
      </form>
    </section>`;
  document.getElementById("onboarding-form").addEventListener("submit", onOnboardingSubmit);
}

async function onOnboardingSubmit(e) {
  e.preventDefault();
  const f = e.target;
  const errEl = document.getElementById("onboarding-error");
  errEl.textContent = "";

  let scopeBody = {};
  const raw = f.scope_json.value.trim();
  if (raw) {
    try { scopeBody = JSON.parse(raw); }
    catch (_) { errEl.textContent = "Scope JSON is not valid JSON."; return; }
  }

  const payload = {
    name: f.name.value.trim(),
    platform: f.platform.value,
    platform_handle: f.platform_handle.value.trim(),
    scope: scopeBody.in_scope || scopeBody.scope || [],
    out_of_scope: scopeBody.out_of_scope || [],
    bounty_ranges: scopeBody.bounty_ranges || {},
    policy_url: scopeBody.policy_url || "",
    notes: scopeBody.notes || "",
  };
  const r = await API.programCreate(payload);
  if (r.status >= 400) {
    errEl.textContent = r.body.error || "Failed to create program.";
    return;
  }
  setSelectedProgramSlug(r.body.program.slug);
  await refreshPrograms();
  location.hash = "#workspace/dashboard";
  route();
}

// ── Mission Control dashboard ───────────────────────────────────
async function viewDashboard() {
  setActiveSection("dashboard");
  const slug = ProgramState.activeSlug;
  const root = document.getElementById("view-root");
  if (!slug) { root.innerHTML = noProgramHint(); return; }
  root.innerHTML = `<div class="loading">Loading mission control…</div>`;
  let data;
  try { data = await API.dashboard(slug); }
  catch (e) { root.innerHTML = `<div class="error">Failed to load dashboard: ${escapeHtml(String(e))}</div>`; return; }

  renderScopeIndicator(data.scope_summary);

  const program  = data.program || {};
  const ss       = data.scope_summary || {};
  const bounties = program.bounty_ranges || {};
  const bountyText = Object.entries(bounties).map(
    ([sev, range]) => `<span class="bounty-row"><b>${escapeHtml(sev)}</b> $${range[0]}–$${range[1]}</span>`
  ).join("") || "<span class='dim'>not specified</span>";

  root.innerHTML = `
    <div class="dashboard">
      <div class="d-row">
        <section class="card card-program">
          <h3>Active program</h3>
          <h2>${escapeHtml(program.name || "")}</h2>
          <div class="meta">
            <span class="platform-chip platform-${escapeHtml(program.platform || 'other')}">${escapeHtml(program.platform || '')}</span>
            ${program.policy_url ? `<a href="${escapeHtml(program.policy_url)}" target="_blank" rel="noopener">Policy</a>` : ''}
          </div>
          <div class="bounties">${bountyText}</div>
        </section>

        <section class="card card-scope">
          <h3>Scope summary</h3>
          ${renderScopeDonut(ss)}
          <ul class="scope-counts">
            <li><span class="dot dot-in"></span> In-scope assets <b>${ss.assets_in || 0}</b></li>
            <li><span class="dot dot-out"></span> Blocked assets <b>${ss.assets_blocked || 0}</b></li>
            <li><span class="dot dot-amb"></span> Ambiguous <b>${ss.assets_ambiguous || 0}</b></li>
            <li class="dim">${ss.rule_in_count || 0} in-scope rules · ${ss.rule_out_count || 0} out-of-scope rules</li>
          </ul>
        </section>

        <section class="card card-tools">
          <h3>Toolchain</h3>
          <div class="tool-summary">
            <div class="tool-counts">
              <span class="big">${data.tool_summary?.installed ?? "?"}</span>
              <span class="dim">of ${data.tool_summary?.total ?? "?"} installed</span>
            </div>
            <a class="btn-link" href="#workspace/tools">Toolchain →</a>
          </div>
        </section>
      </div>

      <div class="d-row">
        <section class="card card-actions">
          <h3>Next best actions</h3>
          ${renderNextActions(data.next_best_actions)}
        </section>

        <section class="card card-active-jobs">
          <h3>Active jobs</h3>
          ${renderActiveJobs(data.active_jobs)}
        </section>
      </div>

      <div class="d-row">
        <section class="card card-findings">
          <h3>New finding candidates <span class="dim">(confidence ≥ 0.6)</span></h3>
          ${renderFindingsMini(data.new_findings, slug)}
        </section>

        <section class="card card-reports">
          <h3>Reports ready</h3>
          ${renderReportsReady(data.reports_ready)}
        </section>
      </div>

      <div class="d-row">
        <section class="card card-assets">
          <h3>Recent assets <span class="dim">(in-scope, last ${data.recent_assets?.length || 0})</span></h3>
          ${renderRecentAssets(data.recent_assets, slug)}
        </section>
      </div>
    </div>
  `;
}

function renderScopeDonut(ss) {
  const total = (ss.assets_in || 0) + (ss.assets_blocked || 0) + (ss.assets_ambiguous || 0);
  if (total === 0) {
    return `<div class="donut empty"><span class="dim">No assets yet</span></div>`;
  }
  const inPct  = Math.round((ss.assets_in        || 0) / total * 100);
  const outPct = Math.round((ss.assets_blocked   || 0) / total * 100);
  const ambPct = 100 - inPct - outPct;
  // Conic gradient avoids needing an SVG library.
  const gradient =
    `conic-gradient(var(--scope-in) 0 ${inPct}%, ` +
    `var(--scope-out) ${inPct}% ${inPct + outPct}%, ` +
    `var(--scope-ambiguous) ${inPct + outPct}% 100%)`;
  return `
    <div class="donut" style="background: ${gradient};">
      <div class="donut-hole">${total}</div>
    </div>
  `;
}

function renderNextActions(actions) {
  if (!actions || actions.length === 0) {
    return `<p class="dim">Strategist hasn't recommended anything yet. Run passive recon to seed the queue.</p>`;
  }
  return `<ol class="actions-list">${
    actions.map(a => `
      <li>
        <div class="action-text">${escapeHtml(a.text || a.title || JSON.stringify(a))}</div>
        ${a.why ? `<div class="action-why dim">${escapeHtml(a.why)}</div>` : ''}
      </li>`).join("")
  }</ol>`;
}

function renderActiveJobs(jobs) {
  if (!jobs || jobs.length === 0) {
    return `<p class="dim">No jobs running.</p>`;
  }
  return `
    <table class="mini-table">
      <thead><tr><th>Agent</th><th>Job</th><th>Model</th><th>Started</th></tr></thead>
      <tbody>
        ${jobs.map(j => `
          <tr>
            <td>${escapeHtml(j.agent)}</td>
            <td><code>${escapeHtml((j.job_id || '').slice(0,12))}</code></td>
            <td>${escapeHtml(j.model || '')}</td>
            <td class="dim">${escapeHtml(j.started_at || '')}</td>
          </tr>`).join("")}
      </tbody>
    </table>`;
}

function renderFindingsMini(findings, slug) {
  if (!findings || findings.length === 0) {
    return `<p class="dim">No new finding candidates above the confidence floor.</p>`;
  }
  return `
    <table class="mini-table findings-mini">
      <thead><tr><th>Bug</th><th>Class</th><th>Title</th><th>Conf</th><th>CVSS</th></tr></thead>
      <tbody>
        ${findings.map(f => `
          <tr>
            <td><code>${escapeHtml(f.bug_id || '')}</code></td>
            <td>${escapeHtml(f.vuln_class)}</td>
            <td>${escapeHtml(f.title)}</td>
            <td>${(f.confidence ?? 0).toFixed(2)}</td>
            <td>${(f.cvss_score ?? 0).toFixed(1)}</td>
          </tr>`).join("")}
      </tbody>
    </table>`;
}

function renderReportsReady(drafts) {
  if (!drafts || drafts.length === 0) {
    return `<p class="dim">No drafts pending approval.</p>`;
  }
  return `
    <ul class="reports-list">
      ${drafts.map(d => `
        <li>
          <code>${escapeHtml(d.bug_id || '')}</code>
          <span class="platform-chip platform-${escapeHtml(d.platform)}">${escapeHtml(d.platform)}</span>
          <span class="dim">${escapeHtml(d.severity || '')}</span>
          <div class="title">${escapeHtml(d.title || '')}</div>
        </li>`).join("")}
    </ul>`;
}

function renderRecentAssets(assets, slug) {
  if (!assets || assets.length === 0) {
    return `<p class="dim">No in-scope assets recorded yet. Run passive recon.</p>`;
  }
  return `
    <table class="mini-table assets-mini">
      <thead><tr><th>Host</th><th>Status</th><th>Title</th><th>Scope</th></tr></thead>
      <tbody>
        ${assets.map(a => `
          <tr>
            <td><code>${escapeHtml(a.subdomain || '')}</code></td>
            <td>${a.http_status ?? '—'}</td>
            <td>${escapeHtml((a.http_title || '').slice(0, 80))}</td>
            <td><scope-badge program-slug="${escapeHtml(slug)}" target="${escapeHtml(a.subdomain)}"></scope-badge></td>
          </tr>`).join("")}
      </tbody>
    </table>`;
}

// ── Scope workbench ─────────────────────────────────────────────
async function viewScope() {
  setActiveSection("scope");
  const root = document.getElementById("view-root");
  const slug = ProgramState.activeSlug;
  if (!slug) { root.innerHTML = noProgramHint(); return; }
  if (ProgramState.workflows.length === 0) await refreshWorkflows();
  const workflowOpts = ProgramState.workflows.map(w =>
    `<option value="${w.id}">${escapeHtml(w.name)} (${escapeHtml(w.mode)})</option>`
  ).join("");

  root.innerHTML = `
    <section class="scope-workbench">
      <h2>Scope workbench</h2>
      <p class="hint">Check a target against <strong>${escapeHtml(ProgramState.active?.name || slug)}</strong>'s
         scope rules, preview the command a tool would run, and review recent
         blocked attempts.</p>

      <div class="scope-grid">
        <section class="scope-card">
          <h3>Target check</h3>
          <form id="scope-check-form">
            <label>Target <input type="text" name="target" required placeholder="api.example.com"></label>
            <button type="submit">Check scope</button>
          </form>
          <div id="scope-check-result"></div>
        </section>

        <section class="scope-card">
          <h3>Pre-flight preview</h3>
          <form id="preflight-form">
            <label>Target <input type="text" name="target" required placeholder="api.example.com"></label>
            <label>Workflow / mode
              <select name="mode" required>${workflowOpts}</select>
            </label>
            <label>Tool
              <select name="tool" required>
                <option value="subfinder">subfinder (passive)</option>
                <option value="amass">amass (passive)</option>
                <option value="crtsh">crtsh (passive)</option>
                <option value="dnsx">dnsx (passive)</option>
                <option value="httpx">httpx (low_active)</option>
                <option value="gowitness">gowitness (low_active)</option>
                <option value="wafw00f">wafw00f (low_active)</option>
                <option value="nuclei">nuclei (mod_active)</option>
                <option value="graphw00f">graphw00f (mod_active)</option>
                <option value="clairvoyance">clairvoyance (mod_active)</option>
              </select>
            </label>
            <button type="submit">Open pre-flight</button>
          </form>
        </section>

        <section class="scope-card wide">
          <h3>Recent blocked targets</h3>
          <div id="blocked-targets"><div class="dim">Loading…</div></div>
        </section>
      </div>
    </section>
  `;
  document.getElementById("scope-check-form").addEventListener("submit", onScopeCheckSubmit);
  document.getElementById("preflight-form").addEventListener("submit", onPreflightSubmit);
  refreshBlockedTargets();
}

async function onScopeCheckSubmit(e) {
  e.preventDefault();
  const target = e.target.target.value.trim();
  const out = document.getElementById("scope-check-result");
  if (!target) { out.innerHTML = ""; return; }
  out.innerHTML = `<div class="dim">Checking…</div>`;
  const slug = ProgramState.activeSlug;
  const result = await API.scopeCheck(slug, target);
  out.innerHTML = `
    <div class="scope-result status-${result.scope_status}">
      <scope-badge program-slug="${escapeHtml(slug)}" target="${escapeHtml(target)}"></scope-badge>
      <p class="reason">${escapeHtml(result.reason || '')}</p>
      ${result.matched ? `<pre class="matched">${escapeHtml(JSON.stringify(result.matched, null, 2))}</pre>` : ''}
    </div>`;
}

async function onPreflightSubmit(e) {
  e.preventDefault();
  const f = e.target;
  const target = f.target.value.trim();
  if (!target) return;
  const confirmed = await openPreflightModal({
    programSlug: ProgramState.activeSlug,
    target, mode: f.mode.value, tool: f.tool.value,
  });
  if (confirmed) {
    alert(`Pre-flight confirmed for ${f.tool.value} on ${target}.
Job dispatch lands when the v2 job runner ships.`);
  }
}

async function refreshBlockedTargets() {
  const slug = ProgramState.activeSlug;
  const box = document.getElementById("blocked-targets");
  if (!box) return;
  try {
    const data = await API.blockedTargets(slug);
    if (data.count === 0) {
      box.innerHTML = `<p class="dim">No recent scope rejections recorded.</p>`;
      return;
    }
    const rows = (data.blocked || []).map(b => `
      <tr class="status-${b.scope_status}">
        <td><code>${escapeHtml(b.target || '?')}</code></td>
        <td>${escapeHtml(b.reason || '')}</td>
        <td>${escapeHtml(b.platform || '')}</td>
        <td><code>${escapeHtml(b.job_id || '')}</code></td>
        <td>${escapeHtml(b.ts || '')}</td>
      </tr>`).join("");
    box.innerHTML = `
      <table class="blocked-table">
        <thead><tr><th>Target</th><th>Reason</th><th>Platform</th><th>Job</th><th>When</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  } catch (e) {
    box.innerHTML = `<p class="error">Failed to load: ${escapeHtml(String(e))}</p>`;
  }
}

// ── Phase 18: Assets tree ───────────────────────────────────────
let _assetFilterState = { q: "", in_scope_only: false, with_findings_only: false };
let _assetSelectedId = null;

async function viewAssets() {
  setActiveSection("assets");
  const slug = ProgramState.activeSlug;
  const root = document.getElementById("view-root");
  if (!slug) { root.innerHTML = noProgramHint(); return; }
  root.innerHTML = `
    <section class="assets-view">
      <header class="assets-header">
        <h2>Assets</h2>
        <form id="asset-filter">
          <input type="search" name="q" placeholder="Filter subdomains…"
                 value="${escapeHtml(_assetFilterState.q || '')}">
          <label><input type="checkbox" name="in_scope_only"
                         ${_assetFilterState.in_scope_only ? 'checked' : ''}>
                 In scope only</label>
          <label><input type="checkbox" name="with_findings_only"
                         ${_assetFilterState.with_findings_only ? 'checked' : ''}>
                 With findings</label>
        </form>
      </header>
      <div class="assets-grid">
        <div class="asset-tree" id="asset-tree"><div class="dim">Loading…</div></div>
        <div class="asset-detail" id="asset-detail">
          <p class="dim">Select an asset to view detail.</p>
        </div>
      </div>
    </section>
  `;
  document.getElementById("asset-filter").addEventListener("change", onAssetFilterChange);
  document.getElementById("asset-filter").querySelector("input[name='q']")
    .addEventListener("input", debounce(onAssetFilterChange, 250));
  await refreshAssetTree();
}

async function refreshAssetTree() {
  const slug = ProgramState.activeSlug;
  const treeBox = document.getElementById("asset-tree");
  if (!treeBox) return;
  const qs = {};
  if (_assetFilterState.q) qs.q = _assetFilterState.q;
  if (_assetFilterState.in_scope_only) qs.in_scope_only = "1";
  if (_assetFilterState.with_findings_only) qs.with_findings_only = "1";
  let data;
  try { data = await API.assets(slug, qs); }
  catch (e) { treeBox.innerHTML = `<div class="error">${escapeHtml(String(e))}</div>`; return; }
  if (data.subdomain_count === 0) {
    treeBox.innerHTML = `<p class="dim">No assets match. Run passive recon to populate.</p>`;
    return;
  }
  treeBox.innerHTML = data.tree.map(root => `
    <details class="tree-root" ${data.tree.length === 1 ? 'open' : ''}>
      <summary>
        <strong>${escapeHtml(root.root_domain)}</strong>
        <span class="dim">${root.subdomain_count}</span>
      </summary>
      <ul class="tree-children">
        ${root.subdomains.map(s => `
          <li data-sid="${s.id}" class="tree-leaf${s.id === _assetSelectedId ? ' selected' : ''}">
            <scope-badge program-slug="${escapeHtml(slug)}" target="${escapeHtml(s.subdomain)}"></scope-badge>
            <code>${escapeHtml(s.subdomain)}</code>
            ${s.http_status ? `<span class="http-status">${s.http_status}</span>` : ''}
            ${s.finding_count ? `<span class="finding-badge">${s.finding_count}</span>` : ''}
          </li>`).join("")}
      </ul>
    </details>
  `).join("");
  treeBox.querySelectorAll(".tree-leaf").forEach(el => {
    el.addEventListener("click", () => {
      const sid = Number(el.dataset.sid);
      _assetSelectedId = sid;
      treeBox.querySelectorAll(".tree-leaf").forEach(n => n.classList.remove("selected"));
      el.classList.add("selected");
      renderAssetDetail(sid);
    });
  });
}

function onAssetFilterChange(e) {
  const form = document.getElementById("asset-filter");
  _assetFilterState = {
    q: form.q.value.trim(),
    in_scope_only: form.in_scope_only.checked,
    with_findings_only: form.with_findings_only.checked,
  };
  refreshAssetTree();
}

async function renderAssetDetail(sid) {
  const box = document.getElementById("asset-detail");
  if (!box) return;
  box.innerHTML = `<div class="dim">Loading…</div>`;
  let data;
  try { data = await API.assetDetail(sid); }
  catch (e) { box.innerHTML = `<div class="error">${escapeHtml(String(e))}</div>`; return; }
  const slug = ProgramState.activeSlug;
  const techs = (data.technologies || []).map(t =>
    `<span class="tech-chip">${escapeHtml(t)}</span>`).join("") || '<span class="dim">none</span>';
  const ips = (data.ip_addresses || []).map(i =>
    `<code>${escapeHtml(i)}</code>`).join(", ") || '<span class="dim">unresolved</span>';
  const findingRows = (data.findings || []).map(f => `
    <tr>
      <td><code>${escapeHtml(f.bug_id)}</code></td>
      <td>${escapeHtml(f.vuln_class)}</td>
      <td>${escapeHtml(f.title)}</td>
      <td>${(f.cvss_score || 0).toFixed(1)}</td>
      <td>${escapeHtml(f.status)}</td>
    </tr>`).join("");
  box.innerHTML = `
    <header class="asset-detail-header">
      <scope-badge program-slug="${escapeHtml(slug)}" target="${escapeHtml(data.subdomain)}"></scope-badge>
      <h3><code>${escapeHtml(data.subdomain)}</code></h3>
      ${data.http_status ? `<span class="http-status">HTTP ${data.http_status}</span>` : ''}
    </header>
    ${data.http_title ? `<p class="asset-title">${escapeHtml(data.http_title)}</p>` : ''}
    <dl class="kv">
      <dt>Root domain</dt><dd><code>${escapeHtml(data.domain)}</code></dd>
      <dt>DNS resolved</dt><dd>${data.dns_resolved ? 'yes' : 'no'}</dd>
      <dt>IPs</dt><dd>${ips}</dd>
      <dt>Technologies</dt><dd>${techs}</dd>
      <dt>First seen</dt><dd class="dim">${escapeHtml(data.created_at || '')}</dd>
      <dt>Last updated</dt><dd class="dim">${escapeHtml(data.updated_at || '')}</dd>
    </dl>
    ${data.screenshot_path ? `
      <section class="screenshot">
        <h4>Screenshot</h4>
        <p class="dim"><code>${escapeHtml(data.screenshot_path)}</code></p>
      </section>` : ''}
    ${findingRows ? `
      <section class="asset-findings">
        <h4>Findings (${data.findings.length})</h4>
        <table class="mini-table">
          <thead><tr><th>Bug</th><th>Class</th><th>Title</th><th>CVSS</th><th>Status</th></tr></thead>
          <tbody>${findingRows}</tbody>
        </table>
      </section>` : ''}
  `;
}

function debounce(fn, ms) {
  let timer;
  return function (...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), ms);
  };
}

// ── Phase 19: Findings Kanban + detail ──────────────────────────
const KANBAN_COLUMN_LABELS = {
  new:            "New",
  needs_review:   "Needs review",
  confirmed:      "Confirmed",
  draft_ready:    "Draft ready",
  submitted:      "Submitted",
  retesting:      "Retesting",
  closed:         "Closed",
  false_positive: "False positive",
};

async function viewFindings() {
  setActiveSection("findings");
  const slug = ProgramState.activeSlug;
  const root = document.getElementById("view-root");
  if (!slug) { root.innerHTML = noProgramHint(); return; }
  root.innerHTML = `<div class="loading">Loading triage board…</div>`;
  let data;
  try { data = await API.findingsBoard(slug); }
  catch (e) { root.innerHTML = `<div class="error">${escapeHtml(String(e))}</div>`; return; }

  const board = Object.keys(KANBAN_COLUMN_LABELS).map(col => `
    <div class="kanban-column" data-status="${col}">
      <h3>${escapeHtml(KANBAN_COLUMN_LABELS[col])}
          <span class="dim">${data.counts[col] || 0}</span></h3>
      <div class="kanban-cards">
        ${(data.columns[col] || []).map(f => renderFindingCard(f, slug)).join("")}
      </div>
    </div>
  `).join("");

  root.innerHTML = `
    <section class="findings-view">
      <header class="findings-header">
        <h2>Findings — ${data.total} in program</h2>
        <p class="dim">Click a card for detail. Drag between columns to update status.</p>
      </header>
      <div class="kanban-board">${board}</div>
      ${data.columns.dup && data.columns.dup.length ? `
        <section class="kanban-dup">
          <h3>Analyst-flagged duplicates <span class="dim">${data.counts.dup || 0}</span></h3>
          <div class="kanban-cards">
            ${data.columns.dup.map(f => renderFindingCard(f, slug)).join("")}
          </div>
        </section>` : ''}
    </section>`;
  attachKanbanHandlers();
}

function renderFindingCard(f, slug) {
  const sev = f.cvss_score >= 9 ? 'critical'
            : f.cvss_score >= 7 ? 'high'
            : f.cvss_score >= 4 ? 'medium'
            : f.cvss_score > 0  ? 'low' : 'info';
  return `
    <article class="finding-card sev-${sev} conf-${f.confidence_label}"
             draggable="true" data-fid="${f.id}" data-status="${f.status || ''}">
      <header>
        <code>${escapeHtml(f.bug_id || '')}</code>
        <span class="vuln-chip">${escapeHtml(f.vuln_class)}</span>
        <span class="cvss-chip" title="CVSS ${f.cvss_score ?? '?'}">${(f.cvss_score || 0).toFixed(1)}</span>
      </header>
      <div class="title">${escapeHtml(f.title || '')}</div>
      <footer>
        <span class="conf-chip">${escapeHtml(f.confidence_label)} conf</span>
        ${f.draft_count ? `<span class="draft-chip">${f.draft_count} drafts</span>` : ''}
        ${f.bounty_estimate_usd ? `<span class="bounty-chip">$${f.bounty_estimate_usd}</span>` : ''}
      </footer>
    </article>
  `;
}

function attachKanbanHandlers() {
  const root = document.getElementById("view-root");
  root.querySelectorAll(".finding-card").forEach(card => {
    card.addEventListener("click", () => {
      location.hash = `#workspace/findings/${card.dataset.fid}`;
    });
    card.addEventListener("dragstart", (e) => {
      e.dataTransfer.setData("text/finding-id", card.dataset.fid);
      e.dataTransfer.effectAllowed = "move";
      card.classList.add("dragging");
    });
    card.addEventListener("dragend", () => card.classList.remove("dragging"));
  });
  root.querySelectorAll(".kanban-column").forEach(col => {
    col.addEventListener("dragover", (e) => {
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      col.classList.add("drag-over");
    });
    col.addEventListener("dragleave", () => col.classList.remove("drag-over"));
    col.addEventListener("drop", async (e) => {
      e.preventDefault();
      col.classList.remove("drag-over");
      const fid = e.dataTransfer.getData("text/finding-id");
      const newStatus = col.dataset.status;
      if (!fid || !newStatus) return;
      const r = await API.findingStatus(fid, newStatus);
      if (r.status >= 400) {
        alert(r.body.error || `Failed to update status (${r.status}).`);
        return;
      }
      viewFindings();  // refresh
    });
  });
}

async function viewFindingDetail(fid) {
  setActiveSection("findings");
  const root = document.getElementById("view-root");
  root.innerHTML = `<div class="loading">Loading finding…</div>`;
  let data;
  try { data = await API.findingDetail(fid); }
  catch (e) { root.innerHTML = `<div class="error">${escapeHtml(String(e))}</div>`; return; }

  const tabs = ["overview", "raw", "ai", "taxonomy", "manual", "drafts"];
  root.innerHTML = `
    <section class="finding-detail">
      <header class="finding-detail-header">
        <a href="#workspace/findings" class="back-link">← Board</a>
        <h2><code>${escapeHtml(data.bug_id)}</code> ${escapeHtml(data.title)}</h2>
        <span class="status-pill status-${escapeHtml(data.status)}">${escapeHtml(data.status)}</span>
      </header>
      <nav class="tabs">
        ${tabs.map(t => `<a href="#" data-tab="${t}">${t}</a>`).join("")}
      </nav>
      <div class="tab-panels" id="tab-panels">
        ${renderOverviewTab(data)}
        ${renderRawTab(data)}
        ${renderAITab(data)}
        ${renderTaxonomyTab(data)}
        ${renderManualTab(data)}
        ${renderDraftsTab(data)}
      </div>
    </section>
  `;
  // Activate first tab.
  const panels = root.querySelectorAll(".tab-panel");
  const links  = root.querySelectorAll(".tabs a");
  function activate(name) {
    panels.forEach(p => p.classList.toggle("active", p.dataset.tab === name));
    links.forEach(a => a.classList.toggle("active", a.dataset.tab === name));
  }
  activate("overview");
  links.forEach(a => a.addEventListener("click", (e) => {
    e.preventDefault();
    activate(a.dataset.tab);
  }));
  // Wire verify buttons.
  root.querySelectorAll(".btn-verify").forEach(btn => {
    btn.addEventListener("click", async () => {
      const r = await API.verifyEvidence(fid, btn.dataset.eid);
      if (r.ok) viewFindingDetail(fid);
      else alert(r.error || "Verify failed.");
    });
  });
  // Status-change select.
  const statusSel = root.querySelector("#detail-status");
  if (statusSel) {
    statusSel.addEventListener("change", async () => {
      const r = await API.findingStatus(fid, statusSel.value);
      if (r.status >= 400) {
        alert(r.body.error || "Status update failed.");
        statusSel.value = data.status;
      } else {
        viewFindingDetail(fid);
      }
    });
  }
}

function renderOverviewTab(data) {
  const readiness = data.readiness || {};
  const checklist = [
    ["affected_url",       "Affected URL"],
    ["reproduction_steps", "Reproduction steps"],
    ["impact",             "Impact statement"],
    ["remediation",        "Suggested remediation"],
    ["screenshot",         "Screenshot"],
  ];
  const checks = checklist.map(([k, label]) =>
    `<li class="${readiness[k] ? 'done' : 'todo'}">${readiness[k] ? '✓' : '✗'} ${escapeHtml(label)}</li>`
  ).join("");
  const valid = data.valid_statuses || [];
  return `
    <section class="tab-panel" data-tab="overview">
      <dl class="kv">
        <dt>Bug ID</dt><dd><code>${escapeHtml(data.bug_id)}</code></dd>
        <dt>Vuln class</dt><dd>${escapeHtml(data.vuln_class)}</dd>
        <dt>Domain</dt><dd><code>${escapeHtml(data.domain || '')}</code></dd>
        <dt>CVSS</dt><dd>${(data.cvss_score ?? 0).toFixed(1)} <span class="dim">${escapeHtml(data.cvss_vector || '')}</span></dd>
        <dt>Bounty estimate</dt><dd>$${data.bounty_estimate_usd ?? 0}</dd>
        <dt>Confidence</dt><dd>${(data.confidence ?? 0).toFixed(2)}</dd>
        <dt>Status</dt><dd>
          <select id="detail-status">
            ${valid.map(s => `<option value="${s}" ${s === data.status ? 'selected' : ''}>${s}</option>`).join("")}
          </select>
        </dd>
      </dl>
      <section class="readiness">
        <h3>Evidence completeness</h3>
        <ul>${checks}</ul>
      </section>
      ${data.description ? `<section class="description"><h3>Description</h3><p>${escapeHtml(data.description)}</p></section>` : ''}
    </section>
  `;
}

function renderRawTab(data) {
  const obs = (data.evidence?.observed || []).concat(data.evidence?.inferred || []);
  const verified = data.evidence?.verified || [];
  if (obs.length === 0 && verified.length === 0) {
    return `<section class="tab-panel" data-tab="raw"><p class="dim">No observed/inferred/verified evidence recorded yet.</p></section>`;
  }
  const rows = [...obs, ...verified].map(e => `
    <div class="ev-row src-${escapeHtml(e.source)}">
      <header>
        <code>${escapeHtml(e.key)}</code>
        <span class="ev-src">${escapeHtml(e.source)}</span>
        ${e.verified_by ? `<span class="dim">verified by ${escapeHtml(e.verified_by)}</span>` : ''}
      </header>
      <pre>${escapeHtml(typeof e.value === 'string' ? e.value : JSON.stringify(e.value, null, 2))}</pre>
    </div>
  `).join("");
  return `
    <section class="tab-panel" data-tab="raw">
      <p class="dim immut">Observed and inferred evidence is immutable. Verified rows are operator-confirmed AI hypotheses.</p>
      ${rows}
    </section>
  `;
}

function renderAITab(data) {
  const rows = (data.evidence?.ai_hypothesis || []);
  if (rows.length === 0) {
    return `<section class="tab-panel" data-tab="ai"><p class="dim">No AI hypotheses recorded.</p></section>`;
  }
  return `
    <section class="tab-panel" data-tab="ai">
      <p class="dim">AI-generated rows are mutable until verified. Verify only after manual reproduction.</p>
      ${rows.map(e => `
        <div class="ev-row src-ai_hypothesis">
          <header>
            <code>${escapeHtml(e.key)}</code>
            <span class="ai-badge">AI HYPOTHESIS</span>
            <button class="btn-verify" data-eid="${e.id}">Verify</button>
          </header>
          <pre>${escapeHtml(typeof e.value === 'string' ? e.value : JSON.stringify(e.value, null, 2))}</pre>
        </div>
      `).join("")}
    </section>
  `;
}

function renderTaxonomyTab(data) {
  const attack = (data.attack_techniques || []);
  const tax = (data.taxonomy || []);
  return `
    <section class="tab-panel" data-tab="taxonomy">
      <h3>MITRE ATT&CK</h3>
      ${attack.length ? `<ul class="tax-list">${attack.map(t => `
        <li><code>${escapeHtml(t.technique_id)}</code> ${escapeHtml(t.tactic)}
            <span class="dim">conf ${(t.confidence ?? 0).toFixed(2)}</span>
            ${t.rationale ? `<p>${escapeHtml(t.rationale)}</p>` : ''}</li>`).join("")}</ul>`
        : '<p class="dim">No ATT&CK mappings.</p>'}
      <h3>CWE / OWASP</h3>
      ${tax.length ? `<ul class="tax-list">${tax.map(t => `
        <li><b>${escapeHtml(t.taxonomy.toUpperCase())}</b>
            <code>${escapeHtml(t.code)}</code>
            ${escapeHtml(t.name || '')}
            <span class="dim">${escapeHtml(t.source)}</span></li>`).join("")}</ul>`
        : '<p class="dim">No CWE/OWASP mapping yet.</p>'}
    </section>
  `;
}

function renderManualTab(data) {
  const md = data.manual_checklist_md;
  if (!md) {
    return `<section class="tab-panel" data-tab="manual">
      <p class="dim">No curated manual checklist for vuln class <code>${escapeHtml(data.vuln_class)}</code>.</p>
    </section>`;
  }
  // Minimal markdown-to-HTML — just headings, lists, code, bold.
  return `<section class="tab-panel" data-tab="manual">${renderMiniMarkdown(md)}</section>`;
}

function renderDraftsTab(data) {
  const drafts = data.drafts || [];
  if (drafts.length === 0) {
    return `<section class="tab-panel" data-tab="drafts">
      <p class="dim">No platform drafts yet. The Reporter agent will create them once analysis is complete.</p>
    </section>`;
  }
  return `<section class="tab-panel" data-tab="drafts">
    <ul class="drafts-list">
      ${drafts.map(d => `
        <li class="${d.human_approved ? 'approved' : 'pending'}">
          <header>
            <span class="platform-chip platform-${escapeHtml(d.platform)}">${escapeHtml(d.platform)}</span>
            <span class="dim">${escapeHtml(d.severity || '')}</span>
            ${d.human_approved ? '<span class="approved-pill">approved</span>' : '<span class="pending-pill">pending</span>'}
          </header>
          <div class="title">${escapeHtml(d.title || '')}</div>
        </li>`).join("")}
    </ul>
  </section>`;
}

function renderMiniMarkdown(md) {
  // VERY minimal — for the curated checklists we control the inputs of,
  // so we only need: # heading, - list, [ ] checkbox, **bold**, `code`.
  let html = escapeHtml(md);
  html = html.replace(/^### (.+)$/gm, "<h3>$1</h3>");
  html = html.replace(/^## (.+)$/gm,  "<h2>$1</h2>");
  html = html.replace(/^# (.+)$/gm,   "<h1>$1</h1>");
  html = html.replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>");
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  // Lists with [ ] checkboxes
  html = html.replace(/^- \[ \] (.+)$/gm, '<li class="cb"><input type="checkbox"> $1</li>');
  html = html.replace(/^- (.+)$/gm, "<li>$1</li>");
  html = html.replace(/(<li[^>]*>.*<\/li>\s*)+/gs, "<ul>$&</ul>");
  // Paragraphs (anything that's just a non-empty plain line)
  html = html.split(/\n{2,}/).map(p =>
    /^<(h\d|ul|li|p)/.test(p.trim()) ? p : `<p>${p}</p>`
  ).join("\n");
  return html;
}

async function viewAttack() {
  setActiveSection("attack");
  const data = await API.heatmap(activeJobId());
  const root = document.getElementById("view-root");
  const cells = TACTICS.map(([id, name]) => {
    const cell = data.tactics[id] || {count: 0, max_confidence: 0, top_techniques: []};
    const score = cell.count * (cell.max_confidence || 0);
    const opacity = Math.min(1.0, score / 5.0).toFixed(2);
    return `<div class="tactic" style="background: rgba(220,80,40,${opacity})" data-tactic="${id}" title="${id} — ${name}">
              <div class="tname">${name}</div>
              <div class="tcount">${cell.count}</div>
              <ul class="techs">${(cell.top_techniques || []).map(t => `<li>${t.id}</li>`).join("")}</ul>
            </div>`;
  }).join("");
  root.innerHTML = `
    <h2>ATT&amp;CK Heatmap — ${data.total_findings} findings</h2>
    <div class="heatmap">${cells}</div>`;
}

// ── Phase 20: Reports — drafts list with quality gate ───────────
async function viewReports() {
  setActiveSection("reports");
  const slug = ProgramState.activeSlug;
  const root = document.getElementById("view-root");
  if (!slug) { root.innerHTML = noProgramHint(); return; }
  root.innerHTML = `<div class="loading">Loading drafts…</div>`;
  // Reuse dashboard's reports_ready widget data for the list.
  let data;
  try { data = await API.dashboard(slug); }
  catch (e) { root.innerHTML = `<div class="error">${escapeHtml(String(e))}</div>`; return; }
  const drafts = data.reports_ready || [];
  if (drafts.length === 0) {
    root.innerHTML = `
      <section class="reports-view">
        <h2>Reports</h2>
        <p class="dim">No drafts pending approval. The Reporter agent
           creates drafts after Analyst scores a finding.</p>
      </section>`;
    return;
  }
  root.innerHTML = `
    <section class="reports-view">
      <h2>Reports — ${drafts.length} draft${drafts.length === 1 ? '' : 's'} pending</h2>
      <p class="dim">Each draft must pass the 10-check quality gate before copy-to-clipboard.</p>
      <div class="reports-grid">
        ${drafts.map(d => `
          <article class="report-card" data-did="${d.id}">
            <header>
              <code>${escapeHtml(d.bug_id || '')}</code>
              <span class="platform-chip platform-${escapeHtml(d.platform)}">${escapeHtml(d.platform)}</span>
              <span class="dim">${escapeHtml(d.severity || '')}</span>
            </header>
            <div class="title">${escapeHtml(d.title || '')}</div>
            <footer>
              <span class="dim">Click to open quality gate</span>
            </footer>
          </article>
        `).join("")}
      </div>
      <div id="quality-gate-pane"></div>
    </section>
  `;
  root.querySelectorAll(".report-card").forEach(card => {
    card.addEventListener("click", () => renderQualityGate(card.dataset.did));
  });
}

async function renderQualityGate(draftId) {
  const pane = document.getElementById("quality-gate-pane");
  pane.innerHTML = `<div class="loading">Running quality gate…</div>`;
  const gate = await API.qualityGate(draftId, false);
  pane.innerHTML = `
    <section class="quality-gate">
      <header>
        <h3>Quality gate — ${gate.passed_count} / ${gate.total} passing</h3>
        <span class="gate-pill ${gate.passed ? 'ok' : 'block'}">
          ${gate.passed ? 'READY TO SUBMIT' : 'BLOCKED'}
        </span>
      </header>
      <ul class="gate-checks">
        ${gate.checks.map(c => `
          <li class="${c.passed ? 'ok' : 'fail'}">
            <span class="mark">${c.passed ? '✓' : '✗'}</span>
            <span class="label">${escapeHtml(c.label)}</span>
            ${c.reason ? `<span class="reason dim">${escapeHtml(c.reason)}</span>` : ''}
          </li>`).join("")}
      </ul>
      <label class="review-ack">
        <input type="checkbox" id="gate-reviewed">
        I have reviewed the manual verification checklist for this finding.
      </label>
      <button class="btn-copy-body" disabled>Copy draft body to clipboard</button>
    </section>
  `;
  const ack = pane.querySelector("#gate-reviewed");
  const btn = pane.querySelector(".btn-copy-body");
  ack.addEventListener("change", async () => {
    // Re-run gate with reviewed=1 to refresh state.
    const fresh = await API.qualityGate(draftId, ack.checked);
    btn.disabled = !fresh.passed;
    if (ack.checked) renderQualityGate(draftId);  // re-render
  });
  btn.addEventListener("click", async () => {
    const detail = await API.submission(draftId);
    if (!detail || !detail.body_md) return;
    try {
      await navigator.clipboard.writeText(detail.body_md);
      btn.textContent = "Copied ✓";
      setTimeout(() => { btn.textContent = "Copy draft body to clipboard"; }, 1500);
    } catch (_) { /* ignore */ }
  });
}

const CATEGORY_LABELS = {
  subdomain:  "Subdomain enumeration",
  dns_http:   "DNS / HTTP probing",
  screenshot: "Screenshots",
  vuln:       "Vulnerability scanning",
  fuzz:       "Content discovery / fuzzing",
  api:        "API enumeration",
  graphql:    "GraphQL",
  cloud:      "Cloud surface",
  js:         "JS analysis / secrets",
  other:      "Other",
};

async function viewTools() {
  setActiveSection("tools");
  await renderToolsView({ refresh: false });
}

async function renderToolsView({ refresh = false }) {
  const root = document.getElementById("view-root");
  root.innerHTML = `<div class="loading">Probing toolchain${refresh ? ' (fresh)' : ''}…</div>`;
  let data;
  try { data = await API.toolHealth(refresh); }
  catch (e) { root.innerHTML = `<div class="error">${escapeHtml(String(e))}</div>`; return; }

  // Group by category.
  const groups = {};
  for (const t of (data.tools || [])) {
    const k = t.category || "other";
    (groups[k] = groups[k] || []).push(t);
  }
  const order = ["subdomain", "dns_http", "screenshot", "vuln", "fuzz",
                  "api", "graphql", "cloud", "js", "other"];
  const sections = order
    .filter(k => groups[k] && groups[k].length)
    .map(k => `
      <section class="tools-group">
        <h3>${escapeHtml(CATEGORY_LABELS[k] || k)}
            <span class="dim">(${groups[k].filter(t => t.installed).length} / ${groups[k].length} installed)</span></h3>
        <table class="tools-table">
          <thead><tr>
            <th>Tool</th><th>Status</th><th>Version</th><th>Path</th><th>Method</th><th>Install command</th>
          </tr></thead>
          <tbody>
            ${groups[k].map(t => `
              <tr class="${t.installed ? 'installed' : 'missing'}">
                <td>${escapeHtml(t.name)}</td>
                <td>${t.installed ? '<span class="ok-pill">installed</span>' : '<span class="miss-pill">missing</span>'}</td>
                <td><code>${escapeHtml(t.version || '')}</code></td>
                <td class="dim"><code>${escapeHtml(t.path || '')}</code></td>
                <td>${escapeHtml(t.install_method || '')}</td>
                <td>${t.install_cmd ? `
                  <code>${escapeHtml(t.install_cmd.join(' '))}</code>
                  <button class="btn-copy" data-cmd="${escapeHtml(t.install_cmd.join(' '))}"
                          title="Copy command to clipboard">⧉</button>
                ` : ''}</td>
              </tr>`).join("")}
          </tbody>
        </table>
      </section>`).join("");

  root.innerHTML = `
    <section class="tools-view">
      <header class="tools-header">
        <h2>Toolchain — ${data.summary.installed} / ${data.summary.total} installed</h2>
        <button id="tools-refresh" class="btn-secondary">Re-check tools</button>
      </header>
      ${sections}
    </section>`;

  document.getElementById("tools-refresh").addEventListener("click",
    () => renderToolsView({ refresh: true }));
  root.querySelectorAll(".btn-copy").forEach(btn => {
    btn.addEventListener("click", async (e) => {
      const cmd = e.currentTarget.dataset.cmd;
      try {
        await navigator.clipboard.writeText(cmd);
        e.currentTarget.textContent = "✓";
        setTimeout(() => { e.currentTarget.textContent = "⧉"; }, 1200);
      } catch (_) { /* clipboard may be unavailable in some browsers */ }
    });
  });
}

async function viewAgents() {
  setActiveSection("agents");
  const data = await API.agents(activeJobId());
  const root = document.getElementById("view-root");
  const cards = data.runs.map(r => `
    <div class="agent-card status-${r.status}">
      <h3>${escapeHtml(r.agent)}</h3>
      <span class="model">${escapeHtml(r.model || "")}</span>
      <span class="status">${escapeHtml(r.status)}</span>
      <span class="cost">$${(r.cost_usd || 0).toFixed(4)}</span>
      ${r.error ? `<p class="err">${escapeHtml(r.error)}</p>` : ""}
    </div>`).join("");
  root.innerHTML = `
    <h2>Agents — total cost $${data.total_cost_usd.toFixed(4)}</h2>
    <div class="agent-grid">${cards}</div>`;
}

async function viewSettings() {
  setActiveSection("settings");
  const p = ProgramState.active;
  document.getElementById("view-root").innerHTML = `
    <section class="settings-view">
      <h2>Settings</h2>
      <p class="dim">Per-program settings page lands in Phase 25. For now, this is read-only.</p>
      ${p ? `
        <dl class="kv">
          <dt>Program</dt><dd>${escapeHtml(p.name)}</dd>
          <dt>Slug</dt><dd><code>${escapeHtml(p.slug)}</code></dd>
          <dt>Platform</dt><dd>${escapeHtml(p.platform)}</dd>
          <dt>Handle</dt><dd>${escapeHtml(p.platform_handle || '')}</dd>
          <dt>Policy</dt><dd>${p.policy_url ? `<a href="${escapeHtml(p.policy_url)}" target="_blank" rel="noopener">${escapeHtml(p.policy_url)}</a>` : '<span class="dim">none</span>'}</dd>
          <dt>In-scope rules</dt><dd>${(p.scope || []).length}</dd>
          <dt>Out-of-scope rules</dt><dd>${(p.out_of_scope || []).length}</dd>
        </dl>` : ""}
    </section>`;
}

function noProgramHint() {
  return `<section class="placeholder">
    <h2>Pick a program</h2>
    <p>Select or create a program from the topbar to use Mission Control.</p>
  </section>`;
}

// ── router ──────────────────────────────────────────────────────
const SECTIONS = {
  dashboard: viewDashboard,
  scope:     viewScope,
  assets:    viewAssets,
  findings:  viewFindings,
  attack:    viewAttack,
  reports:   viewReports,
  tools:     viewTools,
  agents:    viewAgents,
  settings:  viewSettings,
};

function route() {
  if (ProgramState.list.length === 0) {
    viewOnboarding();
    return;
  }
  const hash = location.hash || "#workspace/dashboard";
  // Format: #workspace/<section>/<id?>
  let section = "dashboard";
  let detailId = null;
  if (hash.startsWith("#workspace/")) {
    const parts = hash.slice("#workspace/".length).split("/");
    section = parts[0] || "dashboard";
    detailId = parts[1] || null;
  } else if (hash.startsWith("#")) {
    const legacy = hash.slice(1);
    if (SECTIONS[legacy]) {
      location.replace(`#workspace/${legacy}`);
      return;
    }
  }
  // Detail routes: #workspace/findings/<fid> → finding detail page.
  if (section === "findings" && detailId) {
    viewFindingDetail(detailId).catch(err => {
      document.getElementById("view-root").innerHTML =
        `<div class="error">Failed to load finding: ${escapeHtml(String(err))}</div>`;
    });
    return;
  }
  const fn = SECTIONS[section] || viewDashboard;
  fn().catch(err => {
    document.getElementById("view-root").innerHTML =
      `<div class="error">Failed to load ${escapeHtml(section)}: ${escapeHtml(String(err))}</div>`;
  });
}

// ── helpers ─────────────────────────────────────────────────────
function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => (
    {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]
  ));
}

// ── boot ────────────────────────────────────────────────────────
async function boot() {
  await Promise.all([refreshPrograms(), refreshWorkflows()]);
  route();

  document.getElementById("program-select")?.addEventListener("change", (e) => {
    setSelectedProgramSlug(e.target.value);
    ProgramState.activeSlug = e.target.value;
    ProgramState.active = ProgramState.list.find(p => p.slug === e.target.value) || null;
    _scopeIndicatorState = null;
    for (let i = sessionStorage.length - 1; i >= 0; i--) {
      const k = sessionStorage.key(i);
      if (k && k.startsWith("rf.scope:")) sessionStorage.removeItem(k);
    }
    renderProgramSelector();
    renderScopeIndicator();
    route();
  });

  window.addEventListener("hashchange", route);
}

window.addEventListener("DOMContentLoaded", boot);

function attachStream(jobId) {
  if (typeof EventSource === "undefined") return;
  const es = new EventSource(`/api/agents/stream?job=${encodeURIComponent(jobId)}`);
  es.onmessage = () => route();
  return es;
}
attachStream(activeJobId());
