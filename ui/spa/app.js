// ReconForge v2 SPA — minimal vanilla JS router + views.
// Production polish lands in a follow-up; this scaffold proves the API contract.

const API = {
  agents:      (jobId) => fetch(`/api/agents/runs?job=${encodeURIComponent(jobId)}`).then(r => r.json()),
  heatmap:     (jobId) => fetch(`/api/attack/heatmap?job=${encodeURIComponent(jobId)}`).then(r => r.json()),
  findings:    (jobId) => fetch(`/api/findings?job=${encodeURIComponent(jobId)}`).then(r => r.json()),
  finding:     (id)    => fetch(`/api/findings/${id}`).then(r => r.json()),
  submission:  (id)    => fetch(`/api/submissions/${id}`).then(r => r.json()),
  approve:     (id, v) => fetch(`/api/submissions/${id}/approve`, {
    method: "POST", body: JSON.stringify({approved: v}),
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

function activeJobId() {
  return new URLSearchParams(location.search).get("job") || "demo";
}

async function viewAgents() {
  const data = await API.agents(activeJobId());
  const root = document.getElementById("view-root");
  const cards = data.runs.map(r => `
    <div class="agent-card status-${r.status}">
      <h3>${r.agent}</h3>
      <span class="model">${r.model || ""}</span>
      <span class="status">${r.status}</span>
      <span class="cost">$${(r.cost_usd || 0).toFixed(4)}</span>
      ${r.error ? `<p class="err">${r.error}</p>` : ""}
    </div>`).join("");
  root.innerHTML = `
    <h2>Agents — total cost $${data.total_cost_usd.toFixed(4)}</h2>
    <div class="agent-grid">${cards}</div>`;
}

async function viewHeatmap() {
  const data = await API.heatmap(activeJobId());
  const root = document.getElementById("view-root");
  const cells = TACTICS.map(([id, name]) => {
    const cell = data.tactics[id] || {count: 0, max_confidence: 0, top_techniques: []};
    const score = cell.count * (cell.max_confidence || 0);
    const opacity = Math.min(1.0, score / 5.0).toFixed(2);
    return `<div class="tactic" style="background: rgba(220,80,40,${opacity})"
                 data-tactic="${id}" title="${id} — ${name}">
              <div class="tname">${name}</div>
              <div class="tcount">${cell.count}</div>
              <ul class="techs">${(cell.top_techniques || []).map(
                t => `<li>${t.id}</li>`).join("")}</ul>
            </div>`;
  }).join("");
  root.innerHTML = `
    <h2>ATT&amp;CK Heatmap — ${data.total_findings} findings</h2>
    <div class="heatmap">${cells}</div>`;
}

async function viewFindings() {
  const data = await API.findings(activeJobId());
  const root = document.getElementById("view-root");
  const rows = data.findings.map(f => `
    <tr data-id="${f.id}">
      <td>${f.bug_id}</td>
      <td>${f.vuln_class}</td>
      <td>${f.title}</td>
      <td>${(f.cvss_score || 0).toFixed(1)}</td>
      <td>$${f.bounty_estimate_usd || 0}</td>
      <td>${f.status}</td>
      <td>${f.draft_count} drafts</td>
    </tr>`).join("");
  root.innerHTML = `
    <h2>Findings — ${data.count}</h2>
    <table class="findings">
      <thead><tr>
        <th>Bug ID</th><th>Class</th><th>Title</th><th>CVSS</th>
        <th>Bounty</th><th>Status</th><th>Drafts</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

async function viewSubmissions() {
  const data = await API.findings(activeJobId());
  const root = document.getElementById("view-root");
  root.innerHTML = `
    <h2>Submission Preview</h2>
    <p>Pick a finding from the Findings tab to view its drafts. The preview
       allows you to mark drafts approved before manual submission.</p>`;
}

const VIEWS = {
  agents:      viewAgents,
  heatmap:     viewHeatmap,
  findings:    viewFindings,
  submissions: viewSubmissions,
};

function route() {
  const view = (location.hash || "#agents").slice(1);
  const fn = VIEWS[view] || viewAgents;
  fn().catch(err => {
    document.getElementById("view-root").innerHTML =
      `<div class="error">Failed to load ${view}: ${err}</div>`;
  });
}

window.addEventListener("hashchange", route);
window.addEventListener("DOMContentLoaded", route);

// SSE stream for live agent events — kept minimal in v2 scaffold.
function attachStream(jobId) {
  if (typeof EventSource === "undefined") return;
  const es = new EventSource(`/api/agents/stream?job=${encodeURIComponent(jobId)}`);
  es.onmessage = (ev) => {
    // Re-fetch the active view when any agent event arrives.
    route();
  };
  return es;
}
attachStream(activeJobId());
