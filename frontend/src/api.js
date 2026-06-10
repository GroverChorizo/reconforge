// Thin API client for the ReconForge backend. Every endpoint wraps its
// payload as {success, message, data}; we unwrap .data here so callers get
// the bare object. Same-origin, cookie session.
async function getJSON(url) {
  const r = await fetch(url, {
    credentials: "include",
    headers: { Accept: "application/json" },
  });
  if (!r.ok) throw new Error(`${url} -> ${r.status}`);
  const j = await r.json();
  return j && j.data !== undefined ? j.data : j;
}

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body || {}),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.success === false) {
    throw new Error(j.message || `${url} -> ${r.status}`);
  }
  return j && j.data !== undefined ? j.data : j;
}

export const api = {
  state: () => getJSON("/api/state"),
  agentState: (target) =>
    getJSON("/api/agent/state" + (target ? `?target=${encodeURIComponent(target)}` : "")),
  logs: () => getJSON("/api/logs"),
  scope: () => getJSON("/api/scope"),
  // Methodology phases (kill-chain) for a target. Carries per-phase tool_meta
  // (name + cmd template, no resolved secrets) used by the Command Forge.
  pipeline: (target) =>
    getJSON("/api/pipeline" + (target ? `?target=${encodeURIComponent(target)}` : "")),
  // Persist + enforce declared scope (Target Intake). After this resolves,
  // scope_guard gates every dispatch against these exact in/out-of-scope rules.
  saveScope: (body) => postJSON("/api/scope", body),
};
