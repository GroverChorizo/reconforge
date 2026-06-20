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

async function sendJSON(method, url, body) {
  const init = {
    method,
    credentials: "include",
    headers: { Accept: "application/json" },
  };
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body || {});
  }
  const r = await fetch(url, init);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.success === false) {
    throw new Error(j.message || `${url} -> ${r.status}`);
  }
  return j && j.data !== undefined ? j.data : j;
}

const postJSON = (url, body) => sendJSON("POST", url, body || {});

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
  // Login/user accounts (admin only — backend returns 403 otherwise).
  users: () => getJSON("/api/users"),
  createUser: (body) => postJSON("/api/users", body),
  updateUser: (id, body) => sendJSON("PUT", `/api/users/${id}`, body),
  deleteUser: (id) => sendJSON("DELETE", `/api/users/${id}`),
};
