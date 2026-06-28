// Thin API client for the ReconForge backend. Every endpoint wraps its
// payload as {success, message, data}; we unwrap .data here so callers get
// the bare object. Same-origin, cookie session.
async function getJSON(url) {
  const r = await fetch(url, {
    credentials: "include",
    headers: { Accept: "application/json" },
  });
  if (!r.ok) {
    // Attach the HTTP status so callers can distinguish 401 (needs login)
    // from a network/backend-down failure.
    const e = new Error(`${url} -> ${r.status}`);
    e.status = r.status;
    throw e;
  }
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
    const e = new Error(j.message || `${url} -> ${r.status}`);
    e.status = r.status;
    throw e;
  }
  return j && j.data !== undefined ? j.data : j;
}

const postJSON = (url, body) => sendJSON("POST", url, body || {});

export const api = {
  // Auth. login() sets the session cookie on success; logout() clears it.
  login: (username, password) => postJSON("/api/login", { username, password }),
  logout: () => postJSON("/api/logout", {}),
  state: () => getJSON("/api/state"),
  agentState: (target) =>
    getJSON("/api/agent/state" + (target ? `?target=${encodeURIComponent(target)}` : "")),
  logs: () => getJSON("/api/logs"),
  scope: () => getJSON("/api/scope"),
  // Methodology phases (kill-chain) for a target. Carries per-phase tool_meta
  // (name + cmd template, no resolved secrets) used by the Command Forge.
  pipeline: (target) =>
    getJSON("/api/pipeline" + (target ? `?target=${encodeURIComponent(target)}` : "")),
  // Execute a single kill-chain phase for a target (scope-gated server-side),
  // and read its live logs. fresh=true starts a new dated run dir.
  pipelineRun: (target, phase, fresh = false) =>
    postJSON("/api/pipeline/run", { target, phase, fresh }),
  pipelineLogs: (target, phase) =>
    getJSON(`/api/pipeline/logs?target=${encodeURIComponent(target)}&phase=${encodeURIComponent(phase)}`),
  // Six-agent LLM chain (Scope Guard → … → Reporter).
  agentRun: (target, mode = "passive_recon") =>
    postJSON("/api/agent/run", { target, mode }),
  agentLogs: (target) =>
    getJSON("/api/agent/logs" + (target ? `?target=${encodeURIComponent(target)}` : "")),
  // Dated scan runs on disk: out/<target>/<datestamp>/<phase>/.
  runs: (target) =>
    getJSON("/api/runs" + (target ? `?target=${encodeURIComponent(target)}` : "")),
  // Saved command library (per program/target).
  commands: (target) =>
    getJSON("/api/commands" + (target ? `?target=${encodeURIComponent(target)}` : "")),
  saveCommand: (body) => postJSON("/api/commands", body),
  deleteCommand: (id) => sendJSON("DELETE", `/api/commands/${id}`),
  // Persist + enforce declared scope (Target Intake). After this resolves,
  // scope_guard gates every dispatch against these exact in/out-of-scope rules.
  saveScope: (body) => postJSON("/api/scope", body),
  // Per-target workflow timeline (Session Log). history() reads the persisted
  // events; logCommand() appends one (e.g. a command copied from the Forge).
  history: (target) =>
    getJSON("/api/history" + (target ? `?domain=${encodeURIComponent(target)}` : "")),
  logCommand: (body) => postJSON("/api/history", body),
  // Login/user accounts (admin only — backend returns 403 otherwise).
  users: () => getJSON("/api/users"),
  createUser: (body) => postJSON("/api/users", body),
  updateUser: (id, body) => sendJSON("PUT", `/api/users/${id}`, body),
  deleteUser: (id) => sendJSON("DELETE", `/api/users/${id}`),
};
