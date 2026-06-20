import React, { useState, useEffect, useCallback } from "react";
import { Users, UserPlus, Trash2, CheckCircle2, AlertTriangle, ShieldCheck } from "lucide-react";
import { api } from "../../api.js";

function Field({ label, hint, children }) {
  return (
    <label className="field">
      <span className="flabel">{label}{hint && <i>{hint}</i>}</span>
      {children}
    </label>
  );
}

/* Accounts — login/user management for the app itself. Wired to the admin-only
   /api/users CRUD in main.py. Non-admins get a clear "admin only" notice rather
   than a broken page (the backend returns 403). */
export default function Accounts() {
  const [users, setUsers] = useState(null);   // null = loading
  const [denied, setDenied] = useState(false);
  const [f, setF] = useState({ username: "", password: "", role: "user" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);
  const set = (k) => (e) => setF((s) => ({ ...s, [k]: e.target.value }));

  const load = useCallback(async () => {
    try {
      const rows = await api.users();
      setUsers(Array.isArray(rows) ? rows : []);
      setDenied(false);
    } catch (e) {
      if (String(e.message || e).includes("403")) setDenied(true);
      setUsers([]);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const create = async () => {
    const username = f.username.trim();
    if (!username || !f.password) { setMsg({ k: "err", t: "Username and password are required." }); return; }
    setBusy(true); setMsg(null);
    try {
      await api.createUser({ username, password: f.password, role: f.role });
      setMsg({ k: "ok", t: `Account “${username}” created.` });
      setF({ username: "", password: "", role: "user" });
      await load();
    } catch (e) {
      setMsg({ k: "err", t: String(e.message || e) });
    } finally {
      setBusy(false);
    }
  };

  const remove = async (u) => {
    setMsg(null);
    try {
      await api.deleteUser(u.id);
      setMsg({ k: "ok", t: `Account “${u.username}” deleted.` });
      await load();
    } catch (e) {
      setMsg({ k: "err", t: String(e.message || e) });
    }
  };

  return (
    <main className="ws">
      <div className="ws-head">
        <div className="ws-title">
          <div className="ey">Admin · Accounts</div>
          <h1>Accounts</h1>
          <div className="sub">Login accounts for ReconForge itself. Admins manage who can sign in and at what role.</div>
        </div>
      </div>

      {denied ? (
        <div className="panel">
          <div className="placeholder">
            <div className="pk">Admin only</div>
            Account management requires an admin login. Sign in as an admin to add or remove accounts.
          </div>
        </div>
      ) : (
        <div className="row2 intake-grid">
          <div className="panel">
            <div className="phead"><div className="pt"><Users /> Accounts</div>
              <div className="pmeta">{users == null ? "…" : `${users.length} account${users.length === 1 ? "" : "s"}`}</div></div>
            <div className="pbody">
              {users == null && <div className="empty">Loading…</div>}
              {users && users.length === 0 && <div className="empty">No accounts.</div>}
              {users && users.map((u) => (
                <div className="job" key={u.id}>
                  <span className="jdom">{u.username}</span>
                  <span className={`tag ${u.role === "admin" ? "run" : "q"}`}>{u.role}</span>
                  <span className="jphase" style={{ marginLeft: "auto" }}>{(u.created_at || "").slice(0, 10)}</span>
                  <button className="icobtn" title="Delete account" onClick={() => remove(u)}><Trash2 size={14} /></button>
                </div>
              ))}
            </div>
          </div>

          <div className="panel">
            <div className="phead"><div className="pt"><UserPlus /> Add account</div></div>
            <div className="pbody form">
              <Field label="Username"><input value={f.username} onChange={set("username")} spellCheck={false} autoComplete="off" placeholder="researcher" /></Field>
              <Field label="Password"><input type="password" value={f.password} onChange={set("password")} autoComplete="new-password" placeholder="••••••••" /></Field>
              <Field label="Role">
                <select value={f.role} onChange={set("role")}>
                  <option value="user">user</option>
                  <option value="admin">admin</option>
                </select>
              </Field>
              <div className="fnote"><ShieldCheck size={12} /> Admins can manage accounts and scope; users can run the pipeline.</div>
              <button className="btn primary" onClick={create} disabled={busy}>
                <UserPlus size={13} /> {busy ? "creating…" : "Create account"}
              </button>
            </div>
          </div>
        </div>
      )}

      {msg && (
        <div className="intake-foot">
          <div className={`savemsg ${msg.k}`}>
            {msg.k === "ok" ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}{msg.t}
          </div>
        </div>
      )}
    </main>
  );
}
