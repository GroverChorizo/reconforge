import React, { useState } from "react";
import { LogIn, Lock } from "lucide-react";
import { api } from "../api.js";

/* Operator sign-in. The SPA is served before auth, but every /api/* call needs
   a session cookie — without this screen the app could only ever show an empty
   OFFLINE shell. On success we reload so the whole app boots fresh with the new
   cookie (no half-authenticated state to reason about). */
export default function Login() {
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    if (!u.trim() || !p) { setErr("Enter your username and password."); return; }
    setBusy(true); setErr(null);
    try {
      await api.login(u.trim(), p);
      window.location.reload();
    } catch (e2) {
      const m = String(e2.message || e2);
      setErr(e2.status === 401 || /invalid credentials/i.test(m) ? "Invalid credentials." : m);
      setBusy(false);
    }
  };

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={submit}>
        <div className="brand login-brand"><span className="b1">RECON</span><span className="b2">FORGE</span></div>
        <div className="login-sub"><Lock size={11} /> Operator sign-in</div>
        <label className="field">
          <span className="flabel">Username</span>
          <input value={u} onChange={(e) => setU(e.target.value)} autoFocus
                 autoComplete="username" spellCheck={false} />
        </label>
        <label className="field">
          <span className="flabel">Password</span>
          <input type="password" value={p} onChange={(e) => setP(e.target.value)}
                 autoComplete="current-password" />
        </label>
        {err && <div className="login-err">{err}</div>}
        <button className="btn primary login-btn" type="submit" disabled={busy}>
          <LogIn size={14} /> {busy ? "signing in…" : "Sign in"}
        </button>
        <div className="login-foot">The first-run admin password is printed once in the server console.</div>
      </form>
    </div>
  );
}
