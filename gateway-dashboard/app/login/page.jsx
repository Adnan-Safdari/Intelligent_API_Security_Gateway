"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const json = await res.json();
      if (!json.ok) {
        setError(json.error || "could not sign in");
        setPassword("");
        return;
      }
      router.replace("/");
      router.refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="gate">
      <form className="gate-card" onSubmit={submit}>
        <div className="gate-brand">
          <span className="logo">IASG</span>
          <div>
            <strong>Operations</strong>
            <small>Intelligent API Security Gateway</small>
          </div>
        </div>

        <label className="field block">
          Username
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoFocus
            required
          />
        </label>

        <label className="field block">
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>

        {error ? (
          <p className="gate-error" role="alert">
            {error}
          </p>
        ) : null}

        <button type="submit" className="act primary" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>

        <p className="form-note">
          Ten failed attempts locks an account for fifteen minutes. The console that
          detects brute force should not be trivially brute forced.
        </p>
      </form>
    </div>
  );
}
