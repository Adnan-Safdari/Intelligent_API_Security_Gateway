"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

export default function SetupPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // Closed for good once anyone exists, so arriving here later goes to login.
  useEffect(() => {
    fetch("/api/auth/setup")
      .then((r) => r.json())
      .then((j) => {
        if (!j.needed) router.replace("/login");
      })
      .catch(() => {});
  }, [router]);

  async function submit(e) {
    e.preventDefault();
    if (password !== confirm) {
      setError("the two passwords do not match");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const res = await fetch("/api/auth/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const json = await res.json();
      if (!json.ok) {
        setError(json.error || "could not create the account");
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
            <strong>First run</strong>
            <small>Create the administrator account</small>
          </div>
        </div>

        <p className="form-note">
          Nobody has an account yet, so nothing is reachable until one exists. This page
          closes permanently once it does — a second admin is added from inside the
          console.
        </p>

        <label className="field block">
          Username
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            placeholder="3-32 characters: a-z 0-9 . _ -"
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
            autoComplete="new-password"
            placeholder="at least 10 characters"
            required
          />
        </label>

        <label className="field block">
          Confirm password
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
            required
          />
        </label>

        {error ? (
          <p className="gate-error" role="alert">
            {error}
          </p>
        ) : null}

        <button type="submit" className="act primary" disabled={busy}>
          {busy ? "Creating…" : "Create administrator"}
        </button>
      </form>
    </div>
  );
}
