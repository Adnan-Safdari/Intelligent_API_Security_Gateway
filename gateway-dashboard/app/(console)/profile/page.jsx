"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHead } from "@/app/ui/chrome";
import { formatTime } from "@/app/ui/format";
import { useLive } from "@/app/ui/store";

const CAN = {
  viewer: ["Read every page"],
  operator: ["Read every page", "Instruct the agent about an address"],
  admin: ["Read every page", "Instruct the agent about an address", "Manage accounts", "Reset the durable record"],
};

export default function ProfilePage() {
  const { me, setToast } = useLive();

  const [sessions, setSessions] = useState([]);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/auth/sessions", { cache: "no-store" });
      const data = await res.json();
      setSessions(data.sessions || []);
    } catch {
      /* the panel shows its own emptiness */
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function changePassword(event) {
    event.preventDefault();
    if (next !== confirm) {
      setToast({ tone: "bad", text: "the two new passwords do not match" });
      return;
    }
    setSaving(true);
    try {
      const res = await fetch("/api/auth/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ current, next }),
      });
      const data = await res.json();
      if (!data.ok) {
        setToast({ tone: "bad", text: data.error });
        return;
      }
      setCurrent("");
      setNext("");
      setConfirm("");
      setToast({
        tone: "good",
        text: data.signedOutElsewhere
          ? `password changed — ${data.signedOutElsewhere} other ${
              data.signedOutElsewhere === 1 ? "session" : "sessions"
            } signed out`
          : "password changed",
      });
      load();
    } finally {
      setSaving(false);
    }
  }

  async function endOthers() {
    const res = await fetch("/api/auth/sessions", { method: "DELETE" });
    const data = await res.json();
    setToast({
      tone: "good",
      text: data.ended ? `signed out of ${data.ended} other sessions` : "no other sessions",
    });
    load();
  }

  const others = sessions.filter((s) => !s.current).length;

  return (
    <>
      <PageHead title="Profile">
        The account this browser is signed in as, and where else it is signed in.
      </PageHead>

      <section className="workbench">
        <div className="stack">
          <article className="card">
            <div className="card-head">
              <h2>Account</h2>
            </div>
            <ul className="fact-list">
              <li>
                <span>Username</span>
                <b>{me?.username || "—"}</b>
              </li>
              <li>
                <span>Role</span>
                <b>{me?.role || "—"}</b>
              </li>
            </ul>
            <p className="campaign-note">
              <b>This role can</b> {(CAN[me?.role] || []).join(" · ")}
            </p>
          </article>

          <article className="card">
            <div className="card-head">
              <h2>Change password</h2>
            </div>
            <form className="stack-form" onSubmit={changePassword}>
              <label>
                Current password
                <input
                  type="password"
                  autoComplete="current-password"
                  value={current}
                  onChange={(e) => setCurrent(e.target.value)}
                  required
                />
              </label>
              <label>
                New password
                <input
                  type="password"
                  autoComplete="new-password"
                  value={next}
                  onChange={(e) => setNext(e.target.value)}
                  minLength={10}
                  required
                />
              </label>
              <label>
                Repeat new password
                <input
                  type="password"
                  autoComplete="new-password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  minLength={10}
                  required
                />
              </label>
              <small className="hint">
                At least 10 characters. Changing it signs out every other session for this
                account, but not this one.
              </small>
              <button type="submit" className="act primary" disabled={saving}>
                {saving ? "saving…" : "change password"}
              </button>
            </form>
          </article>
        </div>

        <div className="side">
          <article className="card">
            <div className="card-head">
              <h2>Signed in</h2>
              {others ? (
                <button type="button" className="act" onClick={endOthers}>
                  end {others} other
                </button>
              ) : null}
            </div>
            {sessions.length === 0 ? (
              <p className="empty">No active sessions.</p>
            ) : (
              <ul className="session-list">
                {sessions.map((s) => (
                  <li key={`${s.createdAt}-${s.userAgent}`} className={s.current ? "current" : ""}>
                    <div className="policy-top">
                      <span className="grow ellipsis" title={s.userAgent}>
                        {shortAgent(s.userAgent)}
                      </span>
                      {s.current ? <span className="tag good">this browser</span> : null}
                    </div>
                    <small>
                      since {formatTime(s.createdAt)} · expires {formatTime(s.expiresAt)}
                    </small>
                  </li>
                ))}
              </ul>
            )}
          </article>
        </div>
      </section>
    </>
  );
}

/** A user agent string is unreadable; the browser and platform are the useful part. */
function shortAgent(agent) {
  if (!agent) return "Unknown client";
  const browser =
    /Firefox\/[\d.]+/.exec(agent)?.[0] ||
    /Edg\/[\d.]+/.exec(agent)?.[0] ||
    /Chrome\/[\d.]+/.exec(agent)?.[0] ||
    /Safari\/[\d.]+/.exec(agent)?.[0] ||
    agent.slice(0, 28);
  const platform =
    /Macintosh|Windows|Linux|Android|iPhone|iPad/.exec(agent)?.[0] || "";
  return platform ? `${browser} on ${platform}` : browser;
}
