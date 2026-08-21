"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHead } from "@/app/ui/chrome";
import { formatTime } from "@/app/ui/format";
import { useLive } from "@/app/ui/store";

const ROLES = ["viewer", "operator", "admin"];

const WHAT_EACH_ROLE_CAN_DO = {
  viewer: "read everything, change nothing",
  operator: "instruct the agent, but not manage accounts",
  admin: "everything, including these accounts",
};

export default function UsersPage() {
  const { me, setToast } = useLive();
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [form, setForm] = useState({ username: "", password: "", role: "operator" });

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/users", { cache: "no-store" });
      const json = await res.json();
      if (!json.ok) {
        setError(json.error || "could not load accounts");
        return;
      }
      setUsers(json.users);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function send(url, options, label) {
    setBusy(label);
    try {
      const res = await fetch(url, {
        headers: { "Content-Type": "application/json" },
        ...options,
      });
      const json = await res.json();
      if (!json.ok) {
        setToast({ tone: "bad", text: json.error || "that did not work" });
        return false;
      }
      await load();
      return true;
    } catch (err) {
      setToast({ tone: "bad", text: err.message });
      return false;
    } finally {
      setBusy("");
    }
  }

  async function create(e) {
    e.preventDefault();
    const ok = await send(
      "/api/users",
      { method: "POST", body: JSON.stringify(form) },
      "create",
    );
    if (ok) {
      setToast({ tone: "good", text: `${form.username} can now sign in` });
      setForm({ username: "", password: "", role: "operator" });
    }
  }

  if (me.role !== "admin") {
    return (
      <>
        <PageHead title="Users">Accounts and what each of them may do.</PageHead>
        <article className="card">
          <p className="empty">
            Managing accounts needs the admin role. You are signed in as{" "}
            <b>{me.username}</b> ({me.role}).
          </p>
        </article>
      </>
    );
  }

  return (
    <>
      <PageHead title="Users">
        Who can reach this console and what they may do with it. Roles are checked on the
        server for every action — hiding a button is presentation, not authorisation.
      </PageHead>

      <section className="workbench">
        <article className="card">
          <div className="card-head">
            <h2>Accounts</h2>
            <span className="count">{users.length}</span>
          </div>

          {error ? <p className="empty">{error}</p> : null}

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Role</th>
                  <th>Sessions</th>
                  <th>Last sign-in</th>
                  <th>State</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className={u.disabled ? "dim" : ""}>
                    <td>
                      <b>{u.username}</b>
                      {u.id === me.id ? <span className="tag"> you</span> : null}
                    </td>
                    <td>
                      <select
                        value={u.role}
                        disabled={Boolean(busy)}
                        onChange={(e) =>
                          send(
                            `/api/users/${u.id}`,
                            {
                              method: "PATCH",
                              body: JSON.stringify({ role: e.target.value }),
                            },
                            `role-${u.id}`,
                          )
                        }
                      >
                        {ROLES.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="mono">{u.sessions}</td>
                    <td className="mono">
                      {u.lastLoginAt ? formatTime(u.lastLoginAt) : "never"}
                    </td>
                    <td>
                      <span className={u.disabled ? "tag" : "tag good"}>
                        {u.disabled ? "disabled" : "active"}
                      </span>
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          type="button"
                          className="act small"
                          disabled={Boolean(busy)}
                          onClick={() =>
                            send(
                              `/api/users/${u.id}`,
                              {
                                method: "PATCH",
                                body: JSON.stringify({ disabled: !u.disabled }),
                              },
                              `toggle-${u.id}`,
                            )
                          }
                        >
                          {u.disabled ? "enable" : "disable"}
                        </button>
                        <button
                          type="button"
                          className="act small"
                          disabled={Boolean(busy) || u.id === me.id}
                          title={
                            u.id === me.id
                              ? "You cannot delete your own account"
                              : `Delete ${u.username}`
                          }
                          onClick={() => {
                            if (!confirm(`Delete ${u.username}? This cannot be undone.`)) return;
                            send(`/api/users/${u.id}`, { method: "DELETE" }, `del-${u.id}`);
                          }}
                        >
                          delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>

        <div className="side">
          <article className="card">
            <div className="card-head">
              <h2>Add a user</h2>
            </div>
            <form className="form" onSubmit={create}>
              <label className="field block">
                Username
                <input
                  type="text"
                  value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  placeholder="3-32 characters: a-z 0-9 . _ -"
                  autoComplete="off"
                  required
                />
              </label>

              <label className="field block">
                Password
                <input
                  type="password"
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  placeholder="at least 10 characters"
                  autoComplete="new-password"
                  required
                />
              </label>

              <label className="field block">
                Role
                <select
                  value={form.role}
                  onChange={(e) => setForm({ ...form, role: e.target.value })}
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </label>

              <p className="form-note">{WHAT_EACH_ROLE_CAN_DO[form.role]}</p>

              <button type="submit" className="act primary" disabled={Boolean(busy)}>
                {busy === "create" ? "Creating…" : "Create account"}
              </button>
            </form>
          </article>

          <article className="card">
            <div className="card-head">
              <h2>What the roles mean</h2>
            </div>
            <ul className="policy-list">
              {ROLES.map((r) => (
                <li key={r}>
                  <div className="policy-top">
                    <b>{r}</b>
                  </div>
                  <small>{WHAT_EACH_ROLE_CAN_DO[r]}</small>
                </li>
              ))}
            </ul>
          </article>

          <ResetRecord setToast={setToast} />
        </div>
      </section>
    </>
  );
}

/**
 * Throw away the durable record.
 *
 * Deliberately narrow, and the narrowness is the feature: campaigns and the
 * agent's learned feedback go, accounts and live telemetry stay. Wiping the
 * accounts would sign everyone out and drop the console back to /setup, which
 * is a different operation with a different command behind it.
 *
 * Typing the word is the confirmation. A modal that only needs a second click
 * is one mis-click away from the same accident.
 */
function ResetRecord({ setToast }) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);

  async function reset(event) {
    event.preventDefault();
    setBusy(true);
    try {
      const res = await fetch("/api/admin/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirm: typed }),
      });
      const data = await res.json();
      if (!data.ok) {
        setToast({ tone: "bad", text: data.error });
        return;
      }
      const cleared = Object.entries(data.cleared || {})
        .map(([table, n]) => `${n} ${table}`)
        .join(", ");
      setToast({ tone: "good", text: `record cleared — removed ${cleared}` });
      setTyped("");
    } catch (err) {
      setToast({ tone: "bad", text: err.message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <article className="card danger-zone">
      <div className="card-head">
        <h2>Reset the record</h2>
      </div>
      <p className="form-note">
        Deletes every campaign and everything the agent has learned from being overruled,
        and restarts campaign numbering at #1. Useful before a demo.
      </p>
      <p className="form-note">
        <b>Keeps</b> these accounts, and all live telemetry and policy in Redis — policy
        expires by itself, and deleting it from under the gateway would be enforcement by
        another name.
      </p>
      <form className="stack-form" onSubmit={reset}>
        <label>
          {/* One flex item, not three: .stack-form label is a column, so bare
              text either side of the <code> would each become their own row. */}
          <span>
            Type <code>reset</code> to confirm
          </span>
          <input
            type="text"
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder="reset"
            autoComplete="off"
          />
        </label>
        <button type="submit" className="act danger" disabled={busy || typed !== "reset"}>
          {busy ? "clearing…" : "clear campaigns and feedback"}
        </button>
      </form>
    </article>
  );
}
