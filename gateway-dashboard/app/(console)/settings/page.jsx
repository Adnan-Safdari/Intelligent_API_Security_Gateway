"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHead, ResetControl } from "@/app/ui/chrome";
import { useLive } from "@/app/ui/store";

/**
 * Live enforcement settings.
 *
 * The form is built from what the gateway says it is enforcing, never from what
 * this page last sent. After saving it re-reads, so a change the gateway refused
 * shows as refused instead of appearing to have worked.
 */

const SIGNALS = [
  { name: "api_flooding", label: "API flooding" },
  { name: "sql_injection", label: "SQL injection" },
  { name: "path_traversal", label: "Path traversal" },
  { name: "ip_reputation", label: "Known bad address" },
];

export default function SettingsPage() {
  const { setToast } = useLive();

  const [saved, setSaved] = useState(null); // what the gateway reports
  const [draft, setDraft] = useState(null); // what the form holds
  const [source, setSource] = useState("file");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState(null); // "apply" | "revert" | null
  const [confirmText, setConfirmText] = useState("");

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/settings");
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setError(data.error || `could not read settings (${res.status})`);
        return null;
      }
      setError(null);
      setSaved(data.settings);
      setSource(data.source);
      return data.settings;
    } catch (err) {
      setError(`could not reach the server: ${err.message}`);
      return null;
    }
  }, []);

  useEffect(() => {
    load().then((s) => s && setDraft(structuredClone(s)));
  }, [load]);

  const dirty = draft && saved && JSON.stringify(draft) !== JSON.stringify(saved);

  function edit(section, key, value) {
    setDraft((d) => ({ ...d, [section]: { ...d[section], [key]: value } }));
  }

  function toggleSignal(name) {
    setDraft((d) => {
      const current = d.block.signals || [];
      const next = current.includes(name)
        ? current.filter((s) => s !== name)
        : [...current, name];
      return { ...d, block: { ...d.block, signals: next } };
    });
  }

  async function apply() {
    setBusy(true);
    try {
      const res = await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirm: "apply", settings: draft }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setToast({ tone: "bad", text: data.error || `save failed (${res.status})` });
        return;
      }
      close();
      // The gateway applies on its own schedule and may refuse. Wait a beat,
      // then show what it actually ended up enforcing.
      setToast({ tone: "good", text: "sent to the gateway — waiting for it to apply" });
      setTimeout(async () => {
        const now = await load();
        if (!now) return;
        if (JSON.stringify(now) === JSON.stringify(draft)) {
          setToast({ tone: "good", text: "the gateway is enforcing the new settings" });
        } else {
          setToast({
            tone: "bad",
            text: "the gateway did not accept every change — the form now shows what it is enforcing",
          });
          setDraft(structuredClone(now));
        }
      }, 6000);
    } catch (err) {
      setToast({ tone: "bad", text: `could not reach the server: ${err.message}` });
    } finally {
      setBusy(false);
    }
  }

  async function revert() {
    setBusy(true);
    try {
      const res = await fetch("/api/settings", { method: "DELETE" });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setToast({ tone: "bad", text: data.error || `revert failed (${res.status})` });
        return;
      }
      close();
      setToast({ tone: "good", text: "override removed — waiting for the gateway" });
      setTimeout(async () => {
        const now = await load();
        if (now) setDraft(structuredClone(now));
      }, 6000);
    } catch (err) {
      setToast({ tone: "bad", text: `could not reach the server: ${err.message}` });
    } finally {
      setBusy(false);
    }
  }

  function close() {
    setConfirming(null);
    setConfirmText("");
  }

  if (error) {
    return (
      <>
        <PageHead title="Settings">
          The enforcement settings the gateway is running right now.
        </PageHead>
        <section className="workbench">
          <article className="card">
            <p className="empty">{error}</p>
          </article>
        </section>
      </>
    );
  }

  if (!draft) {
    return (
      <>
        <PageHead title="Settings">
          The enforcement settings the gateway is running right now.
        </PageHead>
        <section className="workbench">
          <article className="card">
            <p className="empty">Reading what the gateway is enforcing…</p>
          </article>
        </section>
      </>
    );
  }

  return (
    <>
      <PageHead title="Settings">
        What the gateway is enforcing right now. Changes apply within a few seconds
        without a restart — the config file stays the source of truth at boot, and{" "}
        <b>Revert</b> returns to exactly what it booted with. Listen address, backend
        and timeouts are not here: changing those means restarting the gateway.
      </PageHead>

      <div className="settings-bar">
        <ResetControl className="settings-reset" />
        <span className={source === "console" ? "pill on" : "pill"}>
          {source === "console" ? "Running a console override" : "Running the config file"}
        </span>
        <span className="grow" />
        {dirty ? <em className="unsaved">unsaved changes</em> : null}
        <button
          type="button"
          className="act"
          disabled={busy || source !== "console"}
          onClick={() => setConfirming("revert")}
          title="Return the gateway to the settings in its config file"
        >
          Revert to file
        </button>
        <button
          type="button"
          className="act primary"
          disabled={busy || !dirty}
          onClick={() => setConfirming("apply")}
        >
          Apply changes
        </button>
      </div>

      <section className="workbench settings-grid">
        <Card
          title="API flooding"
          note="Counts requests per IP in a one-minute window."
        >
          <Toggle
            label="Detector on"
            checked={draft.rate_limit.enabled}
            onChange={(v) => edit("rate_limit", "enabled", v)}
          />
          <Num
            label="Requests per minute"
            value={draft.rate_limit.requests_per_minute}
            min={1}
            onChange={(v) => edit("rate_limit", "requests_per_minute", v)}
            hint="The count that has to be exceeded before the signal fires."
          />
          <Toggle
            label="Refuse traffic over this rate"
            checked={draft.rate_limit.enforce}
            onChange={(v) => edit("rate_limit", "enforce", v)}
          />
          <small className="field-note">
            Off, the count above only raises a signal. On, it becomes a limit every
            address is held to and anything over it gets a 429. An address the agent has
            throttled is held to <b>its</b> rate instead; the ranges under “Never block
            these” skip the limit entirely.
          </small>
        </Card>

        <Card title="SQL injection" note="Matches signatures in the path, query and body.">
          <Toggle
            label="Detector on"
            checked={draft.attack_detection.enabled}
            onChange={(v) => edit("attack_detection", "enabled", v)}
          />
          <List
            label="Signatures"
            value={draft.attack_detection.sql_patterns || []}
            onChange={(v) => edit("attack_detection", "sql_patterns", v)}
            hint="One per line. Matched case-insensitively. Empty falls back to the built-in list."
          />
        </Card>

        <Card title="Consecutive failed logins" note="Counts configured backend invalid-credential outcomes per client and login target. Login routes and status meanings are structural settings in config.yaml.">
          <Toggle
            label="Detector on"
            checked={draft.brute_force.enabled}
            onChange={(v) => edit("brute_force", "enabled", v)}
          />
          <Num
            label="Consecutive failures"
            value={draft.brute_force.max_failures}
            min={1}
            onChange={(v) => edit("brute_force", "max_failures", v)}
          />
          <Text
            label="Window"
            value={draft.brute_force.window}
            onChange={(v) => edit("brute_force", "window", v)}
            hint='A gap longer than this starts a new streak, like "60s" or "5m".'
          />
        </Card>

        <Card title="Unknown-route scanning" note="Counts distinct raw paths classified as &lt;unmatched&gt; by the configured route table. Backend 404s on known routes and repeated dead links do not count.">
          <Toggle
            label="Detector on"
            checked={draft.unknown_route_scanning.enabled}
            onChange={(v) => edit("unknown_route_scanning", "enabled", v)}
          />
          <Num
            label="Distinct paths"
            value={draft.unknown_route_scanning.distinct_paths}
            min={2}
            onChange={(v) => edit("unknown_route_scanning", "distinct_paths", v)}
          />
          <Text
            label="Window"
            value={draft.unknown_route_scanning.window}
            onChange={(v) => edit("unknown_route_scanning", "window", v)}
            hint='How long distinct unmatched paths remain associated, like "5m".'
          />
          <Num
            label="Maximum clients"
            value={draft.unknown_route_scanning.max_clients}
            min={1}
            max={100000}
            onChange={(v) => edit("unknown_route_scanning", "max_clients", v)}
          />
          <Num
            label="Maximum paths per client"
            value={draft.unknown_route_scanning.max_paths_per_client}
            min={2}
            max={10000}
            onChange={(v) => edit("unknown_route_scanning", "max_paths_per_client", v)}
          />
        </Card>

        <Card
          title="Path traversal and enumeration"
          note="Matches traversal signatures in the path and query, and known-sensitive paths."
        >
          <Toggle
            label="Detector on"
            checked={draft.enumeration_path_traversal.enabled}
            onChange={(v) => edit("enumeration_path_traversal", "enabled", v)}
          />
          <List
            label="Traversal signatures"
            value={draft.enumeration_path_traversal.traversal_patterns || []}
            onChange={(v) => edit("enumeration_path_traversal", "traversal_patterns", v)}
          />
          <List
            label="Enumeration paths"
            value={draft.enumeration_path_traversal.enumeration_patterns || []}
            onChange={(v) => edit("enumeration_path_traversal", "enumeration_patterns", v)}
          />
        </Card>

        <Card
          title="Known bad addresses"
          note="The only detector that answers on a first request: it knows the address rather than watching what it does. The feed itself is set in config.yaml — what moves here is whether it counts and how loudly."
        >
          <Toggle
            label="Detector on"
            checked={draft.ip_reputation.enabled}
            onChange={(v) => edit("ip_reputation", "enabled", v)}
          />
          <Num
            label="Score a listed address carries"
            value={draft.ip_reputation.score}
            min={0}
            max={100}
            onChange={(v) => edit("ip_reputation", "score", v)}
          />
          <Text
            label="Quiet period after firing"
            value={draft.ip_reputation.cooldown}
            onChange={(v) => edit("ip_reputation", "cooldown", v)}
            hint='A listed address is listed on every request. This is how long it stays quiet after raising a signal, like "5m".'
          />
        </Card>

        <Card
          title="Gateway reflex"
          note="The gateway's own blocking, decided per request in nanoseconds. Naming detectors is what arms it — on with nothing named blocks nothing."
          wide
        >
          <Toggle
            label="Blocking on"
            checked={draft.block.enabled}
            onChange={(v) => edit("block", "enabled", v)}
          />

          <div className="field">
            <span className="field-label">Block on these detectors</span>
            <div className="checkrow">
              {SIGNALS.map((s) => (
                <label key={s.name} className="check">
                  <input
                    type="checkbox"
                    checked={(draft.block.signals || []).includes(s.name)}
                    onChange={() => toggleSignal(s.name)}
                  />
                  {s.label}
                </label>
              ))}
            </div>
            <small>
              Only these are trusted to block on their own. With none ticked the reflex
              is armed but silent.
            </small>
          </div>

          <Num
            label="Minimum score"
            value={draft.block.min_score}
            min={0}
            max={100}
            onChange={(v) => edit("block", "min_score", v)}
            hint="A floor on top of the detector's own threshold, 0–100. Raise it to make blocking less trigger-happy."
          />
          <Text
            label="Block duration"
            value={draft.block.duration}
            onChange={(v) => edit("block", "duration", v)}
            hint='How long a block lasts, like "60s". Blocks already running keep the deadline they were given.'
          />
          <List
            label="Never block these"
            value={draft.block.exempt_cidrs || []}
            onChange={(v) => edit("block", "exempt_cidrs", v)}
            hint="Addresses or CIDR ranges, one per line. An empty list exempts nobody."
          />
        </Card>

        <Card
          title="Control plane decisions"
          note="Whether the policy keys the agent writes are enforced on live traffic."
        >
          <Toggle
            label="Enforce agent decisions"
            checked={draft.policy.enabled}
            onChange={(v) => edit("policy", "enabled", v)}
          />
          <Toggle
            label="Throttling on"
            checked={draft.throttle.enabled}
            onChange={(v) => edit("throttle", "enabled", v)}
          />
          <Num
            label="Throttle delay (ms)"
            value={draft.throttle.delay_ms}
            min={0}
            onChange={(v) => edit("throttle", "delay_ms", v)}
            hint="How long a throttled caller is held before being served."
          />
        </Card>
      </section>

      {confirming ? (
        <div className="modal-overlay" onMouseDown={() => !busy && close()}>
          <div className="modal-card" onMouseDown={(e) => e.stopPropagation()}>
            <h2>{confirming === "apply" ? "Apply these settings?" : "Revert to the config file?"}</h2>
            <p>
              {confirming === "apply"
                ? "This changes what the running gateway detects and blocks, within a few seconds and without a restart."
                : "The gateway returns to the settings it booted with. Anything changed here is discarded."}
            </p>
            <p className="modal-note">
              Blocks already in force keep running either way; they expire on their own.
            </p>
            <label className="modal-label">
              Type <b>{confirming === "apply" ? "apply" : "revert"}</b> to confirm
              <input
                type="text"
                value={confirmText}
                autoFocus
                disabled={busy}
                onChange={(e) => setConfirmText(e.target.value)}
                placeholder={confirming}
              />
            </label>
            <div className="modal-actions">
              <button type="button" className="act" onClick={close} disabled={busy}>
                Cancel
              </button>
              <button
                type="button"
                className="act danger"
                disabled={busy || confirmText !== confirming}
                onClick={confirming === "apply" ? apply : revert}
              >
                {busy ? "Working…" : confirming === "apply" ? "Apply" : "Revert"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}

function Card({ title, note, children, wide }) {
  return (
    <article className={wide ? "card settings-card wide" : "card settings-card"}>
      <div className="card-head">
        <h2>{title}</h2>
      </div>
      {note ? <p className="card-note">{note}</p> : null}
      <div className="settings-fields">{children}</div>
    </article>
  );
}

function Toggle({ label, checked, onChange }) {
  return (
    <label className="check toggle">
      <input type="checkbox" checked={Boolean(checked)} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  );
}

function Num({ label, value, onChange, min, max, hint }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      <input
        type="number"
        value={value ?? ""}
        min={min}
        max={max}
        onChange={(e) => onChange(e.target.value === "" ? "" : Number(e.target.value))}
      />
      {hint ? <small>{hint}</small> : null}
    </label>
  );
}

function Text({ label, value, onChange, hint }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      <input type="text" value={value ?? ""} onChange={(e) => onChange(e.target.value)} />
      {hint ? <small>{hint}</small> : null}
    </label>
  );
}

// Lists are edited as lines rather than as chips: these are patterns and CIDRs
// that get pasted in from somewhere else, and a textarea takes a paste whole.
function List({ label, value, onChange, hint }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      <textarea
        rows={Math.min(Math.max(value.length + 1, 3), 10)}
        value={value.join("\n")}
        onChange={(e) =>
          onChange(
            e.target.value
              .split("\n")
              .map((line) => line.trim())
              .filter(Boolean),
          )
        }
      />
      {hint ? <small>{hint}</small> : null}
    </label>
  );
}
