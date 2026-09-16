"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { PageHead } from "@/app/ui/chrome";
import { Metric } from "@/app/ui/parts";
import { useLive } from "@/app/ui/store";

/**
 * The detector library, one row per gateway/internal/signals/*.go file --
 * not the design mockup's 8 rows. The mockup treats "Spray" as an eighth
 * independent detector; the gateway has no such thing (password_spraying
 * is a control-plane campaign classification derived FROM brute-force
 * evidence, never its own signal -- see the note in ui/format.js). Six
 * real detectors, matched to the six config sections Settings already
 * edits, is what's actually here to show. (Seven since object enumeration;
 * the page now counts rather than stating a number.)
 *
 * blockName is the id Settings' "Gateway reflex" checkbox row uses for
 * this detector, when it has one -- only four can arm the reflex to block
 * on their own; the rest (brute-force, route scanning, object enumeration) can
 * only ever raise a signal, a real architectural fact this page shows
 * rather than papering over with a control that would do nothing.
 */
const DETECTORS = [
  {
    signalKeys: ["api_flooding"],
    name: "API flooding",
    rule: "rate limit per source IP, per minute",
    section: "rate_limit",
    scope: "All routes",
    window: "60s",
    threshold: (d) => `${d.rate_limit.requests_per_minute} req/min`,
    blockName: "api_flooding",
  },
  {
    signalKeys: ["sql_injection"],
    name: "SQL injection",
    rule: "signature match in path, query and body",
    section: "attack_detection",
    scope: "Query + body",
    window: "per request",
    threshold: () => "pattern match",
    blockName: "sql_injection",
  },
  {
    signalKeys: ["consecutive_failed_logins"],
    name: "Consecutive failed logins",
    rule: "failed-auth streak per client and login target",
    section: "brute_force",
    scope: "Login routes",
    window: (d) => d.brute_force.window,
    threshold: (d) => `${d.brute_force.max_failures} failures`,
    blockName: null,
  },
  {
    signalKeys: ["unknown_route_scanning"],
    name: "Unknown-route scanning",
    rule: "distinct <unmatched> paths per client",
    section: "unknown_route_scanning",
    scope: "Unmatched routes",
    window: (d) => d.unknown_route_scanning.window,
    threshold: (d) => `${d.unknown_route_scanning.distinct_paths} paths`,
    blockName: null,
  },
  {
    signalKeys: ["object_enumeration"],
    name: "Object ID enumeration (BOLA)",
    rule: "distinct object ids per client, per object template",
    section: "object_enumeration",
    scope: "Object templates",
    window: (d) => d.object_enumeration.window,
    threshold: (d) => `${d.object_enumeration.distinct_ids} ids`,
    blockName: null,
  },
  {
    // The gateway now only ever emits this base id (gateway/internal/signals/
    // collector.go used to also append a more specific attack-type string --
    // path_traversal / enumeration / the compound -- which would have
    // double-counted one match as two here).
    signalKeys: ["enumeration_path_traversal"],
    name: "Path traversal & enumeration",
    rule: "traversal signatures + sequential identifier walk",
    section: "enumeration_path_traversal",
    scope: "All routes",
    window: "per request",
    threshold: () => "pattern match",
    // Must match block.signals' actual vocabulary (api/settings/route.js's
    // KNOWN_SIGNALS) -- the gateway's reflex matches on ev.Signal, which for
    // this detector is always this same base id, never the attack-type
    // string. "path_traversal" here would have been a switch that ticked on
    // and silently blocked nothing.
    blockName: "enumeration_path_traversal",
  },
  {
    signalKeys: ["ip_reputation"],
    name: "Known bad addresses",
    rule: "source on the configured reputation feed",
    section: "ip_reputation",
    scope: "All routes",
    window: "per request",
    threshold: (d) => `score ${d.ip_reputation.score}`,
    blockName: "ip_reputation",
  },
];

export default function SignalsPage() {
  const { stats, policies, learned, setToast } = useLive();

  const [saved, setSaved] = useState(null);
  const [draft, setDraft] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState(false);
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

  function toggleEnabled(section) {
    setDraft((d) => ({ ...d, [section]: { ...d[section], enabled: !d[section].enabled } }));
  }

  function toggleBlock(name) {
    setDraft((d) => {
      const current = d.block.signals || [];
      const next = current.includes(name) ? current.filter((s) => s !== name) : [...current, name];
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
      setConfirming(false);
      setConfirmText("");
      setToast({ tone: "good", text: "sent to the gateway — waiting for it to apply" });
      setTimeout(async () => {
        const now = await load();
        if (!now) return;
        if (JSON.stringify(now) === JSON.stringify(draft)) {
          setToast({ tone: "good", text: "the gateway is enforcing the new settings" });
        } else {
          setToast({
            tone: "bad",
            text: "the gateway did not accept every change — the table now shows what it is enforcing",
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

  // A gateway older than this console may not publish every section.
  const detectors = draft ? DETECTORS.filter((d) => draft[d.section]) : [];
  const enabledCount = detectors.filter((d) => draft[d.section].enabled).length;
  const autoBlockEligible = detectors.filter((d) => d.blockName);
  const autoBlockCount =
    draft?.block.enabled ? autoBlockEligible.filter((d) => (draft.block.signals || []).includes(d.blockName)).length : 0;
  const policyBlocked = policies.filter(
    (p) => p.action === "temp_block" || p.action === "temporary_block",
  ).length;

  const alertsFor = useMemo(
    () => (keys) => keys.reduce((sum, k) => sum + (stats.signals?.[k] || 0), 0),
    [stats.signals],
  );

  if (error) {
    return (
      <>
        <PageHead eyebrow="Detection" title="Signals">
          Every detector the gateway runs, in one table.
        </PageHead>
        <article className="card">
          <p className="empty">{error}</p>
        </article>
      </>
    );
  }

  if (!draft) {
    return (
      <>
        <PageHead eyebrow="Detection" title="Signals">
          Every detector the gateway runs, in one table.
        </PageHead>
        <article className="card">
          <p className="empty">Reading what the gateway is enforcing…</p>
        </article>
      </>
    );
  }

  return (
    <>
      <PageHead
        eyebrow="Detection"
        title="Signals"
        actions={
          <button type="button" className="act primary" disabled={busy || !dirty} onClick={() => setConfirming(true)}>
            Apply changes
          </button>
        }
      >
        {detectors.length} detectors run on every inspected request. Turning one off stops
        it from raising a signal at all. Only {autoBlockEligible.length} of the{" "}
        {detectors.length} can be trusted to block traffic on their own — the rest only
        ever raise a signal for the agent to correlate and the control plane to act on.
      </PageHead>

      <section className="metrics">
        <Metric label="Detectors enabled" value={enabledCount} detail={`of ${detectors.length} detectors`} />
        <Metric
          label="At temp block"
          value={policyBlocked}
          tone={policyBlocked > 0 ? "high" : undefined}
          detail="addresses, right now"
        />
        <Metric label="Trusted to auto-block" value={autoBlockCount} detail={`of ${autoBlockEligible.length} eligible`} />
        <Metric label="Learned corrections" value={learned.length} detail="human overrides applied" />
      </section>

      <article className="card panel-primary">
        <div className="signal-table">
          <div className="signal-row signal-row-head">
            <div>Detector</div>
            <div>Alerts</div>
            <div>Threshold</div>
            <div>Auto-block</div>
            <div>Enabled</div>
          </div>
          {detectors.map((d) => {
            const enabled = draft[d.section].enabled;
            const alerts = alertsFor(d.signalKeys);
            const window = typeof d.window === "function" ? d.window(draft) : d.window;
            const blockOn = d.blockName ? (draft.block.signals || []).includes(d.blockName) : false;
            return (
              <div className={enabled ? "signal-row" : "signal-row off"} key={d.section}>
                <div className="signal-detector">
                  <span className="signal-bar" style={{ background: enabled ? "var(--accent)" : "var(--line-2)" }} />
                  <div>
                    <div className="signal-name">{d.name}</div>
                    <div className="signal-rule mono">{d.rule}</div>
                    <div className="signal-scope">
                      Window {window} · {d.scope}
                    </div>
                  </div>
                </div>
                <div className="signal-alerts mono">{alerts.toLocaleString()}</div>
                <div className="signal-threshold">{d.threshold(draft)}</div>
                <div>
                  {d.blockName ? (
                    <button
                      type="button"
                      role="switch"
                      aria-checked={blockOn}
                      className={blockOn ? "switch on" : "switch"}
                      onClick={() => toggleBlock(d.blockName)}
                      title={
                        blockOn
                          ? "Trusted to block on its own match"
                          : "Raises a signal only -- does not block by itself"
                      }
                    >
                      <span className="knob" />
                    </button>
                  ) : (
                    <span className="faint">not eligible</span>
                  )}
                </div>
                <div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={enabled}
                    className={enabled ? "switch on" : "switch"}
                    onClick={() => toggleEnabled(d.section)}
                  >
                    <span className="knob" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
        <div className="signal-foot">
          <span>Changes apply at the edge within a few seconds of saving.</span>
        </div>
      </article>

      {confirming ? (
        <div className="modal-overlay" onMouseDown={() => !busy && setConfirming(false)}>
          <div className="modal-card" onMouseDown={(e) => e.stopPropagation()}>
            <h2>Apply these settings?</h2>
            <p>
              This changes what the running gateway detects and blocks, within a few
              seconds and without a restart.
            </p>
            <p className="modal-note">
              Blocks already in force keep running either way; they expire on their own.
            </p>
            <label className="modal-label">
              Type <b>apply</b> to confirm
              <input
                type="text"
                value={confirmText}
                autoFocus
                disabled={busy}
                onChange={(e) => setConfirmText(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && confirmText === "apply" && !busy) apply();
                }}
                placeholder="apply"
              />
            </label>
            <div className="modal-actions">
              <button type="button" className="act" onClick={() => setConfirming(false)} disabled={busy}>
                Cancel
              </button>
              <button
                type="button"
                className="act danger"
                disabled={busy || confirmText !== "apply"}
                onClick={apply}
              >
                {busy ? "Applying…" : "Apply"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
