"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { PageHead } from "@/app/ui/chrome";
import { actionLabel, formatTime, formatTtl } from "@/app/ui/format";
import { Field } from "@/app/ui/parts";

const MODES = ["monitor", "manual", "automatic"];
const ACTIONS = ["monitor", "throttle", "temp_block"];

export default function AdaptivePage() {
  const [data, setData] = useState({
    baselines: [],
    recommendations: [],
    audit: [],
    activePolicies: [],
  });
  const [draft, setDraft] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [override, setOverride] = useState({
    target_identity: "",
    action: "temp_block",
    duration_seconds: 900,
    reason: "",
  });

  const load = useCallback(async () => {
    const response = await fetch("/api/adaptive", { cache: "no-store" });
    const value = await response.json();
    setData(value);
    if (value.config) setDraft((current) => current || structuredClone(value.config));
    setError(value.available ? "" : value.error || "adaptive store unavailable");
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, [load]);

  const pending = useMemo(
    () => data.recommendations?.filter((row) => row.status === "pending_approval") || [],
    [data.recommendations],
  );

  async function saveConfig() {
    setBusy("settings");
    const response = await fetch("/api/adaptive/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(draft),
    });
    const value = await response.json();
    setBusy("");
    if (!response.ok) return setError(value.error || "settings rejected");
    setDraft(structuredClone(value.config));
    await load();
  }

  async function decide(row, decision) {
    const action = document.getElementById(`action-${row.policyId}`)?.value || row.action;
    const rpm = Number(
      document.getElementById(`rpm-${row.policyId}`)?.value || row.requestsPerMinute || 0,
    );
    const duration = Number(document.getElementById(`duration-${row.policyId}`)?.value || 900);
    setBusy(row.policyId);
    const response = await fetch(`/api/adaptive/recommendations/${encodeURIComponent(row.policyId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        decision,
        edits:
          decision === "approve"
            ? {
                action,
                requests_per_minute: action === "throttle" ? rpm : 0,
                duration_seconds: duration,
              }
            : {},
      }),
    });
    const value = await response.json();
    setBusy("");
    if (!response.ok) return setError(value.error || "decision rejected");
    await load();
  }

  async function sendOverride(event) {
    event.preventDefault();
    setBusy("override");
    const response = await fetch("/api/adaptive/overrides", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(override),
    });
    const value = await response.json();
    setBusy("");
    if (!response.ok) return setError(value.error || "override rejected");
    setOverride((row) => ({ ...row, target_identity: "", reason: "" }));
    await load();
  }

  function edit(section, name, value) {
    setDraft((current) => ({ ...current, [section]: { ...current[section], [name]: value } }));
  }

  return (
    <>
      <PageHead title="Adaptive enforcement">
        Endpoint-specific baselines, analyst-controlled recommendations, and the durable
        reason behind every action. An anomaly score is advisory; policy confidence comes
        from gateway evidence and campaign correlation.
      </PageHead>

      {error ? <p className="notice bad">{error}</p> : null}

      {draft ? (
        <section className="card adaptive-settings">
          <div className="card-head">
            <h2>Operating mode and guardrails</h2>
            <span>configuration v{draft.version}</span>
          </div>

          <div className="mode-grid">
            {MODES.map((mode) => (
              <button
                key={mode}
                type="button"
                className={`act ${draft.mode === mode ? "on" : ""}`}
                onClick={() => setDraft({ ...draft, mode })}
              >
                {mode}
              </button>
            ))}
          </div>

          <div className="guardrail-grid">
            <Field.Select
              label="Maximum automatic action"
              value={draft.guardrails.maximum_automatic_action}
              options={ACTIONS}
              onChange={(value) => edit("guardrails", "maximum_automatic_action", value)}
              optionLabel={actionLabel}
            />
            <Field.Number
              label="Throttle confidence"
              step="0.01"
              value={draft.guardrails.minimum_confidence_throttle}
              onChange={(value) => edit("guardrails", "minimum_confidence_throttle", Number(value))}
            />
            <Field.Number
              label="Block confidence"
              step="0.01"
              value={draft.guardrails.minimum_confidence_temporary_block}
              onChange={(value) => edit("guardrails", "minimum_confidence_temporary_block", Number(value))}
            />
            <Field.Number
              label="Maximum duration (seconds)"
              value={draft.guardrails.maximum_policy_duration_seconds}
              onChange={(value) => edit("guardrails", "maximum_policy_duration_seconds", Number(value))}
            />
            <Field.Number
              label="Monitor duration"
              value={draft.guardrails.monitor_duration_seconds}
              onChange={(value) => edit("guardrails", "monitor_duration_seconds", Number(value))}
            />
            <Field.Number
              label="Throttle duration"
              value={draft.guardrails.throttle_duration_seconds}
              onChange={(value) => edit("guardrails", "throttle_duration_seconds", Number(value))}
            />
            <Field.Number
              label="Temporary-block duration"
              value={draft.guardrails.temporary_block_duration_seconds}
              onChange={(value) => edit("guardrails", "temporary_block_duration_seconds", Number(value))}
            />
            <Field.Number
              label="Minimum throttle RPM"
              value={draft.guardrails.minimum_throttle_rpm}
              onChange={(value) => edit("guardrails", "minimum_throttle_rpm", Number(value))}
            />
            <Field.Number
              label="Default throttle RPM"
              value={draft.guardrails.default_throttle_rpm}
              onChange={(value) => edit("guardrails", "default_throttle_rpm", Number(value))}
            />
            <Field.Number
              label="Maximum throttle RPM"
              value={draft.guardrails.maximum_throttle_rpm}
              onChange={(value) => edit("guardrails", "maximum_throttle_rpm", Number(value))}
            />
            <Field.Number
              label="Throttle baseline fraction"
              step="0.01"
              value={draft.guardrails.throttle_baseline_fraction}
              onChange={(value) => edit("guardrails", "throttle_baseline_fraction", Number(value))}
            />
            <Field.Number
              label="Policy cooldown (seconds)"
              value={draft.guardrails.policy_cooldown_seconds}
              onChange={(value) => edit("guardrails", "policy_cooldown_seconds", Number(value))}
            />
            <Field.Number
              label="Evidence required: throttle"
              value={draft.guardrails.minimum_deterministic_evidence_throttle}
              onChange={(value) => edit("guardrails", "minimum_deterministic_evidence_throttle", Number(value))}
            />
            <Field.Number
              label="Evidence required: block"
              value={draft.guardrails.minimum_deterministic_evidence_temporary_block}
              onChange={(value) => edit("guardrails", "minimum_deterministic_evidence_temporary_block", Number(value))}
            />
            <Field.Number
              label="Strong ML anomaly"
              step="0.01"
              value={draft.guardrails.strong_ml_anomaly}
              onChange={(value) => edit("guardrails", "strong_ml_anomaly", Number(value))}
            />
            <Field.Number
              label="Baseline warm-up windows"
              value={draft.baseline.warmup_windows}
              onChange={(value) => edit("baseline", "warmup_windows", Number(value))}
            />
            <Field.Number
              label="Baseline rolling windows"
              value={draft.baseline.rolling_windows}
              onChange={(value) => edit("baseline", "rolling_windows", Number(value))}
            />
            <Field.Number
              label="Baseline MAD multiplier"
              step="0.1"
              value={draft.baseline.mad_multiplier}
              onChange={(value) => edit("baseline", "mad_multiplier", Number(value))}
            />
            <Field.Number
              label="Baseline minimum MAD"
              step="0.1"
              value={draft.baseline.minimum_mad}
              onChange={(value) => edit("baseline", "minimum_mad", Number(value))}
            />
            <Field.Number
              label="Minimum learned RPM"
              value={draft.baseline.minimum_threshold_rpm}
              onChange={(value) => edit("baseline", "minimum_threshold_rpm", Number(value))}
            />
            <Field.Number
              label="Maximum learned RPM"
              value={draft.baseline.maximum_threshold_rpm}
              onChange={(value) => edit("baseline", "maximum_threshold_rpm", Number(value))}
            />
            <Field.Number
              label="Baseline hysteresis"
              step="0.01"
              value={draft.baseline.hysteresis_ratio}
              onChange={(value) => edit("baseline", "hysteresis_ratio", Number(value))}
            />
            <Field.Number
              label="Threshold cooldown"
              value={draft.baseline.cooldown_seconds}
              onChange={(value) => edit("baseline", "cooldown_seconds", Number(value))}
            />
            <Field.Number
              label="Deterministic risk weight"
              step="0.01"
              value={draft.risk.deterministic_weight}
              onChange={(value) => edit("risk", "deterministic_weight", Number(value))}
            />
            <Field.Number
              label="Behavioural risk weight"
              step="0.01"
              value={draft.risk.behavioural_weight}
              onChange={(value) => edit("risk", "behavioural_weight", Number(value))}
            />
            <Field.Number
              label="Campaign risk weight"
              step="0.01"
              value={draft.risk.campaign_weight}
              onChange={(value) => edit("risk", "campaign_weight", Number(value))}
            />
            <Field.Number
              label="ML advisory weight"
              step="0.01"
              value={draft.risk.ml_weight}
              onChange={(value) => edit("risk", "ml_weight", Number(value))}
            />
            <Field.Number
              label="Throttle risk score"
              step="0.1"
              value={draft.risk.throttle_score}
              onChange={(value) => edit("risk", "throttle_score", Number(value))}
            />
            <Field.Number
              label="Block risk score"
              step="0.1"
              value={draft.risk.temporary_block_score}
              onChange={(value) => edit("risk", "temporary_block_score", Number(value))}
            />
            <Field.Textarea
              label="Emergency allowlist (address/CIDR per line)"
              value={draft.guardrails.allowlist.join("\n")}
              onChange={(value) => edit("guardrails", "allowlist", splitRanges(value))}
            />
            <Field.Textarea
              label="Emergency blocklist (address/CIDR per line)"
              value={draft.guardrails.blocklist.join("\n")}
              onChange={(value) => edit("guardrails", "blocklist", splitRanges(value))}
            />
          </div>

          <button className="act primary" type="button" disabled={Boolean(busy)} onClick={saveConfig}>
            {busy === "settings" ? "Saving…" : "Save validated settings"}
          </button>
        </section>
      ) : null}

      <section className="card">
        <div className="card-head">
          <h2>Endpoint baselines</h2>
          <span>{data.baselines?.length || 0} normalized endpoints</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Endpoint</th>
                <th>State</th>
                <th>Samples</th>
                <th>Observed RPM</th>
                <th>Median</th>
                <th>MAD</th>
                <th>Threshold</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {data.baselines?.length ? (
                data.baselines.map((row) => (
                  <tr key={`${row.method} ${row.routeTemplate}`}>
                    <td>
                      <span className="method">{row.method}</span> {row.routeTemplate}
                    </td>
                    <td>
                      <span className={`tag ${row.ready ? "good" : ""}`}>
                        {row.ready ? "ready" : "warming up"}
                      </span>
                    </td>
                    <td>{row.sampleCount}</td>
                    <td>{row.observedRate}</td>
                    <td>{row.statistic.toFixed(1)}</td>
                    <td>{row.mad.toFixed(1)}</td>
                    <td>{row.threshold}</td>
                    <td>{formatTime(row.lastUpdate)}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="8" className="empty">
                    No completed trusted windows yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Pending recommendation queue</h2>
          <span>{pending.length}</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Target / scope</th>
                <th>Risk</th>
                <th>Policy confidence</th>
                <th>Action</th>
                <th>RPM</th>
                <th>Duration</th>
                <th>Decision</th>
              </tr>
            </thead>
            <tbody>
              {pending.length ? (
                pending.map((row) => (
                  <tr key={row.policyId}>
                    <td className="mono">
                      {row.targetIdentity}
                      <small className="scope-line">
                        {row.method} {row.routeTemplate}
                      </small>
                      <DecisionExplanation value={row.explanation} />
                    </td>
                    <td>{row.riskScore.toFixed(1)}</td>
                    <td>{row.confidence.toFixed(3)}</td>
                    <td>
                      <select id={`action-${row.policyId}`} defaultValue={row.action}>
                        {ACTIONS.map((action) => (
                          <option key={action} value={action}>
                            {actionLabel(action)}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <input
                        id={`rpm-${row.policyId}`}
                        type="number"
                        defaultValue={row.requestsPerMinute || draft?.guardrails.default_throttle_rpm || 60}
                      />
                    </td>
                    <td>
                      <input
                        id={`duration-${row.policyId}`}
                        type="number"
                        defaultValue={draft?.guardrails.throttle_duration_seconds || 900}
                      />
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="act small"
                          disabled={Boolean(busy)}
                          onClick={() => decide(row, "approve")}
                        >
                          Approve / edit
                        </button>
                        <button
                          className="act danger small"
                          disabled={Boolean(busy)}
                          onClick={() => decide(row, "reject")}
                        >
                          Reject
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="7" className="empty">
                    No recommendations await approval.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="workbench">
        <article className="card">
          <div className="card-head">
            <h2>Active policies</h2>
            <span>{data.activePolicies?.length || 0}</span>
          </div>
          <ul className="decision-list">
            {data.activePolicies?.map((row) => (
              <li key={row.policyId}>
                <div>
                  <b>{row.ip}</b> <span className="tag">{actionLabel(row.action)}</span>{" "}
                  <small>
                    {formatTtl(row.expiresIn)} · {row.method} {row.routeTemplate}
                  </small>
                </div>
                <DecisionExplanation value={row.explanation} />
              </li>
            ))}
          </ul>
        </article>

        <div className="side">
          <article className="card">
            <div className="card-head">
              <h2>Emergency override</h2>
              <span>manual precedence</span>
            </div>
            <form className="form" onSubmit={sendOverride}>
              <Field.Text
                label="Client IP"
                value={override.target_identity}
                onChange={(value) => setOverride({ ...override, target_identity: value })}
              />
              <Field.Select
                label="Action"
                value={override.action}
                options={["allow", "temp_block"]}
                onChange={(value) => setOverride({ ...override, action: value })}
                optionLabel={actionLabel}
              />
              <Field.Number
                label="Duration seconds"
                value={override.duration_seconds}
                onChange={(value) => setOverride({ ...override, duration_seconds: Number(value) })}
              />
              <Field.Text
                label="Reason"
                value={override.reason}
                onChange={(value) => setOverride({ ...override, reason: value })}
              />
              <button className="act primary" disabled={Boolean(busy) || !override.target_identity}>
                Queue override
              </button>
            </form>
          </article>

          <article className="card">
            <div className="card-head">
              <h2>Audit timeline</h2>
              <span>durable</span>
            </div>
            <ul className="audit-list">
              {data.audit?.map((row) => (
                <li key={row.auditId}>
                  <b>{row.event}</b> · {row.policyId}
                  <small>
                    {row.actor} · {formatTime(row.createdAt)}
                  </small>
                </li>
              ))}
            </ul>
          </article>
        </div>
      </section>
    </>
  );
}

function splitRanges(value) {
  return value
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function DecisionExplanation({ value = {} }) {
  const baseline = value.baseline || {};
  const ml = value.ml || {};
  const final = value.final || {};
  return (
    <details>
      <summary>Why this decision?</summary>
      <p>
        Risk {final.risk_score ?? "—"}/100; policy confidence {final.confidence ?? "—"}.
        Baseline {baseline.baseline_ready ? "ready" : "not ready"}: observed{" "}
        {baseline.observed ?? "—"}, threshold {baseline.threshold ?? "—"}, deviation{" "}
        {baseline.deviation ?? "—"}.
      </p>
      <p>
        Model anomaly score: {ml.anomaly_score ?? "unavailable"} ({ml.model_version || "no model"}).
        This is not policy confidence.
      </p>
      <p>{(final.guardrails || []).join("; ")}</p>
    </details>
  );
}
