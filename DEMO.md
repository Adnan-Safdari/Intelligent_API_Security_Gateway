# Live demo: JMeter + Gateway Dashboard

This is the presentation flow for the complete project. JMeter is the only
traffic generator; the Gateway Dashboard is the only evidence and control
surface. There are no curl requests, Redis commands, gateway logs, mock
backends, or manual policy writes in this walkthrough.

The story is simple: **generate an attack, watch the gateway record it, let the
control plane correlate it, then show the policy the gateway enforces.**

## Before the audience arrives

Start the stack from the repository root:

```powershell
docker compose -f infra/docker-compose.yml up -d
```

Open [http://localhost:5177](http://localhost:5177) and wait until its status
line shows **Redis connected** and a recent control-plane heartbeat. In
**Settings**, use **Reset console** to clear prior events, campaigns and
history. Reset intentionally leaves active policies in place, so on **Policy**
delete any policy for the address you will reuse—or choose a fresh JMeter
`ATTACKER_IP`.

Keep these two windows visible:

1. Apache JMeter 5.6.3, opened in `testing/jmeter/` so the plans can find their CSV dictionaries.
2. The dashboard at `http://localhost:5177`.

> Only use these attack plans against this local, deliberately vulnerable demo.

## One important Docker Desktop detail

JMeter plans carry `X-Forwarded-For` identities from RFC 5737 documentation
ranges. The gateway trusts that header only from configured proxies. A JMeter
GUI running on the host still proves gateway detection and the reflex, but on
Docker Desktop its forwarded client address can be ignored and the control
plane will correctly refuse to write policy for the resulting private address.

For the full **campaign → public IP policy → enforcement** demonstration, run
the JMeter plan inside the Compose network. This is still JMeter; it only
places the load generator where the gateway can safely trust its forwarded
identity. From `testing/jmeter/`, run the plan with a JMeter Docker image you
already use, targeting the Compose service name:

```powershell
docker run --rm --network infra_default -v "${PWD}:/plans" -w /plans justb4/jmeter:5.6.3 `
  -n -t adaptive_rate_limit.jmx -JHOST=gateway -JPORT=8082 -JATTACKER_IP=203.0.113.250
```

If your Compose project has a different network name, find it with
`docker network ls` and substitute its `<project>_default` name. The JMeter GUI
is still useful for opening a plan, reading its samplers, and showing its
Summary Report; the networked command is the reliable run mode for policies on
Docker Desktop.

## The polished 8-minute flow

### 1. Start clean — 30 seconds

On **Overview**, point out:

- the four live measures: requests, alerts, addresses and policies;
- the source map and signal mix; and
- the status bar showing the control plane is separate but healthy.

Open **Settings** briefly. Show that gateway enforcement is live-configurable,
then leave `Policy enforcement` enabled. Do not change thresholds during the
main walkthrough: the supplied plans match the shipped configuration.

Talking point: “The gateway sees every request, but it does not wait for a
model or a database to decide what to do.”

### 2. Create a complete incident — 90 seconds

Run `adaptive_rate_limit.jmx` using the Compose-network command above. The
plan automatically:

1. sends 12 invalid logins from `203.0.113.250`;
2. waits for the 30-second control-plane cycle and gateway policy refresh; and
3. sends 25 health requests from the same address, expecting 20 `200` results
   followed by five `429` results.

While JMeter is in its wait stage, use the dashboard in this order:

1. **Events** — enable **Alerts only**. Filter for `203.0.113.250` and show the
   failed-login evidence. This is raw observation, not a verdict.
2. **Campaigns** — show the correlated brute-force campaign, its confidence,
   evidence count, affected address and explanation. This is where individual
   events become an incident.
3. **Policy** — show the active policy, its action, source, and countdown to
   expiry. A policy exists only after the agent's bounded decision process.
4. Return to JMeter's Summary Report. The final health requests receive `429`:
   the gateway enforces its already-refreshed snapshot without asking the
   control plane per request.

Talking point: “The 429 is a throttle, not a permanent ban. The response says
‘not this fast’; when the policy TTL expires, the restriction disappears by
itself.”

### 3. Show the other attack signals — 2 minutes

Run these plans one at a time from JMeter. In the GUI, open a plan and click
Start. Under Docker Desktop, use the Compose-network pattern with
`-t <plan>.jmx -JHOST=gateway -JPORT=8082` whenever a plan includes an
`X-Forwarded-For` demonstration identity and you want its public-IP policy
path to be visible.

| JMeter plan | What to show in the dashboard | Expected result |
| --- | --- | --- |
| `brute_force_demo.jmx` | Events filtered to failed logins, then the Campaigns page | Repeated credential failures become evidence and a campaign. This plan focuses on detector behaviour; use `adaptive_rate_limit.jmx` for its public-IP policy path. |
| `flood_demo.jmx` | Overview alert count, Events signal filter, then Policy | API-flood evidence; the shipped gateway reflex may return `403` once its configured threshold is crossed. |
| `sqli_probe.jmx` | Events filtered to SQL injection | Request-scoped SQLi evidence is recorded. A detector does not automatically block a single ambiguous request. |
| `path_traversal_probe.jmx` | Events filtered to traversal / enumeration | Traversal and forced-browsing evidence is recorded for correlation. |
| `distributed_attack.jmx` | Campaigns and Overview source map | Several identities and attack types demonstrate correlation and a multi-stage view. |

For each plan, keep the explanation consistent:

**Events are evidence. Campaigns are conclusions. Policy is the decision now
being enforced.**

### 4. Demonstrate human control safely — 90 seconds

Use an existing campaign or policy from the preceding steps.

1. On **Policy**, select a different action for a row or use **Instruct the
   agent** with the campaign address and a reason such as `demo review`.
2. Explain that the console writes an instruction, not a policy directly. It
   is applied on the next control-plane cycle and is still subject to
   allowlists, shared-range checks, TTL limits and the writer's safeguards.
3. On **Campaigns**, select a campaign to show the bulk temporary-block action.
   This demonstrates response at incident scope rather than hunting through
   individual event rows.
4. On **Policy**, point out the expiry countdown. If you use **Delete policy**,
   explain it is immediate but does not erase the underlying campaign; the
   agent can write a fresh policy if the incident remains active.

Never demonstrate a policy against localhost or a private address: the writer
rejects them by design. Use an RFC 5737 address such as `203.0.113.250`.

### 5. Demonstrate adaptive governance — 90 seconds

Open **Adaptive enforcement**.

- **Monitor** continues learning, scoring and correlation but never writes an
  enforcing gateway policy.
- **Manual** holds recommendations for an analyst to approve, edit or reject.
- **Automatic** is the default bounded mode: only guardrail-compliant throttle
  or temporary-block recommendations can become policy; ML-only anomalies are
  still monitor-only.

Show the active-policy/recommendation audit and the endpoint-baseline section.
The point is not “AI blocks users”; it is that learning is visible, decisions
are constrained, and an analyst can review the evidence-to-action trail.

If you switch modes for the presentation, switch back to **Automatic** before
running the adaptive rate-limit plan again.

### 6. Close with history and reset — 30 seconds

Open **History** to show that campaigns and feedback persist in Postgres across
service restarts. Then return to **Settings → Reset console** to remove demo
events, campaigns and history. Active policy keys are intentionally preserved;
remove them individually on **Policy** or let their TTL expire.

## Fast recovery

| Symptom | Dashboard-first fix |
| --- | --- |
| No events arrive | Confirm the Overview status bar reports Redis connected, then verify JMeter targets port `8082`, not the vulnerable API on `5002`. |
| Events appear but no policy | Wait one control-plane cycle, then confirm the attack uses a public documentation IP from a trusted Compose-network JMeter run. Also check Adaptive mode is not `monitor`. |
| The adaptive plan fails its `429` assertion | Delete the prior policy for that IP on Policy, or rerun with a new `-JATTACKER_IP=203.0.113.251`. |
| JMeter receives `403` sooner than expected | The gateway reflex responded to a configured repeated signal; show that immediate protection and use a fresh address for the policy-throttle sequence. |
| The dashboard looks old | It polls automatically. Refresh the page only if the status line reports a dependency problem. |

## Demo checklist

- [ ] Compose stack running; Overview shows Redis connected and a heartbeat.
- [ ] Console reset; no reused active policy for the selected attacker IP.
- [ ] JMeter uses the gateway on `8082`.
- [ ] Compose-network JMeter run is used when public-IP policy enforcement must be shown.
- [ ] Events → Campaigns → Policy → JMeter result is shown in that order.
- [ ] Policy expiry and the separation between detector, decision and enforcement are explained.
