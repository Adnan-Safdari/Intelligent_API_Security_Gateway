# JMeter attack plans

Load-generator plans that drive real attacks through the gateway
(`localhost:8082`), one per detector plus a combined one. They exist to make the
gateway's behaviour visible end to end: the detector fires, telemetry records
it, and — for the windowed signals — the gateway's own reflex starts refusing
the attacker.

Built for JMeter 5.6.3.

## The plans

| Plan | Attack | Detector | Does the gateway block on its own? |
| --- | --- | --- | --- |
| `brute_force_demo.jmx` | Dictionary login attack on `/api/login` | `consecutive_failed_logins` | **No** — windowed, but advisory-only; the reflex refuses this signal if named in `block.signals` |
| `flood_demo.jmx` | Request flood on `/api/products` | `api_flooding` | **Yes** — windowed |
| `sqli_probe.jmx` | SQL injection in a login body and a query string | `sql_injection` | No — request-scoped, the control plane decides |
| `path_traversal_probe.jmx` | `../` traversal and forced-browsing probes | `enumeration_path_traversal` | No — request-scoped |
| `distributed_attack.jmx` | Flood + brute force from several addresses at once | both windowed | Only the flood half — see below |
| `adaptive_rate_limit.jmx` | FR3: campaign-driven high-severity throttle | brute force + policy limiter | **Yes, 20/min after policy arrives** |

There is currently no plan for `unknown_route_scanning`, the newest detector.

`distributed_attack.jmx` runs flood and brute-force threads together, but only
the flood thread group can trigger the reflex on its own — brute force is
advisory-only regardless of how many addresses are involved. The plan itself
carries no response assertions either; it's a visible demo, not a pass/fail
check.

"Windowed" detectors fire on repetition; among those, only the ones the reflex
trusts (`api_flooding` and `ip_reputation` today) are safe for the gateway to
act on by itself. `consecutive_failed_logins` and `unknown_route_scanning` are
windowed too but are advisory-only by design — see
`gateway/docs/detection-signals.md`. Request-scoped detectors turn on a single
request that might be innocent, so that judgement is always left to the
control plane.

The `.csv` files are the payload and probe dictionaries the plans read.

## Adaptive rate limiting / FR3

`adaptive_rate_limit.jmx` checks the complete FR3 path, not merely the
detector:

1. It sends 12 failed logins to build a high-severity brute-force campaign.
2. It waits 45 seconds for the control plane (30-second cycle) and the
   gateway's policy refresh.
3. It sends 25 `GET /api/health` requests from the same address and asserts
   that requests 1-20 return `200`, while requests 21-25 return `429`.

The default `ATTACKER_IP` is `203.0.113.250`, an RFC 5737 documentation address
that the policy writer permits for demos. The Docker bridge peer is trusted by
the local configuration, so the plan's `X-Forwarded-For` header is used as the
detector/policy identity. Choose another documentation address between runs if
the earlier 15-minute policy still exists:

```bash
jmeter -n -t adaptive_rate_limit.jmx --jmeterproperty ATTACKER_IP=203.0.113.251
```

## Two ways to run

### 1. The GUI — one attacker

```bash
jmeter                     # opens the window; File → Open a .jmx
```

The plans default to `localhost:8082`, so they run against the gateway with no
setup. Good for watching one attacker get detected, and for the brute-force and
SQLi demos where a single source is all you need.

**The catch under Docker Desktop:** its port forwarder does not preserve source
addresses, so every request from your Mac reaches the gateway as one invented
address. The `X-Forwarded-For` headers in the plans are therefore ignored, and
the several attacker IPs in `flood_demo`/`distributed_attack` collapse into one.
You still see *a* block — just not a distributed one.

### 2. Inside the Compose network — several attackers

To make the distinct attacker addresses real, run JMeter as a container on the
Compose network and target the gateway by its service name. The
`X-Forwarded-For` headers are then believed, because the gateway trusts the
Compose bridge (`server.trusted_proxies`).

```bash
docker run --rm --network infra_default \
  -v "$PWD:/plans" -w /plans \
  -v "$(brew --prefix jmeter)/libexec:/jmeter:ro" \
  eclipse-temurin:17-jre \
  /jmeter/bin/jmeter -n -t distributed_attack.jmx -JHOST=gateway -JPORT=8082 -l out.jtl
```

Run this from inside `testing/jmeter/` so the plans find their `.csv` files.
`-JHOST`/`-JPORT` override the localhost defaults; the plans read them through
`${__P(...)}`, so the same file works both ways.

> If `brew --prefix jmeter` cannot be shared into Docker (Docker Desktop only
> shares a few paths by default), copy `libexec` somewhere shared first — or use
> any JMeter image you trust in place of the mount.

## Before you attack

- **Point the gateway's reflex at the signals you want blocked.** Set
  `enforcement.block.signals` in `gateway/configs/config.yaml` (see
  `config.yaml.example`) and restart the gateway. Without it the detectors still
  fire and the console still shows the attack, but nothing is refused.
- **Turn on `enforcement.policy.enabled`** if you also want the control plane's
  slower, considered decisions to take effect.
- **One control plane only.** A stray second agent on the same Redis will
  mis-correlate your own traffic; make sure just the Compose one is running.

## What you should see

```
# gateway console
SECURITY ALERT: SQL INJECTION DETECTED
[enforcement] blocking 198.51.100.1 for 1m0s: api_flooding crossed threshold (score 60)

# response codes
flood:        404 while allowed, then 403 once the reflex trips
brute force:  401 from the backend, then 403 once blocked
sqli / trav:  401/404 — detected and recorded, not blocked at the gateway
```

The dashboard's **Events** page shows every one of these with its decision; the
**Campaigns** page shows what the control plane correlated out of them.
