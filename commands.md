# IASG Testing & Demo Command Reference

All commands below assume **Windows PowerShell** and are run from the repository root unless a command changes directory. The current Compose file maps the gateway to `http://localhost:8082`, the deliberately vulnerable backend to `http://localhost:5002`, the dashboard to `http://localhost:5177`, and the vulnerable web UI to `http://localhost:5175`.

Use only the local lab stack described here. The attacks in this document target the intentionally vulnerable demo application; they must not be pointed at an external or production system.

> **PowerShell note:** use `curl.exe`, not the `curl` alias, so the examples use real curl arguments. All Redis examples run `redis-cli` inside the Compose `redis` service, so a host Redis installation is unnecessary.

## Test 1 — Infrastructure / Docker baseline

### Purpose

Start the complete local stack and confirm the services and their logs are healthy.

### Commands

```powershell
docker compose -f .\infra\docker-compose.yml up -d
docker compose -f .\infra\docker-compose.yml ps
docker compose -f .\infra\docker-compose.yml logs --tail=100
docker compose -f .\infra\docker-compose.yml logs -f gateway
docker compose -f .\infra\docker-compose.yml logs -f vulnerable_api
docker compose -f .\infra\docker-compose.yml logs -f control_plane
```

Useful lifecycle commands:

```powershell
docker compose -f .\infra\docker-compose.yml restart gateway
docker compose -f .\infra\docker-compose.yml stop
docker compose -f .\infra\docker-compose.yml down
```

`down` stops and removes Compose containers and networks, but leaves named database/Redis volumes intact. It is not a data reset.

## Test 2 — Direct vulnerable backend connectivity

### Purpose

Prove that requests can reach the deliberately vulnerable backend without passing through IASG.

### Commands

```powershell
curl.exe -i http://localhost:5002/
curl.exe -i http://localhost:5002/api/products
curl.exe -i "http://localhost:5002/api/products/search?q=keyboard"
docker compose -f .\infra\docker-compose.yml logs --tail=50 vulnerable_api
```

`Cannot GET /` / HTTP 404 is still evidence that Express is reachable at port 5002; `/api/products` and the search route are the useful successful checks.

## Test 3 — Direct backend login endpoint

### Purpose

Exercise the backend login endpoint directly. It intentionally has no backend-native IP lockout, so it remains suitable for brute-force and spray demonstrations.

### Commands

```powershell
# Seeded local demo account; this is fake lab data, not a real credential.
curl.exe -i -X POST http://localhost:5002/api/login `
  -H "Content-Type: application/json" `
  -d '{"email":"admin@shopforge.com","password":"admin123"}'

# Deliberately invalid; no real credential is documented here.
curl.exe -i -X POST http://localhost:5002/api/login `
  -H "Content-Type: application/json" `
  -d '{"email":"admin@example.com","password":"definitely-wrong"}'
```

The current backend reads `email` and `password`. The gateway detector counts either a JSON `email` or `username` as the attempted identity; email takes precedence if both are supplied.

## Test 4 — Same request through the Gateway

### Purpose

Show the normal route: client → gateway → vulnerable API.

### Commands

```powershell
curl.exe -i -X POST http://localhost:8082/api/login `
  -H "Content-Type: application/json" `
  -H "X-Forwarded-For: 198.51.100.90" `
  -d '{"email":"admin@example.com","password":"definitely-wrong"}'

curl.exe -i "http://localhost:8082/api/products/search?q=keyboard" `
  -H "X-Forwarded-For: 198.51.100.90"
```

The Compose configuration trusts the local/Compose proxy ranges, so the documentation IP in `X-Forwarded-For` is used for a repeatable demo instead of the host loopback address.

## Test 5 — Gateway inspection / log verification

### Purpose

Inspect incoming activity, detector alerts, reflex enforcement, and policy decisions.

### Commands

```powershell
docker compose -f .\infra\docker-compose.yml logs --tail=100 gateway

docker compose -f .\infra\docker-compose.yml logs --tail=300 gateway |
  Select-String -Pattern 'SECURITY ALERT|IP Address|Endpoint|API FLOOD|SQL INJECTION|PATH TRAVERSAL|ENUMERATION|enforcement|policy|blocking|Retry-After'

docker compose -f .\infra\docker-compose.yml logs -f gateway |
  Select-String -Pattern 'SECURITY ALERT|enforcement|policy|blocking'
```

Detector alerts identify the source IP and endpoint. A detector alert is evidence; a `403`/`Retry-After`, an enforcement log, or an active `policy:<ip>` key is the separate enforcement proof.

## Test 6 — Redis telemetry

### Purpose

Inspect the gateway event stream and control-plane policy keys.

### Commands

```powershell
docker compose -f .\infra\docker-compose.yml exec redis redis-cli XLEN iasg:events
docker compose -f .\infra\docker-compose.yml exec redis redis-cli XREVRANGE iasg:events + - COUNT 10
docker compose -f .\infra\docker-compose.yml exec redis redis-cli XREVRANGE iasg:events + - COUNT 100 |
  Select-String -Pattern 'sql_injection|api_flooding|consecutive_failed_logins|unknown_route_scanning|object_enumeration|enumeration_path_traversal|ip_reputation'

docker compose -f .\infra\docker-compose.yml exec redis redis-cli KEYS 'policy:*'
docker compose -f .\infra\docker-compose.yml exec redis redis-cli GET policy:198.51.100.91
docker compose -f .\infra\docker-compose.yml exec redis redis-cli GET iasg:heartbeat
```

Important Redis resources include `iasg:events` (the capped telemetry stream; current configured maximum is 2000) and `policy:<ip>` (an expiring enforcement decision).

## Test 7 — API Flood Detection + Gateway Reflex

### Purpose

Generate a short, readable per-IP flood and observe detection first, then the gateway reflex block.

### Commands

Before this exact 22-request demo, open Dashboard → **Settings** and apply these runtime values: flooding enabled, requests/minute `10`; reflex enabled, signals include `api_flooding`, minimum score `80`, duration `2m`. The tracked `gateway/configs/config.yaml` defaults are instead **100 RPM** and **300s**, so this demo override is intentional.

```powershell
1..22 | ForEach-Object {
  $code = curl.exe -s -o NUL -w "%{http_code}" `
    -H "X-Forwarded-For: 198.51.100.91" `
    http://localhost:8082/api/products
  Write-Host "Request $_ -> HTTP $code"
  Start-Sleep -Milliseconds 150
}
```

With the stated demo values, requests 1–20 normally reach the backend with HTTP 200. At request count 20 the flood evidence reaches score 80 and arms the reflex; request 21 and later should return HTTP 403. The detector crosses its own threshold after **more than** 10 requests.

## Test 8 — Reflex TTL / automatic release

### Purpose

Verify that a reflex block reports and honors a fixed expiry rather than renewing when the attacker retries.

### Commands

```powershell
curl.exe -i http://localhost:8082/api/products `
  -H "X-Forwarded-For: 198.51.100.91"

# Run this once, wait about two minutes when using the Test 7 demo setting, then run it again.
curl.exe -i http://localhost:8082/api/products `
  -H "X-Forwarded-For: 198.51.100.91"
```

While blocked, expect HTTP 403 and `Retry-After`. Repeated blocked requests must show a decreasing value rather than resetting the expiry. After the temporary block expires, the same request should again return HTTP 200 unless a control-plane policy for that IP is independently active.

## Test 9 — Exempt IP / safety tests

### Purpose

Run the actual reflex exemption tests: loopback/private addresses are protected by the configured exemption list, while documentation addresses are usable demo attackers.

### Commands

```powershell
Push-Location .\gateway
go test ./internal/enforcement -run 'TestExemptRangesAreNeverBlocked|TestTheComposeBridgeIsBlockable|TestInvalidExemptRangeIsRefusedAtStartup'
Pop-Location
```

## Test 10 — Brute force (`consecutive_failed_logins`)

### Purpose

Send repeated failed login attempts from one simulated IP. The detector fires
at `max_failures` (default 5) consecutive invalid-credential outcomes for the
same client and login target, read from `routes.auth_outcomes` rather than a
hardcoded status code. **This signal is advisory-only**: it cannot arm the
gateway's own reflex — `internal/enforcement/reflex.go` refuses to start if
`consecutive_failed_logins` is named in `block.signals` — so the following
unrelated request will never be blocked by the gateway alone. It becomes an
expiring throttle or block only after the control plane correlates the
evidence and the policy writer's checks pass.

### Commands

```powershell
1..10 | ForEach-Object {
  $code = curl.exe -s -o NUL -w "%{http_code}" -X POST http://localhost:8082/api/login `
    -H "Content-Type: application/json" `
    -H "X-Forwarded-For: 203.0.113.60" `
    -H "User-Agent: iasg-brute-demo/1.0" `
    -d "{\"email\":\"admin@example.com\",\"password\":\"wrong-$($_)\"}"
  Write-Host "Login attempt $_ -> HTTP $code"
}

# There is nothing to grep for in the gateway logs -- brute_force.go is
# evidence-only and logs nothing. Check the evidence stream instead:
docker compose -f .\infra\docker-compose.yml exec redis redis-cli XREVRANGE iasg:events + - COUNT 50 |
  Select-String -Pattern 'consecutive_failed_logins|203\.0\.113\.60'

# Give the control plane a cycle (default 30s) to correlate, then check for a policy.
docker compose -f .\infra\docker-compose.yml exec redis redis-cli GET policy:203.0.113.60
```

The ten failed logins themselves are normally HTTP 401 from the backend. Any
enforcement that eventually appears against `203.0.113.60` came from the
control plane's next cycle, not from the gateway acting alone.

## Test 10B — Many login identities from one address

### Purpose

Use one source IP across many `email` values. The Go detector does not
classify this as "password spraying" — that distinction does not exist at the
gateway level; `brute_force.go` tracks a consecutive-failure streak per
`(client, login target)` and has no concept of distinct identities. "Password
spraying" is only ever a **control-plane campaign classification**
(`correlation/agent.py`), derived from repeated brute-force evidence after
several addresses or identities are correlated together — it is never a
gateway signal or log line.

### Commands

```powershell
1..5 | ForEach-Object {
  $email = "demo-user$($_)@example.com"
  $json = @{ email = $email; password = 'one-demo-password' } | ConvertTo-Json -Compress
  $code = curl.exe -s -o NUL -w "%{http_code}" -X POST http://localhost:8082/api/login `
    -H "Content-Type: application/json" `
    -H "X-Forwarded-For: 203.0.113.61" `
    -H "User-Agent: iasg-spray-demo/1.0" `
    -d $json
  Write-Host "Spray $email -> HTTP $code"
}

# Check whether the control plane formed a campaign from this, once it has
# had a cycle (default 30s) to run:
docker compose -f .\infra\docker-compose.yml exec redis redis-cli KEYS 'campaign:*'
```

## Test 11 — SQL injection

### Purpose

Demonstrate the isolated vulnerable product search directly, then send the same safe local-lab payload through IASG to produce evidence. No runtime backend mode or `/api/set-mode` is required.

### Commands

```powershell
# Normal direct backend search: a subset of the demo catalogue.
curl.exe "http://localhost:5002/api/products/search?q=keyboard"

# Direct local demonstration: unsafe SQL changes the WHERE clause and returns many/all demo products.
curl.exe -G "http://localhost:5002/api/products/search" --data-urlencode "q=' OR 1=1 --"

# Same normal request through IASG.
curl.exe "http://localhost:8082/api/products/search?q=keyboard" `
  -H "X-Forwarded-For: 198.51.100.92"

# Same local payload through IASG. SQLi remains evidence-only at the reflex layer.
curl.exe -G "http://localhost:8082/api/products/search" `
  -H "X-Forwarded-For: 198.51.100.92" `
  --data-urlencode "q=' OR 1=1 --"

docker compose -f .\infra\docker-compose.yml logs --tail=200 gateway |
  Select-String -Pattern 'SQL INJECTION|198\.51\.100\.92|products/search'

docker compose -f .\infra\docker-compose.yml exec redis redis-cli XREVRANGE iasg:events + - COUNT 100 |
  Select-String -Pattern 'sql_injection|matchedPatterns|matchCount|198\.51\.100\.92'
```

The detector examines path, decoded query parameters, and request body. It forwards the request; any later throttle or block must come from the centralized policy path. Dashboard → Events, then `/ip/198.51.100.92`, shows the dedicated **SQL injection evidence** panel with detection, patterns, risk, request ID, HTTP status, and decision.

## Test 12 — Path traversal + enumeration

### Purpose

Exercise detector signatures against the local lab and the backend’s bounded fake demo resources. No host, container, secret, or real configuration data is exposed.

### Commands

```powershell
# Harmless planted enumeration marker.
curl.exe -i http://localhost:8082/.env-demo `
  -H "X-Forwarded-For: 198.51.100.93"

# Traversal-shaped query stays inside vulnerable-app/backend/demo-files.
curl.exe -G http://localhost:8082/api/demo-files `
  -H "X-Forwarded-For: 198.51.100.93" `
  --data-urlencode "file=public/../fake-secret.txt"

# Local detector-only forced-browsing probes; responses are allowed to be 404.
curl.exe -i http://localhost:8082/.git/config -H "X-Forwarded-For: 198.51.100.93"
curl.exe -i http://localhost:8082/etc/passwd -H "X-Forwarded-For: 198.51.100.93"

docker compose -f .\infra\docker-compose.yml logs --tail=250 gateway |
  Select-String -Pattern 'PATH TRAVERSAL|ENUMERATION|198\.51\.100\.93'
docker compose -f .\infra\docker-compose.yml exec redis redis-cli XREVRANGE iasg:events + - COUNT 100 |
  Select-String -Pattern 'enumeration_path_traversal|198\.51\.100\.93'
```

Traversal/enumeration are request-scoped evidence signals and are intentionally not listed as reflex-blocking signals in the current configuration.

## Test 12B — Object ID enumeration / BOLA (`object_enumeration`)

### Purpose

Show that one logged-in client counting through order ids is recorded as object-level harvesting. `/api/orders/{id}` is deliberately missing its ownership check; `/api/orders-secure/{id}` has one. The detector is advisory-only and cannot see who owns an order, so it detects the pattern. Through the demo gateway the reads themselves are also refused by the ownership check (Test 12C), so most answers are `404`.

### Commands

```powershell
# Log in as jane; the backend returns a signed token.
$login = Invoke-RestMethod -Method Post http://localhost:8082/api/login `
  -ContentType "application/json" -Body '{"email":"jane@example.com","password":"user123"}'
$token = $login.token

# Normal use: her own order list.
curl.exe -s http://localhost:8082/api/orders `
  -H "Authorization: Bearer $token" -H "X-Forwarded-For: 198.51.100.95"

# Harvesting: 30 ids, most belonging to other customers (404 through the gateway).
1..30 | ForEach-Object {
  curl.exe -s -o NUL -w "%{http_code} " "http://localhost:8082/api/orders/$_" `
    -H "Authorization: Bearer $token" -H "X-Forwarded-For: 198.51.100.95"
}

docker compose -f .\infra\docker-compose.yml exec redis redis-cli XREVRANGE iasg:events + - COUNT 50 |
  Select-String -Pattern 'object_enumeration|198\.51\.100\.95'
```

Expect `object_enumeration` in `fired` from the 20th distinct id, with `template` `GET /api/orders/{id}`, `sequentialRun` 20 or more, and a high `deniedShare` because the ownership check refused most of them.

## Test 12C — Ownership check (`ownership_violation`)

### Purpose

Show the gateway stopping BOLA rather than only noticing it. The backend's `/api/orders/{id}` returns any customer's order; `routes.ownership` verifies jane's token, reads the order's `userId`, and answers `404` for anyone else's order before a byte of it is sent. The backend on port 5002 still leaks, to show the fix is in the gateway.

### Commands

```powershell
$login = Invoke-RestMethod -Method Post http://localhost:8082/api/login `
  -ContentType "application/json" -Body '{"email":"jane@example.com","password":"user123"}'
$auth = @{ Authorization = "Bearer $($login.token)" }

# Through the gateway: her own orders 200, everyone else's 404.
foreach ($id in 1..30) {
  try { $o = Invoke-RestMethod "http://localhost:8082/api/orders/$id" -Headers $auth; "$id 200 owner $($o.order.userId)" }
  catch { "$id $($_.Exception.Response.StatusCode.value__)" }
}

# Straight to the backend: other customers' orders come back.
Invoke-RestMethod http://localhost:5002/api/orders/2 -Headers $auth

# A forged token (base64 of the user id, the demo's old token): 401.
curl.exe -s -o NUL -w "%{http_code}`n" http://localhost:8082/api/orders/1 `
  -H "Authorization: Bearer $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('2')))"

docker compose -f .\infra\docker-compose.yml logs --tail=40 gateway | Select-String '\[ownership\]'
```

Expect no `200` for an order whose owner is not jane's, `[ownership] refused ... owner_mismatch` lines in the gateway log, and `ownership_violation` in `iasg:events`. From a public identity the control plane forms an "Unauthorized Object Access (BOLA)" campaign and a throttle scoped to `GET /api/orders/{id}`. On macOS or Linux: `BACKEND_URL=http://localhost:5002 bash testing/signals/ownership.sh`.

**Storefront version**, for a panel that would rather watch a browser than curl: open `http://localhost:5175`, sign in as `jane@example.com` / `user123`, and use the Backend/Gateway switch in the navbar. In Gateway mode, My Orders lists only 1, 6, 11, 16, 21, 26, 31, 36; editing the address bar to `/orders/2` answers "Order not found". Flip the switch to Backend and reload the same `/orders/2` -- it now shows Arjun Mehta's name, address and items. Flip back to Gateway to keep browsing without leaking further orders.

## Test 13 — Control-plane correlation

### Purpose

Watch the agent consume gateway evidence, form campaigns, explain its reasoning, and write policy keys.

### Commands

```powershell
docker compose -f .\infra\docker-compose.yml logs --tail=250 control_plane
docker compose -f .\infra\docker-compose.yml logs -f control_plane |
  Select-String -Pattern '\[cycle\]|\[correlation\]|\[explain\]|\[policy\]|\[review\]|\[assess\]|\[heartbeat\]'
```

A campaign is demonstrated by a `[correlation] Campaign #…` record. `[policy] wrote … policy keys` shows that the control plane made a considered decision; it runs on a cycle rather than in the request path.

## Test 14 — Agent policy → Redis

### Purpose

Inspect active policy decisions and their expiry.

### Commands

```powershell
docker compose -f .\infra\docker-compose.yml exec redis redis-cli KEYS 'policy:*'
docker compose -f .\infra\docker-compose.yml exec redis redis-cli GET policy:198.51.100.91
docker compose -f .\infra\docker-compose.yml exec redis redis-cli TTL policy:198.51.100.91

$keys = docker compose -f .\infra\docker-compose.yml exec -T redis redis-cli --raw KEYS 'policy:*'
if ($keys) { docker compose -f .\infra\docker-compose.yml exec -T redis redis-cli MGET $keys }
```

Policy JSON has an `action` such as `monitor`, `throttle`, `temp_block`, or `escalate`. `monitor` is observe-only; `throttle` limits the address to the policy's `requests_per_minute` via a shared Redis token bucket, answering `429` with `Retry-After` once exhausted — `throttle.delay_ms` in `config.yaml` is a legacy setting retained for console compatibility and no longer sleeps on the request path; `temp_block` and `escalate` deny requests while the policy key exists.

## Test 15 — Reflex → control-plane handoff

### Purpose

Show the two lanes in their intended order: immediate reflex action, asynchronous correlation, then policy enforcement.

### Commands

```powershell
# Terminal A
docker compose -f .\infra\docker-compose.yml logs -f gateway |
  Select-String -Pattern 'API FLOOD|enforcement|blocking|policy'

# Terminal B
docker compose -f .\infra\docker-compose.yml logs -f control_plane |
  Select-String -Pattern '\[cycle\]|\[correlation\]|\[policy\]|\[explain\]'

# Terminal C
docker compose -f .\infra\docker-compose.yml exec redis redis-cli GET policy:198.51.100.91
docker compose -f .\infra\docker-compose.yml exec redis redis-cli TTL policy:198.51.100.91
```

Run the Test 7 or Test 10 traffic in a fourth terminal. The reflex can return 403 immediately; the control plane subsequently correlates retained evidence and may write a separate TTL policy that the gateway refreshes from its policy snapshot.

## Test 16 — Dashboard live monitoring

### Purpose

Use the current console pages to inspect real-time telemetry and conclusions.

### Commands

Open `http://localhost:5177` and sign in/create the local administrator if prompted. Current navigation pages are:

- `/` — Overview
- `/campaigns` — active correlated campaigns
- `/policy` — in-force policies, queued agent instructions, and **Delete policy**
- `/events` — raw events, filters, event serial number, export, and paging
- `/history` — durable campaign history
- `/settings` — live enforcement settings and Reset console
- `/ip/<address>` — per-IP investigation (linked from events/campaigns)

## Test 17 — Historical events / pagination

### Purpose

Generate enough telemetry to compare Redis retention with the Events page’s loaded rows.

### Commands

```powershell
# A different documentation IP for each request avoids a per-IP flood block,
# while producing enough retained events to page through.
$eventIps = @(1..254 | ForEach-Object { "198.51.100.$_" }) +
  @(1..46 | ForEach-Object { "203.0.113.$_" })
foreach ($ip in $eventIps) {
  curl.exe -s -o NUL http://localhost:8082/api/products -H "X-Forwarded-For: $ip"
}

docker compose -f .\infra\docker-compose.yml exec redis redis-cli XLEN iasg:events
docker compose -f .\infra\docker-compose.yml exec redis redis-cli XREVRANGE iasg:events + - COUNT 5
```

On Dashboard → Events, choose a window (100/250/500/1000/2000). The status text reports loaded versus retained events; use **load … older** while it is available. The gateway retains at most the configured `stream_maxlen` (currently 2000).

## Test 18 — Per-IP investigation

### Purpose

Create evidence for a known documentation IP and inspect exactly that address across activity, policy, campaigns, signals, outcomes, and SQLi evidence.

### Commands

```powershell
curl.exe -G "http://localhost:8082/api/products/search" `
  -H "X-Forwarded-For: 198.51.100.95" `
  --data-urlencode "q=' OR 1=1 --"

docker compose -f .\infra\docker-compose.yml exec redis redis-cli XREVRANGE iasg:events + - COUNT 100 |
  Select-String -Pattern '198\.51\.100\.95|sql_injection'
docker compose -f .\infra\docker-compose.yml exec redis redis-cli GET policy:198.51.100.95
```

Open `http://localhost:5177/ip/198.51.100.95`. The page separates SQLi **detection evidence** from the current enforcement decision.

## Test 19 — Filtering / export

### Purpose

Validate that an operator can narrow evidence and save the visible rows.

### Commands

No terminal command is needed. On Dashboard → Events:

1. Enter an IP (for example `198.51.100.95`) in the search box.
2. Click a signal chip such as SQL injection, or enable **Alerts only**.
3. Use **export csv** or **json**; exports contain the current filtered rows.
4. Policy and per-IP activity tables also expose their relevant CSV/JSON export controls.

## Test 20 — JMeter attack plans

### Purpose

Run the checked-in load plans without installing JMeter locally. Current files in `testing/jmeter/` are six plans, not five:

```text
adaptive_rate_limit.jmx    brute_force_demo.jmx      distributed_attack.jmx
flood_demo.jmx             path_traversal_probe.jmx  sqli_probe.jmx
passwords.csv              sqli_payloads.csv         traversal_paths.csv
```

There is no plan yet for `unknown_route_scanning`, the newest detector. See
`testing/jmeter/README.md` for which of these can arm the gateway's own
reflex — as of the current signal vocabulary, only `flood_demo.jmx`'s signal
can.

### Commands

All plans accept `-JHOST` and `-JPORT`. Running inside `infra_default` makes `gateway:8082` available and lets the trusted Compose bridge honor the plans’ simulated `X-Forwarded-For` addresses.

### Test 20A — `flood_demo.jmx`

#### Purpose

Drive the checked-in `/api/products` flood plan and inspect its detector, evidence, correlation, and policy outcomes.

#### Commands

```powershell
docker run --rm `
  --network infra_default `
  -v "${PWD}\testing\jmeter:/tests" `
  justb4/jmeter:latest `
  -n -t /tests/flood_demo.jmx `
  -JHOST=gateway `
  -JPORT=8082

docker compose -f .\infra\docker-compose.yml logs --tail=200 gateway |
  Select-String -Pattern 'API FLOOD|enforcement|policy'
docker compose -f .\infra\docker-compose.yml exec redis redis-cli XLEN iasg:events
docker compose -f .\infra\docker-compose.yml logs --tail=200 control_plane |
  Select-String -Pattern '\[correlation\]|\[policy\]'
docker compose -f .\infra\docker-compose.yml exec redis redis-cli KEYS 'policy:*'
```

### Test 20B — `sqli_probe.jmx`

#### Purpose

Run the signature probes and verify SQL injection evidence without expecting reflex blocking.

#### Commands

```powershell
docker run --rm `
  --network infra_default `
  -v "${PWD}\testing\jmeter:/tests" `
  justb4/jmeter:latest `
  -n -t /tests/sqli_probe.jmx `
  -JHOST=gateway `
  -JPORT=8082

docker compose -f .\infra\docker-compose.yml logs --tail=200 gateway |
  Select-String -Pattern 'SQL INJECTION|jmeter-sqli|policy'
docker compose -f .\infra\docker-compose.yml exec redis redis-cli XREVRANGE iasg:events + - COUNT 100 |
  Select-String -Pattern 'sql_injection|matchedPatterns'
```

The present plan probes `/api/login` JSON and `/api/products?q=…`; its JMeter error/value output can include expected backend 4xx responses. SQLi detection/evidence is the pass condition, not a mandatory 2xx response. For the intentionally vulnerable catalogue consequence, use the `/api/products/search` command in Test 11.

### Test 20C — `path_traversal_probe.jmx`

#### Purpose

Run the checked-in local traversal and forced-browsing probe dictionary.

#### Commands

```powershell
docker run --rm `
  --network infra_default `
  -v "${PWD}\testing\jmeter:/tests" `
  justb4/jmeter:latest `
  -n -t /tests/path_traversal_probe.jmx `
  -JHOST=gateway `
  -JPORT=8082

docker compose -f .\infra\docker-compose.yml logs --tail=200 gateway |
  Select-String -Pattern 'PATH TRAVERSAL|ENUMERATION|traversal-jmeter'
docker compose -f .\infra\docker-compose.yml exec redis redis-cli XREVRANGE iasg:events + - COUNT 100 |
  Select-String -Pattern 'enumeration_path_traversal'
```

### Test 20D — `brute_force_demo.jmx`

#### Purpose

Run the sustained login-failure plan using its checked-in password dictionary.

#### Commands

```powershell
docker run --rm `
  --network infra_default `
  -v "${PWD}\testing\jmeter:/tests" `
  justb4/jmeter:latest `
  -n -t /tests/brute_force_demo.jmx `
  -JHOST=gateway `
  -JPORT=8082

docker compose -f .\infra\docker-compose.yml logs --tail=250 gateway |
  Select-String -Pattern 'enforcement|policy'
docker compose -f .\infra\docker-compose.yml exec redis redis-cli XREVRANGE iasg:events + - COUNT 100 |
  Select-String -Pattern 'consecutive_failed_logins'
```

`brute_force.go` logs nothing on its own — it is evidence-only and
advisory-only, so `BRUTE FORCE` never appears in the gateway logs. Detection
is proven by the `consecutive_failed_logins` evidence above, not a log line.

### Test 20E — `distributed_attack.jmx`

#### Purpose

Run simultaneous flood and brute-force traffic from the JMX plan’s simulated attacker groups.

#### Commands

```powershell
docker run --rm `
  --network infra_default `
  -v "${PWD}\testing\jmeter:/tests" `
  justb4/jmeter:latest `
  -n -t /tests/distributed_attack.jmx `
  -JHOST=gateway `
  -JPORT=8082

docker compose -f .\infra\docker-compose.yml logs --tail=400 gateway |
  Select-String -Pattern 'API FLOOD|enforcement|policy'
docker compose -f .\infra\docker-compose.yml logs --tail=400 control_plane |
  Select-String -Pattern 'Distributed Flood|Brute Force|\[correlation\]|\[policy\]'
docker compose -f .\infra\docker-compose.yml exec redis redis-cli KEYS 'policy:198.51.100.*'
docker compose -f .\infra\docker-compose.yml exec redis redis-cli KEYS 'policy:203.0.113.*'
```

The current plan sends flood traffic to `GET /api/products` using `198.51.100.${__threadNum}` with `User-Agent: jmeter-flood/1.0`, and brute-force traffic to `POST /api/login` using `203.0.113.${__threadNum}` with `User-Agent: jmeter-brute/1.0`. Only the flood half can trigger the gateway's own reflex; the brute-force half is advisory-only and reaches enforcement only through a control-plane policy, if one forms. The plan itself carries no response assertions — it's a visible demo, not a pass/fail check.

## Test 21 — Distributed / multi-IP correlation

### Purpose

Verify that gateway detection is per IP while the control plane can correlate the related behavior into campaigns.

### Commands

```powershell
foreach ($ip in '198.51.100.1','198.51.100.2','198.51.100.3') {
  1..12 | ForEach-Object {
    curl.exe -s -o NUL http://localhost:8082/api/products -H "X-Forwarded-For: $ip"
  }
}

foreach ($ip in '203.0.113.1','203.0.113.2','203.0.113.3') {
  1..5 | ForEach-Object {
    curl.exe -s -o NUL -X POST http://localhost:8082/api/login `
      -H "Content-Type: application/json" -H "X-Forwarded-For: $ip" `
      -d '{"email":"admin@example.com","password":"wrong"}'
  }
}

docker compose -f .\infra\docker-compose.yml logs --tail=400 control_plane |
  Select-String -Pattern 'Distributed Flood|Brute Force|\[correlation\]'
docker compose -f .\infra\docker-compose.yml exec redis redis-cli KEYS 'policy:198.51.100.*'
docker compose -f .\infra\docker-compose.yml exec redis redis-cli KEYS 'policy:203.0.113.*'
```

Use the Test 7 rate setting if you want the short flood group to reach reflex scores. The correlation proof is a campaign containing several addresses, not merely a single gateway detector alert.

## Test 22 — Runtime settings / demo configuration

### Purpose

Record the recommended academic-demo settings and distinguish them from the checked-in default configuration.

### Commands

Open Dashboard → **Settings**, make the following deliberate live override, type `apply`, and confirm the status bar reports the agent/gateway live:

```text
API flooding: enabled; requests/minute 10
SQL injection: enabled
Brute force (consecutive failed logins): enabled; max failures 5; window 1m
  -- login target and success/failure statuses come from routes.auth_outcomes,
  -- not a configurable path here
Path traversal and enumeration: enabled
Unknown-route scanning: enabled
Reflex: enabled; signals api_flooding only; min score 80; duration 2m
  -- brute force and unknown-route scanning cannot be named here: the reflex
  -- refuses to start if either is listed in block.signals
Policy enforcement: enabled
Throttling: enabled; requests_per_minute set on the policy itself
```

The file defaults verified in `gateway/configs/config.yaml` are 100 RPM, 5-minute block duration, 5 failures/60 seconds, min score 80, `api_flooding` alone in reflex signals, and policy enforcement enabled in the present working file. `gateway/configs/config.yaml.example` is a starting template and leaves policy enforcement disabled, so it must not be treated as the live setting. Use **Revert to file** in Settings when the demo ends.

SQLi, traversal, brute force, and unknown-route scanning are all excluded from the reflex today — SQLi and traversal because one suspicious request can be a false positive, brute force and unknown-route scanning because they are advisory-only by design. Their evidence flows to telemetry/control plane, which can make a broader policy decision. These small values are for a short academic demonstration, not production guidance.

Repeat Test 7 to verify the live sequence: 1–20 allowed → detector/risk crosses → around request 21 HTTP 403 → decreasing `Retry-After` → HTTP 200 after the TTL.

## Test 23 — Reset Console

### Purpose

Reset the console safely between demonstrations without silently lifting current enforcement.

### Commands

On Dashboard → Settings:

1. Click **Reset console**.
2. Type exactly `reset` in the confirmation dialog.
3. Confirm the toast and the emptied Overview, Events, Campaigns, and History views.

Reset truncates `iasg:events`, `iasg_overrides`, and `iasg_alerts` while preserving their consumer groups; removes `iasg:stats`, `iasg:attackers`, `campaign:*`, `feedback:*`, and `iasg:ip:*`; and truncates Postgres `campaigns` and `feedback`. It deliberately retains `policy:*` and `iasg:heartbeat`.

To lift one active policy immediately, use Dashboard → Policy → **Delete policy** for that address. This deletes the single Redis policy key; an ongoing campaign can recreate it on a later control-plane cycle. The Reset Console `refreshHistory is not a function` error was fixed by publishing `refreshHistory` from the shared live store before the Reset control invokes it.

## Test 24 — Final end-to-end demo

### Purpose

Use this short presentation sequence.

### Commands

```powershell
docker compose -f .\infra\docker-compose.yml up -d
docker compose -f .\infra\docker-compose.yml ps
Start-Process http://localhost:5175
Start-Process http://localhost:5177

curl.exe -i http://localhost:8082/api/products `
  -H "X-Forwarded-For: 198.51.100.91"

# Apply the Test 22 demo values first, then run the short flood.
1..22 | ForEach-Object {
  $code = curl.exe -s -o NUL -w "%{http_code}" http://localhost:8082/api/products `
    -H "X-Forwarded-For: 198.51.100.91"
  Write-Host "$_ -> $code"
}
```

Then show: gateway alert → Events row → `/ip/198.51.100.91` → Campaigns → Policy → agent explanation → decreasing Retry-After and recovery. Optionally finish with Test 20E for the multi-IP story.

## Test 25 — Regression / developer checks

### Purpose

Run the project’s actual developer checks from their owning modules.

### Commands

```powershell
Push-Location .\gateway
go vet ./...
go build ./...
go test ./...
Pop-Location

Push-Location .\control-plane
python -m pytest
Pop-Location

Push-Location .\vulnerable-app\backend
npm test
Pop-Location

Push-Location .\gateway-dashboard
npm run build
Pop-Location
```

The control-plane `pyproject.toml` supplies pytest; use the activated virtual environment’s `python` if one is required locally. Compose itself installs the control-plane runtime packages in its container.

## Test 26 — Security / known-issue checks

### Purpose

Check that telemetry redacts sensitive request fields and that the demo’s intentionally unsafe behavior remains isolated.

### Commands

```powershell
docker compose -f .\infra\docker-compose.yml logs --tail=500 gateway |
  Select-String -Pattern 'password|passwd|secret|token|authorization|snippet|Login attempt'

docker compose -f .\infra\docker-compose.yml exec redis redis-cli XREVRANGE iasg:events + - COUNT 100 |
  Select-String -Pattern 'password|passwd|secret|token|authorization|snippet'

curl.exe -G http://localhost:8082/api/demo-files `
  -H "X-Forwarded-For: 198.51.100.96" `
  --data-urlencode "file=../../../../etc/passwd"
```

Current source behavior: gateway telemetry uses a redacted snippet and masks fields named `password`, `passwd`, `secret`, `token`, and `authorization`; GET requests have no body snippet. The demo backend logs the login **email** but not the password. The only intentional SQL string concatenation is the isolated `/api/products/search` route, and demo file traversal is bounded to `vulnerable-app/backend/demo-files`; an escape request returns 404. No known request-body/password logging issue is present in the current gateway source.

# Quick Command Reference

## Docker

```powershell
docker compose -f .\infra\docker-compose.yml up -d
docker compose -f .\infra\docker-compose.yml ps
docker compose -f .\infra\docker-compose.yml logs --tail=100
docker compose -f .\infra\docker-compose.yml down
```

## Gateway logs

```powershell
docker compose -f .\infra\docker-compose.yml logs -f gateway
docker compose -f .\infra\docker-compose.yml logs --tail=300 gateway |
  Select-String -Pattern 'SECURITY ALERT|enforcement|policy|blocking'
```

## Control-plane logs

```powershell
docker compose -f .\infra\docker-compose.yml logs -f control_plane
docker compose -f .\infra\docker-compose.yml logs --tail=300 control_plane |
  Select-String -Pattern '\[cycle\]|\[correlation\]|\[explain\]|\[policy\]|\[review\]'
```

## Redis

```powershell
docker compose -f .\infra\docker-compose.yml exec redis redis-cli XLEN iasg:events
docker compose -f .\infra\docker-compose.yml exec redis redis-cli XREVRANGE iasg:events + - COUNT 20
docker compose -f .\infra\docker-compose.yml exec redis redis-cli KEYS 'policy:*'
docker compose -f .\infra\docker-compose.yml exec redis redis-cli GET policy:198.51.100.91
docker compose -f .\infra\docker-compose.yml exec redis redis-cli TTL policy:198.51.100.91
```

## Curl / API

```powershell
curl.exe http://localhost:5002/api/products
curl.exe "http://localhost:8082/api/products/search?q=keyboard"
curl.exe -G http://localhost:8082/api/products/search `
  -H "X-Forwarded-For: 198.51.100.92" `
  --data-urlencode "q=' OR 1=1 --"
curl.exe -i -X POST http://localhost:8082/api/login `
  -H "Content-Type: application/json" `
  -H "X-Forwarded-For: 203.0.113.60" `
  -d '{"email":"admin@example.com","password":"definitely-wrong"}'
```

## JMeter

```powershell
docker run --rm --network infra_default `
  -v "${PWD}\testing\jmeter:/tests" `
  justb4/jmeter:latest `
  -n -t /tests/distributed_attack.jmx -JHOST=gateway -JPORT=8082
```

Replace `distributed_attack.jmx` with any of the six checked-in plans listed in Test 20.

## Go tests

```powershell
Push-Location .\gateway
go vet ./...
go build ./...
go test ./...
Pop-Location
```

## Python tests

```powershell
Push-Location .\control-plane
python -m pytest
Pop-Location
```

## Dashboard build

```powershell
Push-Location .\gateway-dashboard
npm run build
Pop-Location
```
