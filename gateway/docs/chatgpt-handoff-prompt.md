# ChatGPT Handoff Prompt — Intelligent API Security Gateway

Copy everything below the line into ChatGPT as the project context / system prompt.

---

You are helping me develop a university/capstone software project called **Intelligent API Security Gateway (IASG)**.

Read this entire brief carefully. Treat it as the single source of truth. Some older docs in the repo are stale; where docs conflict with the “IMPLEMENTED NOW” section below, trust the implemented reality.

Your job when I ask for help:
- Respect the intended architecture (detectors → metrics → risk scoring → decision engine → allow/throttle/block).
- Do not invent that unfinished subsystems already exist.
- Prefer Go code that fits the current module layout under `gateway/`.
- Never make detectors directly own final block/allow decisions; they should eventually emit metrics into a centralized decision engine.
- Keep suggestions API-security / behavior-analysis focused (not a full Kong/APISIX clone, not a classic HTML WAF).

================================================================================
1. PROJECT IDENTITY
================================================================================

Name: Intelligent API Security Gateway (IASG)
Type: Capstone / academic software project
Language (gateway): Go 1.22+
Go module path: github.com/Adnan-Safdari/Intelligent_API_Security_Gateway
Primary code root: gateway/

What it is:
- A security-focused HTTP reverse proxy that sits in front of backend APIs.
- Goal: detect malicious API behavior and eventually mitigate (allow / throttle / block) before traffic reaches the backend.
- Backend services must require ZERO modifications.

What it is NOT:
- Not a full-featured API gateway like Kong, Apache APISIX, or NGINX (no heavy routing/plugins product surface).
- Not meant to become a generic web application firewall focused on XSS/HTML page protection.
- Stay API-centric: flooding, enumeration, injection in API payloads, credential abuse, path traversal against APIs, etc.

High-level placement:

    Client
      │
      ▼
    Intelligent API Security Gateway  (port 8082)
      │
      ▼
    Backend API  (demo: vulnerable_api on port 5002)

================================================================================
2. PROBLEM STATEMENT
================================================================================

Modern apps expose many Internet-facing APIs, increasing attack surface.

Existing approaches have gaps:
1. Security logic is duplicated across backend services.
2. Static rate limiting cannot distinguish legitimate spikes from attacks.
3. Detection and mitigation are often separated.
4. Many gateways rely on static rules/signatures.
5. Intelligent behavior-based security is uncommon in lightweight self-hosted proxies.

Our solution direction:
A Go reverse proxy that performs behavior analysis, adaptive rate limiting, unified risk scoring, and intelligent request decisions (Allow / Throttle / Block).

================================================================================
3. INTENDED ARCHITECTURE (TARGET — NOT FULLY BUILT YET)
================================================================================

Intended request lifecycle:

    Incoming Request
            │
            ▼
    Intercept Request (reverse proxy + middleware)
            │
            ▼
    Behavior Analysis (detectors produce METRICS, not final decisions)
            │
            ▼
    Risk Scoring (combine detector metrics into one score)
            │
            ▼
    Decision Engine (centralized)
            │
     ┌──────┼──────────┐
     │      │          │
     ▼      ▼          ▼
   Allow  Throttle   Block
     │
     ▼
   Forward to Backend

Critical team decisions (LOCKED IN):
1. Detectors must NOT independently block requests.
2. Every detector emits metrics/evidence only.
3. One centralized Decision Engine chooses Allow / Throttle / Block.
4. Adaptive Rate Limiting is an ENFORCEMENT OUTCOME of the decision engine, not a pre-analysis gate.
5. Future “Agentic AI” may explain or assist analysis, but must NOT be the thing that directly decides Allow/Block.
   Preferred: Detectors → Metrics → Risk Scoring → Decision Engine → optional AI explanation
   Rejected: AI → Allow/Block

Example detector metrics (illustrative JSON):

{
  "failedLogins": 8,
  "requestRate": 40,
  "enumerationScore": 25,
  "pathTraversalDetected": false,
  "sqliConfidence": 0.8
}

Example risk model (illustrative):
Risk Score = Flooding + Enumeration + Traversal + SQLi (+ others)

Example decision bands (risk-style, higher = worse):
- 0–30  → Allow
- 30–70 → Throttle
- 70+   → Block

Intended HTTP outcomes:
- Allow    → proxy/forward to backend
- Throttle → 429 Too Many Requests (and/or delayed forwarding)
- Block    → 403 Forbidden

Adaptive rate limiting example (by risk band):
- Low risk     → 100 req/min
- Medium risk  → 40 req/min
- High risk    → 5 req/min
- Blocked      → 0

Correct ARL flow:
  Analyze → Decision Engine → Throttle

Incorrect ARL flow:
  Rate Limit first → then Analyze

================================================================================
4. FUNCTIONAL REQUIREMENTS (SRS) AND STATUS
================================================================================

FR1 — Intercept API Requests
- Requirement: gateway receives every request before backend.
- Implementation idea: reverse proxy + middleware chain.
- STATUS: COMPLETE / WORKING.

FR2 — Analyze Request Behavior
- Requirement: detectors examine flooding, enumeration, path traversal, SQLi, brute force, etc. and return metrics.
- STATUS: PARTIAL (improved).
- Reality: API Flooding + SQL Injection + Brute Force exist and DETECT AND LOG.
  Brute Force ALSO exposes a Metrics(ip) API (failedLogins, distinctUsers, thresholdCross, attackType)
  but nothing yet consumes those metrics into a shared decision engine.

FR3 — Adaptive Rate Limiting
- Requirement: adaptive limits as a decision outcome.
- STATUS: COMPLETE.
- Reality: enforcement.rate_limit.enforce (off by default) makes rate_limit.requests_per_minute a baseline every non-exempt address is held to. The control plane picks a per-minute allowance from campaign severity (high 20, otherwise 50) and writes it as requests_per_minute in policy:<ip>; that replaces the baseline for that address, tighter or looser. policy.Limiter counts over a sliding minute and answers 429 with Retry-After. Exemptions reuse block.exempt_cidrs. Recovery is the policy TTL lapsing, which returns the address to the baseline in one step.

FR4 — Risk Scoring & Decision Engine
- Requirement: centralized scoring + Allow/Throttle/Block.
- STATUS: SUPERSEDED BY DESIGN — do not build this.
- Reality: scoring is per-detector (0-100); acting on it is split between internal/enforcement in the gateway and the Python control plane. The trust_engine YAML block was loaded into Go structs that nothing read, and has been deleted.

FR5 — Forward Valid Requests / Enforce Decisions
- Requirement: only safe requests reach backend; blocked=403; throttled=429.
- STATUS: FORWARD-ONLY.
- Reality: every request that passes middleware is always proxied. No 403/429 enforcement path exists yet.

FR6 — Logging & Monitoring
- Requirement: persistent logs (Postgres) + dashboard metrics.
- STATUS: NOT STARTED in the gateway.
- Reality: console fmt.Println / banner alerts only. Compose runs Postgres/Redis and a separate dashboard app, but gateway does not write security decision logs to DB yet.

FR7 — Admin Configuration
- Requirement: change thresholds, enable/disable detectors, whitelist/blacklist without recompilation.
- STATUS: NOT STARTED.
- Reality: static YAML at process start only.

Overall completion estimate: roughly 45–55% of the intended product.
Done: reverse proxy foundation + three detect-and-log detectors (flood, SQLi, brute force); brute force already has a Metrics() API.
Missing: metrics bus/context that all detectors write into, risk engine that consumes Metrics(), enforcement, adaptive RL, persistent logging, admin config, remaining detectors (enumeration, path traversal).

================================================================================
5. WHAT IS IMPLEMENTED RIGHT NOW (GROUND TRUTH)
================================================================================

5.1 Entrypoint / bootstrap
File: gateway/cmd/server/main.go

Runtime startup steps:
1. Read config path from env IASG_CONFIG, else default "configs/config.yaml"
2. Load YAML via internal/config.Load
3. If IASG_BACKEND_URL is set, override proxy.backend_url
4. Build listen address from server.host + server.port
5. Create proxy.NewServer(...) with:
   - ListenAddr, BackendURL
   - Read/Write/Idle timeouts
   - ProxyTimeout, MaxIdleConns, MaxConnsPerHost
   - RateLimit (from enforcement.rate_limit)
   - AttackDetection (from enforcement.attack_detection)
   - BruteForce (from enforcement.brute_force)
6. server.Start()

NOTE: Some older docs say cmd/gateway/main.go. That is WRONG.
Correct entrypoint is ALWAYS: gateway/cmd/server/main.go
Docker Compose command: go run ./cmd/server

5.2 Live middleware chain (outer → inner)
File: gateway/internal/proxy/server.go

1. LoggingMiddleware
   - prints Method, Path, IP, User-Agent
2. RequestInspectionMiddleware
   - prints all headers
   - reads body if present, prints it
   - restores body with io.NopCloser so upstream can still read it
3. FloodDetector.Middleware (internal/signals/api_flooding.go)
   - per-IP sliding window (1 minute)
   - sharded in-memory maps (32 shards) to reduce lock contention
   - threshold = config enforcement.rate_limit.requests_per_minute
   - if over threshold: print SECURITY ALERT (severity LOW/MEDIUM/HIGH), THEN STILL ALLOW
   - background cleanup ticker every 5 minutes
4. SQLiDetector.Middleware (internal/signals/sqli_injection.go)
   - reads/restores body
   - case-insensitive substring match against configured sql_patterns
   - default/example patterns: "' OR", "--", "UNION", " OR 1=1"
   - if match: print SECURITY ALERT, THEN STILL ALLOW
5. BruteForceDetector.Middleware (internal/signals/brute_force.go)
   - sits CLOSEST to the reverse proxy because it must observe BACKEND response status
   - only watches configured login paths (default /api/login)
   - wraps ResponseWriter, forwards request, then inspects status:
       401/403 → record failed login for that IP (+ optional email from JSON body)
       2xx     → reset failure history for that IP
   - if failures >= max_failures inside window: print SECURITY ALERT, STILL ALLOWS
   - classifies classic brute_force vs password_spraying (distinct emails > 3)
   - exposes Metrics(ip) → {failedLogins, distinctUsers, thresholdCross, attackType}
   - demo docs: DEMO.md + testing/jmeter/brute_force_demo.jmx + testing/signals/brute_force.sh
6. NewReverseProxy (internal/proxy/reverse_proxy.go)
   - httputil.NewSingleHostReverseProxy(backend)
   - transport timeouts / idle conn limits
   - sets request header X-Gateway: IASG
   - forwards to backend

ONE-SENTENCE RUNTIME TRUTH:
Today this is a detect-and-log reverse proxy with three signals (flood, SQLi, brute force). It always forwards. It does not block or throttle yet. Brute force is the first detector that also exposes a Metrics() API for a future decision engine.

5.3 Implemented packages/files that matter

gateway/cmd/server/main.go
- process bootstrap + config wiring

gateway/internal/config/config.go
- YAML mapping structs for entire planned config surface
- Load(path) reads/unmarshals/validates server.port and proxy.backend_url
- defaults host to 0.0.0.0 if empty

gateway/configs/config.yaml
- active runtime config used by local/Docker runs

gateway/configs/config.yaml.example
- template copy

gateway/internal/proxy/server.go
- Server type, NewServer, Start, middleware assembly, detector construction

gateway/internal/proxy/middleware.go
- Middleware type
- ChainMiddleware (applies in reverse so listed order is outer→inner)
- LoggingMiddleware
- RequestInspectionMiddleware

gateway/internal/proxy/reverse_proxy.go
- NewReverseProxy + Director mutation for X-Gateway header

gateway/internal/proxy/security.go
- legacy compatibility wrapper that builds a default SQLi detector
- NOT used by Server.Start (real wiring is in server.go)

gateway/internal/signals/api_flooding.go
- FloodDetector implementation (detect-and-log)

gateway/internal/signals/sqli_injection.go
- SQLiDetector implementation (detect-and-log)

gateway/internal/signals/brute_force.go
- BruteForceDetector (detect-and-log + Metrics(ip) API)
- Distinguishes brute_force vs password_spraying
- Never blocks (team decision)

DEMO.md
- Brute force demo guide (curl, JMeter, testing/signals scripts)

testing/signals/
- HTTP test scripts for flood, SQLi, traversal/enum, brute force (outside the gateway module)

testing/jmeter/brute_force_demo.jmx + passwords.csv
- JMeter plan for dictionary-style login attempts

gateway/internal/netutil/ip.go
- ClientIP(remoteAddr): strips host:port for IP tracking

5.4 Config fields USED at runtime vs ONLY LOADED

USED by live request path / server start:
- server.host, server.port, read_timeout, write_timeout, idle_timeout
- proxy.backend_url, timeout, max_idle_conns, max_conns_per_host
- enforcement.rate_limit.enabled / requests_per_minute / burst (burst currently not meaningfully used by flood detector logic)
- enforcement.attack_detection.enabled / sql_patterns
- enforcement.brute_force.enabled / max_failures / window / login_paths

LOADED into structs but NOT consumed by request handling yet:
- storage.redis / storage.postgres
- enforcement.throttle / enforcement.block
- signals.ip_reputation / geo_location / payload_analysis / behavioral
- logging.level / format / output

IMPORTANT SCORE MODEL AMBIGUITY:
YAML currently looks like a TRUST score model (higher allow_threshold=80 means safer):
  block_threshold: 20
  throttle_threshold: 50
  allow_threshold: 80
SRS narrative often uses RISK score (higher = worse):
  allow < 30, throttle 30–70, block > 70
When implementing the engine, explicitly choose ONE model (risk vs trust) and rename consistently.

5.5 Attack detection inventory — IMPLEMENTED vs PENDING

This is the explicit attack-detection checklist for the project.

---------------------------------------------------------------------------
A) IMPLEMENTED NOW (wired into the live middleware chain)
---------------------------------------------------------------------------

| Attack | File | How it works today | Structured Metrics() API? | Consumed by decision engine? | Blocks / throttles? | Status detail |
| --- | --- | --- | --- | --- | --- | --- |
| API Flooding | gateway/internal/signals/api_flooding.go | Per-IP in-memory sliding 1-minute window; threshold = requests_per_minute; sharded maps; severity LOW/MEDIUM/HIGH | NO | NO | NO — logs alert then allows | Detect-and-log only |
| SQL Injection | gateway/internal/signals/sqli_injection.go | Reads request body; case-insensitive substring match vs configured sql_patterns ("' OR", "--", "UNION", " OR 1=1", etc.) | NO | NO | NO — logs alert then allows | Detect-and-log only; signature-based |
| Brute Force (+ password spraying classification) | gateway/internal/signals/brute_force.go | Watches login paths only; counts 401/403 failures per IP in a sliding window; success (2xx) resets; classifies classic brute_force vs password_spraying when distinct emails > 3 | YES — Metrics(ip) returns failedLogins, distinctUsers, thresholdCross, attackType | NO (engine not built yet) | NO — logs alert then allows | Newest detector; closest to target architecture; has unit tests + DEMO.md + JMeter plan |

Config for brute force (USED at runtime), from enforcement.brute_force:
  enabled: true
  max_failures: 5
  window: 60s
  login_paths: ["/api/login"]

Notes on implemented detectors:
- All three are middleware in internal/signals and registered in proxy/server.go.
- None feeds a centralized risk/decision engine yet (engine does not exist).
- Flood + SQLi only print console SECURITY ALERT banners (no Metrics() API yet).
- Brute force ALSO has Metrics(ip) ready for a future engine, but nothing calls it in the live request path today except tests / potential future wiring.
- Flood detector file comments historically mentioned 429 blocking, but the code currently ALWAYS allows.
- Brute force originally briefly had lockout/429 in an early commit, then was REFACTORED to detect-only to match team architecture (PR #6 / commits ed73e12 → 521ca3e → 3d9828b → 33a1e1a).
- SQLi currently inspects BODY only.
- Brute force observes RESPONSE status after proxying (response-aware middleware).

---------------------------------------------------------------------------
B) PENDING / NOT IN CURRENT CODEBASE (planned or discussed)
---------------------------------------------------------------------------

| Attack | Planned idea / metrics | In repo tree? | Wired? | Priority notes |
| --- | --- | --- | --- | --- |
| Enumeration | Sequential IDs, 404 ratio, endpoint discovery score | NO | NO | Planned API-behavior detector |
| Path Traversal | Detect "../", encoded traversal, traversal depth in paths/params | NO (old mention of enumeration_path_traversal.go is gone / never wired) | NO | Planned; often paired with enumeration research |
| Credential Stuffing (dedicated) | High-volume credential list attacks / known-breach password reuse patterns | NO dedicated module | PARTIAL overlap | Brute force detector already classifies password_spraying (many usernames); a fuller credential-stuffing detector is still pending |
| XSS | Script payloads in inputs | NO | NO | INTENTIONALLY DEPRIORITIZED — too WAF/HTML-like; stay API-centric |

Also pending around detection (not a specific attack, but required for all detectors):
- Shared request metrics/context object that ALL detectors write into (brute force Metrics() is a template for this)
- Refactor flood + SQLi to expose Metrics() like brute force
- Centralized risk scoring that consumes those metrics
- Decision engine Allow/Throttle/Block
- Adaptive rate limiting as an enforcement outcome
- Persistent logging of which attack signals fired

---------------------------------------------------------------------------
C) QUICK SUMMARY FOR CHATGPT
---------------------------------------------------------------------------

Implemented attacks right now:
1. API Flooding — yes (alert only; no Metrics() API yet)
2. SQL Injection — yes (alert only; no Metrics() API yet)
3. Brute Force — yes (alert only + Metrics(ip) API; also classifies password spraying; never blocks)

Pending attacks:
1. Enumeration — pending
2. Path Traversal — pending
3. Dedicated Credential Stuffing — pending (partial overlap via password_spraying label in brute force)

Out of scope / deprioritized:
1. XSS — deliberately not pursuing as a core detector

When I say “add attack detection”, assume new detectors should emit metrics only, not hard-block by themselves. Follow the brute_force.go pattern as the reference implementation.

5.6 What was removed / does not exist (packages)

Removed:
- internal/context package (RequestContext / builder). It was unused by the live proxy path and deleted.
  An empty internal/context/ directory may still exist on disk.

Not present in the tree (despite some older docs mentioning them):
- internal/trust/
- internal/enforcement/
- internal/storage/ (postgres/redis adapters)
- signals/enumeration_path_traversal.go

================================================================================
6. REPOSITORY STRUCTURE (MONOREPO)
================================================================================

Intelligent_API_Security_Gateway/
├── README.md
├── mkdocs.yml                         # docs site; docs_dir = gateway/docs
├── infra/
│   └── docker-compose.yml             # full local stack
├── gateway/                           # Go module root for the security proxy
│   ├── cmd/server/main.go
│   ├── configs/config.yaml[.example]
│   ├── Dockerfile
│   ├── go.mod / go.sum
│   ├── docs/                          # MkDocs content
│   └── internal/
│       ├── config/
│       ├── netutil/
│       ├── proxy/
│       └── signals/
│           ├── api_flooding.go
│           ├── sqli_injection.go
│           ├── brute_force.go
├── testing/
│   ├── jmeter/
│   └── signals/                       # HTTP detector test scripts (outside gateway)
├── gateway-dashboard/
│   ├── api/                           # Node dashboard API (Compose :4004)
│   └── web/                           # Vite dashboard UI (Compose :5177)
├── vulnerable-app/                    # intentional vulnerable demo API + web
├── DEMO.md                            # Brute force detection demo guide
├── testing/jmeter/                    # JMeter plans (brute_force_demo.jmx, passwords.csv)
├── vulnerable-app2/
└── vulnerable-application/

Docs under gateway/docs/:
- index.md
- system-architecture.md
- request-lifecycle.md
- project-structure.md
- running-locally.md
- reverse-proxy-logic.md          ← most accurate older runtime doc
- project-context.md              ← reconciled vision + reality
- modules/proxy-module.md
- chatgpt-handoff-prompt.md       ← this file

DOC DRIFT WARNING:
Several MkDocs pages are stale. They often:
- cite cmd/gateway/main.go (wrong)
- describe only Logging + Inspection (omit flood/SQLi middlewares)
- claim hardcoded config (now YAML-driven)
- list empty trust/enforcement/storage packages that are not in the tree
When uncertain, prefer: actual Go code + reverse-proxy-logic.md + project-context.md

================================================================================
7. DOCKER COMPOSE / PORTS / LOCAL RUN
================================================================================

Compose file: infra/docker-compose.yml

Ports:
- Gateway API:            http://localhost:8082
- Vulnerable API:         http://localhost:5002
- Gateway Dashboard API:  http://localhost:4004
- Vulnerable Web:         http://localhost:5175
- Dashboard Web:          http://localhost:5177
- MkDocs:                 http://localhost:8000
- Postgres (gateway):     localhost:5434
- Postgres (vuln API):    localhost:5435
- Redis:                  localhost:6379

Gateway service env:
- IASG_CONFIG=configs/config.yaml
- IASG_BACKEND_URL=http://vulnerable_api:5002

Local run (from gateway module directory):
  go mod download
  go run ./cmd/server

Or via Compose from infra/.

Dockerfile builds ./cmd/server and exposes 8082.
Healthcheck probes /api/health — that is expected to be satisfied by the PROXIED BACKEND, not a gateway-local route today.

================================================================================
8. EXAMPLE ACTIVE CONFIG (SIMPLIFIED FROM configs/config.yaml)
================================================================================

server:
  port: 8082
  host: 0.0.0.0
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s

proxy:
  backend_url: "http://localhost:5002"
  timeout: 30s
  max_idle_conns: 100
  max_conns_per_host: 10

storage:               # loaded, unused at runtime
  redis: ...
  postgres: ...

enforcement:
  rate_limit:          # USED by flood detector
    enabled: true
    requests_per_minute: 100
    burst: 20
  attack_detection:    # USED by SQLi detector
    enabled: true
    sql_patterns: ["' OR", "--", "UNION", " OR 1=1"]
  brute_force:         # USED by brute force detector
    enabled: true
    max_failures: 5
    window: 60s
    login_paths: ["/api/login"]
  throttle:            # loaded, unused
    enabled: true
    delay_ms: 500
  block:               # loaded, unused
    enabled: true
    duration: 300s

signals: ...           # loaded placeholders, unused
logging: ...           # loaded, unused by current fmt logging

================================================================================
9. DESIGN PHILOSOPHY
================================================================================

- Behavior-aware more than pure signature WAF.
- Detectors produce evidence; engine produces policy.
- Lightweight, modular, backend-agnostic drop-in security layer.
- Stay API-centric.
- AI is optional future assistance for explanation/analysis, not enforcement ownership.
- Prefer extending internal/signals and adding something like internal/decision or internal/trust, instead of scattering one-off blocks in middleware.

================================================================================
10. RECOMMENDED NEXT IMPLEMENTATION ORDER
================================================================================

1. Shared per-request security/metrics context that detectors write into.
2. Centralized risk/trust scoring + decision engine (Allow/Throttle/Block) that consumes Metrics().
3. Enforcement wiring in proxy (403 / 429 / forward) after the engine.
4. Refactor flood + SQLi to expose Metrics() the same way brute_force.go already does.
5. Add more detectors as metric producers (enumeration, path traversal; optional dedicated credential stuffing).
6. Connect adaptive rate limiting to risk bands.
7. Persistent structured logging to PostgreSQL.
8. Dashboard consumption of those logs.
9. Admin configuration API/UI for thresholds without rebuild.
10. Refresh MkDocs pages so they match the live chain and entrypoint.

Use brute_force.go as the reference pattern for new detectors:
- detect evidence
- log SECURITY ALERT
- expose Metrics(...)
- NEVER hard-block in the detector itself

================================================================================
11. HOW YOU SHOULD ANSWER ME
================================================================================

When proposing code or architecture:
- Explicitly say whether a piece is ALREADY IMPLEMENTED or PROPOSED/NEXT.
- Preserve the detect→metrics→engine→enforce separation.
- Use correct paths (cmd/server, internal/proxy, internal/signals, internal/config).
- Do not assume trust engine / storage adapters / enumeration detector already exist.
- Prefer incremental changes that fit the current detect-and-log middleware chain.
- Prefer the brute force detector's Metrics() pattern when extending signals.
- Call out config score-model ambiguity (risk vs trust) before implementing thresholds.
- Keep explanations concrete and implementation-oriented.

If I ask “what exists today?”, summarize:
“Go reverse proxy on :8082 with logging, body inspection, and three detect-and-log signals: API flooding, SQL injection, and brute force (with password-spraying classification and a Metrics(ip) API). YAML config loading is wired. All requests are still unconditionally forwarded. No decision engine, no adaptive enforcement, no persistent security logging, no admin config yet. Enumeration and path traversal detectors are still pending.”

End of project context.
