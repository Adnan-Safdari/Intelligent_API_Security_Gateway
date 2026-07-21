# Project Context: Intelligent API Security Gateway

> Comprehensive handoff document for contributors and other AIs.  
> Combines product intent (SRS / team decisions) with the **actual** repository state as of July 2026.

---

## 1. Overview

**Intelligent API Security Gateway (IASG)** is a capstone project: a **security-focused reverse proxy**, not a full-featured API gateway like Kong, APISIX, or NGINX.

Primary purpose: detect malicious API behavior and dynamically mitigate attacks **before** requests reach the backend. Backend services require **zero modifications**.

```text
                Client
                   │
                   ▼
        Intelligent API Security Gateway
                   │
                   ▼
              Backend API
```

Stack focus:

- **Language**: Go 1.22+
- **Module**: `github.com/Adnan-Safdari/Intelligent_API_Security_Gateway`
- **Core runtime**: `gateway/` (Go reverse proxy)
- **Demo backend**: `vulnerable-app/` (Node API + web)
- **Admin UI (planned/early)**: `gateway-dashboard/` (Node API + web)
- **Compose stack**: `infra/docker-compose.yml`
- **Docs site**: MkDocs (`mkdocs.yml` → `gateway/docs/`)

---

## 2. Problem Statement

Modern apps expose many Internet-facing APIs, expanding the attack surface. Existing approaches have gaps:

| Limitation | Consequence |
| --- | --- |
| Security logic duplicated in each backend | Inconsistent protection, hard to maintain |
| Static rate limits | Cannot separate legitimate spikes from floods |
| Detection separated from mitigation | Alerts without adaptive response |
| Rule-heavy commercial gateways | Static signatures over behavior |
| Little behavior-based security in lightweight self-hosted proxies | Gap for this project |

**Solution direction:** a Go reverse proxy that performs behavior analysis, adaptive rate limiting, unified risk scoring, and intelligent Allow / Throttle / Block decisions.

---

## 3. Main Goal — Intended Request Lifecycle

Every request should follow:

```text
Incoming Request
        │
        ▼
Intercept Request
        │
        ▼
Behavior Analysis (detectors → metrics)
        │
        ▼
Risk Scoring
        │
        ▼
Decision Engine
        │
 ┌──────┼──────────┐
 │      │          │
 ▼      ▼          ▼
Allow Throttle   Block
 │
 ▼
Forward to Backend
```

The backend should only receive requests the decision engine marks as **Allow** (or Allow under throttle policy, depending on how throttle is enforced).

**Important team decision:** detectors must **not** block on their own. They emit metrics; one centralized engine decides.

Preferred AI role (future):

```text
Detectors → Metrics → Risk Scoring → Decision Engine → AI explanation (optional)
```

Not:

```text
AI → Allow / Block
```

---

## 4. Functional Requirements (SRS) vs Status

| ID | Requirement | Status | Reality in code |
| --- | --- | --- | --- |
| **FR1** | Intercept API requests (reverse proxy + middleware) | **Complete** | Working |
| **FR2** | Analyze request behavior (detectors → metrics) | **Partial** | Flood + SQLi detect-and-log; not metrics-to-engine yet |
| **FR3** | Adaptive rate limiting as a **decision outcome** | **Not wired** | Config exists; flood detector only logs; no adaptive limits |
| **FR4** | Risk scoring + centralized decision engine | **Not implemented** | YAML `trust_engine` loaded but unused at runtime |
| **FR5** | Forward valid / reject blocked / throttle | **Forward only** | Proxy always forwards; no 403/429 enforcement path |
| **FR6** | Logging & monitoring (Postgres + dashboard) | **Not started (gateway)** | Console `fmt.Println` / alert banners only |
| **FR7** | Admin configuration (thresholds, detectors, lists) | **Not started** | Static YAML at startup; no live admin API |

**Overall progress estimate:** ~40–50% of the intended product. Proxy + basic detect-and-log are done; the security brain (scoring, decisions, enforcement, persistence, admin) is still ahead.

---

## 5. What Actually Runs Today

### 5.1 Bootstrap

Entrypoint: `gateway/cmd/server/main.go`

1. Load YAML from `IASG_CONFIG` or default `configs/config.yaml`
2. Optional override: `IASG_BACKEND_URL`
3. Build `proxy.Config` from server/proxy/enforcement slices of config
4. `proxy.NewServer(...).Start()`

Docker Compose runs: `go run ./cmd/server` with backend `http://vulnerable_api:5002`, host port **8082**.

### 5.2 Live middleware chain

Order in `gateway/internal/proxy/server.go` (outer → inner):

1. `LoggingMiddleware` — method, path, IP, User-Agent
2. `RequestInspectionMiddleware` — headers + body (body restored for upstream)
3. `FloodDetector.Middleware` — per-IP sliding 1-minute window; **logs alert if over threshold; still allows**
4. `SQLiDetector.Middleware` — body signature match; **logs alert; still allows**
5. `NewReverseProxy` — `httputil.NewSingleHostReverseProxy` + `X-Gateway: IASG`

**Current behavior summary:** detect-and-log gateway. Every request that reaches the proxy is forwarded. There is no Allow/Throttle/Block branch yet.

### 5.3 Config that is actually used at runtime

Used when building/starting the server:

- `server.*` (host, port, timeouts)
- `proxy.*` (backend_url, timeout, connection limits)
- `enforcement.rate_limit` → flood detector
- `enforcement.attack_detection` → SQLi patterns / enabled flag

Loaded into structs but **not consumed by request handling yet**:

- `trust_engine` (thresholds + weights)
- `storage` (postgres / redis)
- `enforcement.throttle` / `enforcement.block`
- `signals.*` (ip reputation, geo, payload, behavioral placeholders)
- `logging.*`

### 5.4 Removed / unused pieces

- `internal/context` (`RequestContext`, builder) — **removed**; was never imported by the live proxy path. Empty `internal/context/` directory may still exist on disk.
- `proxy/security.go` — thin compatibility wrapper that constructs a default SQLi detector; the real wiring is in `server.go`.

---

## 6. Repository Structure (Accurate)

```text
Intelligent_API_Security_Gateway/
├── README.md
├── mkdocs.yml                          # docs site root → gateway/docs
├── infra/
│   └── docker-compose.yml              # full local stack
├── gateway/                            # Go module root
│   ├── cmd/server/main.go              # ONLY gateway entrypoint
│   ├── configs/
│   │   ├── config.yaml                 # active runtime config
│   │   └── config.yaml.example
│   ├── Dockerfile
│   ├── go.mod / go.sum
│   ├── docs/                           # MkDocs content
│   │   ├── index.md
│   │   ├── system-architecture.md      # partly stale
│   │   ├── request-lifecycle.md        # partly stale
│   │   ├── project-structure.md        # partly stale
│   │   ├── running-locally.md          # partly stale paths
│   │   ├── reverse-proxy-logic.md      # most accurate runtime doc
│   │   ├── project-context.md          # THIS file
│   │   └── modules/proxy-module.md
│   └── internal/
│       ├── config/config.go            # YAML → structs + Load()
│       ├── netutil/ip.go               # ClientIP helper
│       ├── proxy/
│       │   ├── server.go               # listen + middleware assembly
│       │   ├── middleware.go           # logging + inspection + ChainMiddleware
│       │   ├── reverse_proxy.go        # upstream forwarder
│       │   └── security.go             # legacy SQLi adapter
│       └── signals/
│           ├── api_flooding.go         # flood detect-and-log
│           └── sqli_injection.go       # SQLi detect-and-log
├── gateway-dashboard/
│   ├── api/                            # Node dashboard API (Compose :4004)
│   └── web/                            # Vite dashboard UI (Compose :5177)
├── vulnerable-app/                     # intentional vulnerable demo API/UI
├── vulnerable-app2/
└── vulnerable-application/
```

**Not present (despite older docs mentioning them):**

- `internal/trust/`
- `internal/enforcement/`
- `internal/storage/` (postgres/redis adapters)
- `signals/enumeration_path_traversal.go` (planned / previously discussed; **not in tree**)

---

## 7. Current Modules (Detailed)

### 7.1 Reverse proxy (`internal/proxy`)

| File | Role |
| --- | --- |
| `server.go` | HTTP server, detector construction, middleware chain |
| `middleware.go` | `ChainMiddleware`, logging, body inspection |
| `reverse_proxy.go` | Single-host reverse proxy + transport limits + gateway header |
| `security.go` | Compatibility SQLi middleware (not used by `Start`) |

### 7.2 Signals (`internal/signals`)

| Detector | Mechanism | Output today | Enforcement |
| --- | --- | --- | --- |
| **API Flooding** | Sharded in-memory per-IP timestamps; 1-minute window; threshold = `requests_per_minute` | Console SECURITY ALERT (LOW/MEDIUM/HIGH by multiples of threshold) | None (allows) |
| **SQL Injection** | Case-insensitive substring match on body vs configured patterns | Console SECURITY ALERT | None (allows) |

**Planned / discussed detectors (not in current tree or not wired):**

- Enumeration / path traversal
- Credential stuffing (discussed as previously worked on elsewhere)
- Brute force
- XSS explicitly **deprioritized** (too WAF-like; stay API-behavior-centric)

### 7.3 Config (`internal/config` + `configs/`)

Bridge from YAML to Go. Validates `server.port` and `proxy.backend_url`. Defaults host to `0.0.0.0` if empty.

### 7.4 Netutil (`internal/netutil`)

`ClientIP(remoteAddr)` strips host:port for IP-keyed detection.

---

## 8. Planned Target Architecture

### 8.1 Detection → metrics (not decisions)

Each detector should return metrics, for example:

```json
{
  "failedLogins": 8,
  "requestRate": 40,
  "enumerationScore": 25,
  "pathTraversalDetected": false,
  "sqliConfidence": 0.8
}
```

Example metric ideas per attack family:

| Family | Example metrics |
| --- | --- |
| API Flooding | request rate, burst size, window |
| Enumeration | sequential IDs, 404 ratio, endpoint discovery |
| Path Traversal | `../`, encoded traversal, depth |
| SQL Injection | keyword matches, payload patterns, confidence |

### 8.2 Centralized decision engine

Conceptual risk score:

```text
Risk Score = Flooding + Enumeration + Traversal + SQLi (+ …)
```

Decision bands (example; exact numbers belong in config):

| Score | Decision |
| --- | --- |
| 0–30 | Allow |
| 30–70 | Throttle |
| 70+ | Block |

Responses:

- **Block** → `403 Forbidden`
- **Throttle** → `429 Too Many Requests` (and/or delayed forwarding per policy)
- **Allow** → forward to backend

### 8.3 Adaptive rate limiting

ARL is **not** a pre-analysis gate and **not** a detector.

Correct:

```text
Analyze → Decision Engine → Throttle (adaptive limits by risk band)
```

Incorrect:

```text
Rate Limit → Analyze
```

Example adaptive bands:

| Risk | Limit |
| --- | --- |
| Low | 100 req/min |
| Medium | 40 req/min |
| High | 5 req/min |
| Blocked | 0 |

### 8.4 Logging (FR6)

Every request, any outcome. Suggested fields:

- Timestamp, IP, Endpoint, HTTP Method  
- Detectors triggered / metrics snapshot  
- Risk score, Decision, Response code  

Storage target: **PostgreSQL** (Compose already runs Postgres on host port **5434**). Redis is available for hot state (Compose **6379**).

Dashboard should later show: volume, allow/block/throttle counts, top attacking IPs, attack mix, risk trends, endpoint stats.

### 8.5 Admin configuration (FR7)

Without recompilation:

- Detector thresholds / enable-disable  
- Adaptive rate-limit bands  
- Risk decision thresholds  
- Whitelist / blacklist  

---

## 9. Docker / Local Ports (Compose)

From `infra/docker-compose.yml`:

| Service | Port |
| --- | --- |
| Gateway API | http://localhost:8082 |
| Vulnerable API | http://localhost:5002 |
| Gateway Dashboard API | http://localhost:4004 |
| Vulnerable Web | http://localhost:5175 |
| Dashboard Web | http://localhost:5177 |
| MkDocs | http://localhost:8000 |
| Postgres (gateway) | localhost:5434 |
| Postgres (vuln API) | localhost:5435 |
| Redis | localhost:6379 |

Gateway env in Compose:

- `IASG_CONFIG=configs/config.yaml`
- `IASG_BACKEND_URL=http://vulnerable_api:5002`

---

## 10. Documentation Status (Important)

| Doc | Accuracy notes |
| --- | --- |
| `reverse-proxy-logic.md` | **Most accurate** for current runtime (detect-and-log, config usage, context removal) |
| `index.md`, `system-architecture.md`, `request-lifecycle.md`, `proxy-module.md` | Stale: still describe only logging+inspection, often cite `cmd/gateway/main.go` (wrong; use `cmd/server`) |
| `project-structure.md` | Stale: lists empty `trust`/`enforcement`/`storage` packages that are not in the tree; omits current `signals` wiring |
| `running-locally.md` | Config guidance useful; entrypoint path outdated |

When docs conflict with code, **trust the Go sources and `reverse-proxy-logic.md`**.

---

## 11. Design Philosophy

- Behavior-aware more than pure signature WAF  
- Detectors produce **evidence**; engine produces **policy**  
- Lightweight, modular, backend-agnostic  
- Suitable as a drop-in security layer in front of existing APIs  
- Stay API-centric (prefer abuse patterns over HTML/XSS WAF features)  
- AI assists explanation/analysis later; does not own Allow/Block  

---

## 12. Meeting Decisions (Locked-in Direction)

1. No per-attack blocking logic ownership — common decision engine only.  
2. Detectors emit metrics; engine combines them.  
3. Agentic AI is a priority research/feature area, but as **assistive explanation**, not the enforcement brain.  
4. Research each attack independently before coding.  
5. After detectors mature: logging → dashboard → risk scoring polish → adaptive rate limiting → admin config.  
6. Refactor detectors from “alert + allow” toward “metrics only,” then wire enforcement once.

---

## 13. Next Development Priorities (Recommended Order)

1. **Define a shared metrics / request-security context** (replace the deleted unused context package with something detectors actually write into).  
2. **Centralized risk scoring + decision engine** (consume metrics → Allow/Throttle/Block).  
3. **Wire enforcement** in the proxy (403 / 429 / forward) after the engine.  
4. **Refactor flood + SQLi** to emit scores/metrics instead of owning “allow forever.”  
5. **Add missing detectors** (enumeration, path traversal, brute force / credential stuffing) as metric producers.  
6. **Connect adaptive rate limiting** to risk bands.  
7. **Persistent structured logging** to Postgres.  
8. **Dashboard** consumption of those logs.  
9. **Admin configuration** API / UI for thresholds without rebuild.  
10. Refresh MkDocs pages so they match the live chain and entrypoint.

---

## 14. Key Implementation Facts for Coding Agents

- Work inside `gateway/` as the Go module root.  
- Do not reintroduce detector-owned hard blocks; route through a future decision engine.  
- Flood detector comment header mentions blocking with 429, but **implementation currently allows**.  
- `trust_engine` thresholds in YAML are currently inverted-looking vs the SRS example bands (YAML uses block=20, throttle=50, allow=80 as “trust” style). When implementing the engine, reconcile naming: **risk score** (higher = worse) vs **trust score** (higher = safer) and pick one model.  
- Compose and Dockerfile expect `./cmd/server`.  
- Healthcheck in Dockerfile hits `/api/health` — that path is expected from the **backend**, not implemented as a gateway-local route today.  
- Prefer extending `internal/signals` + new `internal/trust` or `internal/decision` packages rather than bloating middleware with one-off blocks.

---

## 15. One-Paragraph Absolute Truth

IASG is intended to be an intelligent, behavior-driven API security reverse proxy with detectors feeding a centralized risk/decision engine that can allow, throttle, or block, plus logging, dashboarding, and admin config. **Today** it is a Go reverse proxy on port 8082 that logs requests, inspects bodies, runs in-memory flood detection and SQLi signature detection as **alerts only**, and always forwards traffic to the configured backend. Config scaffolding for trust scoring, storage, and enforcement exists in YAML, but those subsystems are not yet implemented or wired.
