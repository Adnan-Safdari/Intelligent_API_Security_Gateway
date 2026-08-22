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
- **Admin UI**: `gateway-dashboard/` (Next.js command center on :5177, reads Redis)
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
| **FR2** | Analyze request behavior (detectors → metrics) | **Partial** | Flood + SQLi + Brute Force detect-and-log; brute force has `Metrics(ip)` but no engine consumes it yet |
| **FR3** | Adaptive rate limiting as a **decision outcome** | **Not wired** | Config exists; flood detector only logs; no adaptive limits |
| **FR4** | Risk scoring + centralized decision engine | **Superseded by design** | Scoring is per-detector; decisions are split between the gateway reflex and the control plane. No central engine, and the dead `trust_engine` config has been removed |
| **FR5** | Forward valid / reject blocked / throttle | **Forward only** | Proxy always forwards; no 403/429 enforcement path |
| **FR6** | Logging & monitoring (Postgres + dashboard) | **Partial** | Redis hot telemetry is wired (capped event stream + counters). Postgres history and dashboard UI are not started. |
| **FR7** | Admin configuration (thresholds, detectors, lists) | **Not started** | Static YAML at startup; no live admin API |

**Overall progress estimate:** ~45–55% of the intended product. Proxy + three detect-and-log detectors are done (brute force is the closest to the target metrics pattern); the security brain (scoring, decisions, enforcement, persistence, admin) is still ahead.

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
5. `BruteForceDetector.Middleware` — watches login paths; counts 401/403 failures after proxying; classifies brute force vs password spraying; exposes `Metrics(ip)`; **logs alert; still allows**
6. `NewReverseProxy` — `httputil.NewSingleHostReverseProxy` + `X-Gateway: IASG`

**Current behavior summary:** detect-and-log gateway with three signals. Every request is still forwarded. There is no Allow/Throttle/Block branch yet. Brute force is the first detector with a structured `Metrics()` API for a future decision engine.

### 5.3 Config that is actually used at runtime

Used when building/starting the server:

- `server.*` (host, port, timeouts)
- `proxy.*` (backend_url, timeout, connection limits)
- `enforcement.rate_limit` → flood detector
- `enforcement.attack_detection` → SQLi patterns / enabled flag
- `enforcement.brute_force` → enabled / max_failures / window / login_paths
- `enforcement.enumeration_path_traversal` → traversal/enum detector
- `storage.redis` → hot telemetry (stream, stats, per-IP latest)

Loaded into structs but **not consumed by request handling yet**:

- `storage.postgres`
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
│           ├── sqli_injection.go       # SQLi detect-and-log
│           ├── brute_force.go          # brute force detect-and-log + Metrics()
├── testing/
│   ├── jmeter/                         # JMeter demo plans
│   └── signals/                        # HTTP test scripts for detectors (not in the gateway module)
├── gateway-dashboard/                  # Next.js command center (UI + /api/overview)
│   ├── app/
│   └── lib/
├── vulnerable-app/                     # intentional vulnerable demo API/UI
├── DEMO.md                             # brute force demo guide
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

#### Implemented now

Every detector implements `Name()` + `Metrics(ip) Evidence` (shared contract in `evidence.go`). None of them block. A `Collector` can call `Collect(ip)` / `TotalScore(ip)` for the future decision engine.

| Attack | File | Mechanism | Metrics() | Enforcement |
| --- | --- | --- | --- | --- |
| **API Flooding** | `api_flooding.go` | Per-IP sliding window; threshold = `requests_per_minute` | Yes — `requestRate`, `threshold`, `window`; Score 0–100 | None — logs alert, allows |
| **SQL Injection** | `sqli_injection.go` | Signatures in path, query, and body | Yes — `matchCount`, `matchedPatterns`; last-request evidence per IP | None — logs alert, allows |
| **Path Traversal + Enumeration** | `enumeration_path_traversal.go` | URL/query signatures (`../`, `/.env`, …) | Yes — `pathTraversalDetected`, `enumerationDetected`, match counts | None — logs alert, allows |
| **Brute Force** | `brute_force.go` | Login-path 401/403 failures; spraying vs brute force | Yes — `failedLogins`, `distinctUsers`, `maxFailures` | None — logs alert, allows |

Shared type (`internal/signals/evidence.go`):

```go
type Evidence struct {
    Signal         string         // api_flooding | sql_injection | enumeration_path_traversal | brute_force
    Score          int            // 0-100 contribution
    ThresholdCross bool
    AttackType     string
    Details        map[string]any
}
```

#### Pending / not in current tree

| Attack | Status | Notes |
| --- | --- | --- |
| **Credential Stuffing (dedicated)** | Pending (partial overlap) | Brute force already labels `password_spraying` |
| **XSS** | Deprioritized | Too WAF-like; stay API-centric |

Around all detectors, still pending: centralized decision engine that consumes `Collector.Collect(ip)`, adaptive RL, persistent logging.

**Reference pattern:** `Metrics(ip) Evidence` + never block. `brute_force.go` remains the response-aware example; flood/SQLi/traversal now share the same evidence shape.

Unit tests are **not** stored next to detectors. HTTP test scripts live in `testing/signals/` at the repo root. See [Signal Test Scripts](modules/signal-tests.md).

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

1. **Define a shared metrics / request-security context** (all detectors write into it; brute force `Metrics()` is the template).  
2. **Centralized risk scoring + decision engine** (consume metrics → Allow/Throttle/Block).  
3. **Wire enforcement** in the proxy (403 / 429 / forward) after the engine.  
4. **Refactor flood + SQLi** to expose `Metrics()` like brute force.  
5. **Add missing detectors** (enumeration, path traversal; optional dedicated credential stuffing) as metric producers.  
6. **Connect adaptive rate limiting** to risk bands.  
7. **Persistent structured logging** to Postgres.  
8. **Dashboard** consumption of those logs.  
9. **Admin configuration** API / UI for thresholds without rebuild.  
10. Refresh MkDocs pages so they match the live chain and entrypoint.

---

## 14. Key Implementation Facts for Coding Agents

- Work inside `gateway/` as the Go module root.  
- Do not reintroduce detector-owned hard blocks. Detectors observe and score; blocking belongs to `internal/enforcement` and the control plane.  
- Flood detector comment header mentions blocking with 429, but **implementation currently allows**.  
- There is no trust score and no `trust_engine` config. The model in use is **risk** (higher = worse): each detector emits a 0–100 score, and thresholds are read that way throughout. Do not reintroduce a competing trust-style scale.  
- Compose and Dockerfile expect `./cmd/server`.  
- Healthcheck in Dockerfile hits `/api/health` — that path is expected from the **backend**, not implemented as a gateway-local route today.  
- Prefer extending `internal/signals` (detection) and `internal/enforcement` (action) rather than bloating middleware with one-off blocks. Do not add an `internal/trust` or `internal/decision` package; that layer was considered and deliberately not built.
- Use `brute_force.go` as the reference detector pattern (detect + metrics + never block).

---

## 15. One-Paragraph Absolute Truth

IASG is intended to be an intelligent, behavior-driven API security reverse proxy with detectors feeding a centralized risk/decision engine that can allow, throttle, or block, plus logging, dashboarding, and admin config. **Today** it is a Go reverse proxy on port 8082 that logs requests, inspects bodies, and runs three detect-and-log signals — API flooding, SQL injection, and brute force (with password-spraying classification and a `Metrics(ip)` API) — then always forwards traffic to the configured backend. Config scaffolding for trust scoring, storage, and enforcement exists in YAML, but those subsystems are not yet implemented or wired. Enumeration and path traversal detectors remain pending.
