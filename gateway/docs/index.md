# Intelligent API Security Gateway

## Overview

The system sits in front of an HTTP API and decides, per request, whether that
request should be allowed, slowed down, or refused. It is built as **two
independent lanes**:

- **The data plane** — a Go reverse proxy that every request passes through. It
  runs on a microsecond budget, so it only ever does work that is cheap and
  bounded: match a pattern, increment a counter, read a map.
- **The control plane** — a Python agent that runs on a timer, off the request
  path. It reads what the gateway saw, groups related activity into campaigns,
  and decides what should be done about them.

The two lanes never call each other. They communicate only through Redis: the
gateway writes evidence, the control plane writes policy. Either one can be
stopped without taking the other down, which is the point — an agent that
crashes must not be able to take the API offline with it.

## Why the split

Anything that reasons about an attack needs history, and history takes time to
read. Doing that inside a request would put a network round trip — or an LLM
call — between a user and their response. Doing it on a timer instead means the
expensive thinking happens once every 30 seconds, and the request path only
pays for a map lookup.

The cost is delay: a decision reaches the gateway up to one refresh interval
after it is made. That is an acceptable trade for keeping the proxy fast and
keeping it independent.

## What each lane does

| Lane | Runs | Responsibility |
| --- | --- | --- |
| Gateway (`gateway/`) | Per request | Resolve the client IP, detect known attack shapes, enforce active policy, forward to the backend, record what happened |
| Control plane (`control-plane/`) | Every 30s | Read evidence, cluster it into campaigns, choose an action, write time-bounded policy |
| Dashboard (`gateway-dashboard/`) | On demand | Show live traffic, campaigns, and policy; let an operator override the agent |

## Request path

Every request crosses nine middlewares before reaching the backend. The order
is deliberate and is documented in [Request Lifecycle](request-lifecycle.md).

```mermaid
flowchart LR
    Client[Client] --> Resolver[Client IP resolver]
    Resolver --> Telemetry[Telemetry recorder]
    Telemetry --> Logging[Logging]
    Logging --> Policy[Policy enforcement]
    Policy -->|refused| Client
    Policy --> Inspect[Request inspection]
    Inspect --> Detectors[Five detectors]
    Detectors --> Proxy[Reverse proxy]
    Proxy --> Backend[Backend API]
    Backend --> Client
```

## The feedback loop

What makes this more than a pattern matcher is that the two lanes form a cycle.
The gateway's observations become the control plane's input, and the control
plane's decisions become the gateway's behaviour on the next refresh.

```mermaid
flowchart LR
    GW[Gateway] -->|evidence: iasg:events| Redis[(Redis)]
    Redis -->|reads stream| CP[Control plane]
    CP -->|policy:ip with a TTL| Redis
    Redis -->|snapshot every 5s| GW
    CP -->|campaigns| PG[(Postgres)]
    PG --> Dash[Dashboard]
    Redis --> Dash
    Dash -->|operator override| Redis
```

Enforcement releases itself. Every policy key carries a TTL, and nothing
renews one, so an action expires on its own unless the behaviour that caused
it happens again. See [Policy Enforcement](policy-enforcement.md).

## Where to go next

| Page | What it covers |
| --- | --- |
| [System Architecture](system-architecture.md) | The runtime structure of both lanes |
| [Request Lifecycle](request-lifecycle.md) | The middleware chain and why it is ordered as it is |
| [Detection Signals](detection-signals.md) | The five detectors and the evidence they produce |
| [Policy Enforcement](policy-enforcement.md) | How the gateway acts on the control plane's decisions |
| [Control Plane](control-plane.md) | The agent cycle, campaigns, and the escalation ladder |
| [Identifying the Client](client-ip.md) | Why the attributed IP is the foundation of everything else |
| [Running Locally](running-locally.md) / [Running with Docker](running-with-docker.md) | Getting it started |
