# Request Lifecycle

## Overview

A request crosses nine middlewares on the way in and unwinds back through them
on the way out. The order is not incidental — three of the positions were
chosen to fix specific bugs, and moving them would reintroduce those bugs.

## The path in

```mermaid
sequenceDiagram
    participant C as Client
    participant R as Resolver
    participant T as Telemetry
    participant L as Logging
    participant P as Policy enforcer
    participant I as Inspection
    participant D as Detectors
    participant RP as Reverse proxy
    participant B as Backend

    C->>R: HTTP request
    R->>R: Attribute the request to an IP
    R->>T: Pass down with the IP on the context
    T->>L: (records on the way out, not here)
    L->>P: Log method, path, IP
    alt An active policy refuses this IP
        P-->>C: 429 or 403
    else Allowed
        P->>I: Continue
        I->>D: Print headers and body
        D->>D: Flood, SQLi, traversal, brute force
        D->>RP: Evidence recorded per detector
        RP->>B: Forward with X-Gateway: IASG
        B-->>RP: Response
    end
    RP-->>T: Unwinding
    T->>T: Write the event to iasg:events
    T-->>C: Response
```

## Why the order is what it is

### The resolver must come first

Every detector keys its state by client IP, and the control plane writes policy
against that IP. If two components disagree about who the caller is, one of
them is counting the wrong machine.

The resolver settles the question once and puts the answer on the request
context, so everything downstream reads the same value.

### Telemetry sits just inside the resolver

Telemetry has to be outermost-but-one for two different reasons pulling in
opposite directions:

- **Outside the detectors and the enforcer**, so that by the time it records,
  the detectors have run and the enforcer's decision is known. A refused
  request is still written to `iasg:events` — a 403 is a fact worth recording.
- **Inside the resolver**, so it reads the resolved IP.

That second point was a real defect. When telemetry wrapped the resolver
instead, it held the pre-resolution request, recorded the peer address, and
then looked up detector state under that wrong IP. Behind a proxy, every event
recorded `fired: []` and the control plane never saw an attack at all.

### Detectors sit inside the enforcer

A request that the enforcer refuses never reaches a detector, which is correct:
the gateway should not spend pattern-matching work on traffic it has already
decided to drop.

The consequence is that a blocked request produces no new evidence of its own,
and telemetry must not attribute someone else's evidence to it. Request-scoped
detectors therefore record evidence against a request ID, and telemetry asks
for evidence belonging to *this* request. Windowed detectors — flood and brute
force — still report, because their state is genuinely about the window rather
than the individual request.

Without that, a blocked attacker could send harmless traffic and have the
gateway manufacture fresh-looking evidence for it.

## What gets recorded

`telemetry.Middleware` writes one JSON event per request to the `iasg:events`
Redis stream:

| Field | Meaning |
| --- | --- |
| `requestId` | Correlates the event with detector evidence |
| `ts` | When the request finished |
| `ip` | The resolved client IP |
| `method`, `path`, `query` | What was asked for |
| `status` | Final response status |
| `userAgent` | As sent |
| `decision` | `allow`, `throttle`, `temp_block`, or `escalate` |
| `riskScore` | Summarised from the evidence |
| `fired` | Names of the detectors that fired |
| `signals` | The evidence itself |
| `snippet` | A redacted excerpt of what matched |
| `backendMs` | Time spent waiting on the backend |

`internal/telemetry/redact.go` scrubs the snippet before it is stored, so
credentials seen in a request body do not end up in the stream.

## Code references

| Path | Role |
| --- | --- |
| `internal/proxy/server.go` | Assembles the chain; the comment above it records the ordering rationale |
| `internal/proxy/middleware.go` | `ChainMiddleware`, logging, inspection |
| `internal/netutil/ip.go` | Resolver and its middleware |
| `internal/telemetry/middleware.go` | Event construction and `SnapshotFor` |
| `internal/telemetry/redact.go` | Snippet redaction |
| `internal/signals/collector.go` | Routes request-scoped and windowed detectors |
| `internal/policy/middleware.go` | The enforcing middleware |
