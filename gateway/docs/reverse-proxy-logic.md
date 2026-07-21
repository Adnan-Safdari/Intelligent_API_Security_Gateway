# Reverse Proxy Logic

This document explains how the gateway reverse proxy works, how configuration is loaded, and what happened to the old `internal/context` package.

## What The Gateway Is Doing

The gateway is an HTTP reverse proxy. That means it accepts a request on the gateway port, inspects it with middleware, and then forwards it to a backend API if the request is allowed to continue.

In this project, the gateway runs on `0.0.0.0:8082` inside the container and is published on host port `8082` through Docker Compose.

The backend API in your Docker stack runs on `vulnerable_api:5002`, so requests like `http://localhost:8082/api/health` should reach the gateway first and then be forwarded to the backend.

## Request Flow

The runtime flow starts in `gateway/cmd/server/main.go`:

1. Load YAML configuration from `configs/config.yaml`.
2. Apply `IASG_BACKEND_URL` if it is set in the environment.
3. Build the gateway server configuration.
4. Start the proxy server.

Inside `gateway/internal/proxy/server.go`, the server builds the request pipeline like this:

1. `LoggingMiddleware`
2. `RequestInspectionMiddleware`
3. API flooding detector middleware
4. SQL injection detector middleware
5. Reverse proxy handler

The middleware order matters. The outer middleware sees the request first, and the inner proxy runs last.

## Proxy Package

The main reverse proxy implementation lives in `gateway/internal/proxy/reverse_proxy.go`.

### What it does

- Parses the configured backend URL.
- Creates a `httputil.NewSingleHostReverseProxy` for that backend.
- Configures the outbound HTTP transport with timeout and connection limits.
- Adds the `X-Gateway: IASG` header to proxied requests.

### Why it matters

This is the part that actually forwards traffic to your backend API. The middleware only inspects and logs. The reverse proxy is the component that sends the request onward.

## Middleware Layer

The middleware in `gateway/internal/proxy/middleware.go` does the first layer of request visibility.

### LoggingMiddleware

This logs:

- request method
- request path
- client IP
- user agent

### RequestInspectionMiddleware

This prints:

- all request headers
- the request body, if present

It also restores the request body afterward so the reverse proxy can still forward it.

## Attack Detection Layer

The gateway currently has two detection middlewares in `internal/signals`:

### API Flood Detection

File: `gateway/internal/signals/api_flooding.go`

This tracks request timestamps per IP address in memory.

Behavior:

- groups requests by client IP
- keeps a one minute window
- counts requests in that window
- logs a flood alert if the count goes above the configured threshold
- still allows the request through for now

### SQL Injection Detection

File: `gateway/internal/signals/sqli_injection.go`

This reads the request body and looks for known SQLi signatures such as:

- `' OR`
- `--`
- `UNION`
- ` OR 1=1`

If it finds a match, it logs a formatted alert and still allows the request through.

## Configuration Folder

Yes, the `configs` folder is used.

It contains the runtime YAML that the gateway loads when it starts.

### `configs/config.yaml`

This is the active config used by the gateway in Docker and local runs.

### `configs/config.yaml.example`

This is the template copy you can keep for fresh setups.

### How it is used

`gateway/cmd/server/main.go` calls `config.Load(...)`, which reads the YAML into Go structs defined in `gateway/internal/config/config.go`.

Then `main.go` passes those values into the proxy server:

- listen address
- backend URL
- timeouts
- rate limit config
- attack detection config

So the config folder is not just documentation. It directly controls how the gateway starts and behaves.

## `config.go`

The file `gateway/internal/config/config.go` defines the shape of the YAML config.

It contains Go structs such as:

- `Config`
- `ServerConfig`
- `ProxyConfig`
- `EnforcementConfig`
- `RateLimitConfig`
- `AttackDetectionConfig`

It also contains `Load(path string)`, which:

1. reads the file from disk
2. unmarshals YAML into Go structs
3. fills some defaults
4. validates required fields

So `config.go` is definitely used. It is the bridge between your YAML files and the running gateway.

## About `internal/context`

The old `internal/context` package is not used by the current gateway code.

It contained:

- `RequestContext`
- `BuildRequestContext`
- `NewRequestContext`

But nothing in the live proxy flow imported or called it. The actual runtime middleware path uses request logging, request inspection, flooding detection, SQLi detection, and reverse proxying.

Because it was unused, the package has been removed.

## Current Runtime Summary

The gateway now does exactly this at runtime:

1. Accept the request on port `8082`.
2. Log basic request details.
3. Print headers and body.
4. Detect API flooding and print an alert.
5. Detect SQL injection and print an alert.
6. Forward the request to the backend API on `5002`.

It is currently a detect-and-log gateway, not a blocking gateway.

## If You Want To Extend It Later

Good next steps would be:

- make flood detection and SQLi detection configurable from YAML thresholds
- add a gateway health endpoint
- convert alert logging into structured JSON logs
- add request IDs to every middleware log line
- add unit tests for the proxy middleware chain
