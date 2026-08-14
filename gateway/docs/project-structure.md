# Project Structure

## Overview

The repository is organized around a small executable entrypoint, the implemented proxy package, support files, and documentation.

## Purpose

This page shows which directories contain active code and which directories currently exist without implementation.

## Architecture Explanation

`cmd/server` contains the executable entrypoint. `internal/proxy` contains the implemented server, middleware, and reverse proxy logic. The other directories under `internal/` currently hold support packages or placeholders. `configs/` holds the shared YAML configuration used by both local runs and Docker Compose, while `docker-compose.yml` wires the services together.

## Code References

| Path | Role |
| --- | --- |
| `cmd/server/` | Executable bootstrap for the gateway binary. |
| `internal/proxy/` | Implemented reverse proxy server and middleware. |
| `internal/netutil/` | Shared helpers used by middleware and context-free request handling. |
| `internal/enforcement/` | Present in the repository but currently empty. |
| `internal/signals/` | Attack detectors (flood, SQLi, traversal/enum, brute force). No test files in this package. |
| `testing/signals/` (repo root) | HTTP test scripts that hit a running gateway. See [Signal Test Scripts](modules/signal-tests.md). |
| `internal/storage/` | Present in the repository with empty adapter directories. |
| `internal/trust/` | Present in the repository but currently empty. |
| `configs/` | Contains the shared configuration template and the local runtime config. |
| `docs/` | MkDocs documentation content. |

## Flow Diagram

```mermaid
flowchart TD
    Root[Repository Root] --> Cmd[cmd]
    Root --> Internal[internal]
    Root --> Configs[configs]
    Root --> Docker[docker and compose]
    Root --> Docs[docs]

    Internal --> Proxy[proxy]
    Internal --> Placeholders[other internal directories]
```

## Repository Map

```text
.
├── cmd/
│   └── server/
│       └── main.go
├── configs/
│   ├── config.yaml.example
│   └── config.yaml
├── docker/
├── docs/
│   ├── index.md
│   ├── system-architecture.md
│   ├── request-lifecycle.md
│   ├── running-locally.md
│   ├── project-structure.md
│   ├── javascripts/
│   │   └── mermaid.js
│   └── modules/
│       └── proxy-module.md
├── internal/
│   ├── config/
│   ├── netutil/
│   ├── enforcement/
│   ├── proxy/
│   ├── signals/
│   ├── storage/
│   │   ├── postgres/
│   │   └── redis/
│   └── trust/
├── docker-compose.yml
├── go.mod
└── README.md
```