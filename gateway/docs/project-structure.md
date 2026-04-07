# Project Structure

## Overview

The repository is organized around a small executable entrypoint, the implemented proxy package, support files, and documentation.

## Purpose

This page shows which directories contain active code and which directories currently exist without implementation.

## Architecture Explanation

`cmd/gateway` contains the executable entrypoint. `internal/proxy` contains the implemented server, middleware, and reverse proxy logic. The other directories under `internal/` exist in the repository but do not currently contain Go source files. `configs/` holds the shared YAML configuration used by both local runs and Docker Compose, while `docker-compose.yml` wires the services together.

## Code References

| Path | Role |
| --- | --- |
| `cmd/gateway/` | Executable bootstrap for the gateway binary. |
| `internal/proxy/` | Implemented reverse proxy server and middleware. |
| `internal/context/` | Present in the repository but currently empty. |
| `internal/enforcement/` | Present in the repository but currently empty. |
| `internal/signals/` | Present in the repository but currently empty. |
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
│   └── gateway/
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
│   ├── context/
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