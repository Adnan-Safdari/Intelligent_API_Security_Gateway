# Project structure

| Directory | Purpose |
| --- | --- |
| `gateway/` | Go reverse proxy, detectors, cached-policy enforcement, telemetry, and documentation. |
| `control-plane/` | Python correlation, adaptive baseline/risk decisions, lifecycle, policy writer, and durable storage. |
| `gateway-dashboard/` | Next.js operator console for traffic, campaigns, policies, settings, and adaptive controls. |
| `vulnerable-app/` | Deliberately vulnerable demonstration API protected by the gateway. |
| `infra/` | Docker Compose deployment definitions. |
| `testing/` | Signal and traffic harnesses. |
| `datasets/` | Local captured traffic for offline analysis; not a deployed component. |

The request path is only `gateway/`. The control plane reads evidence and writes
expiring policy keys asynchronously; the dashboard displays and configures that
state without joining the request path.
