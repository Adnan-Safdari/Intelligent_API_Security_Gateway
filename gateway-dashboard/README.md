# Gateway Command Center

The old Express API (`:4004`) and Vite React app were replaced by a **single Next.js app**.

- UI + API routes in one process
- Reads Redis telemetry (`iasg:events`, `iasg:stats`, `iasg:attackers`)
- Polls `/api/overview` every 2 seconds

## Run

Local:

```bash
cd gateway-dashboard
npm install
REDIS_HOST=127.0.0.1 npm run dev
```

Compose: http://localhost:5177

```bash
docker compose -f infra/docker-compose.yml up -d --force-recreate gateway_dashboard
```

Send traffic through the gateway (`bash testing/signals/run_all.sh`) so the live feed has events.
