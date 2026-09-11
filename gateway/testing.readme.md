## Docker Commands

docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml logs -f gateway

## Path Traversal Attack Demonstration

A path traversal attack attempts to access directories or files outside the web root by using ../ sequences.

# Using the demo traversal fixture

curl "http://localhost:8082/api/demo-files?file=public%2F..%2Ffake-secret.txt"

## Enumeration / Forced Browsing Attack Demonstration

An enumeration attack attempts to guess or find hidden, sensitive files and directories.

# Trying to access the demo .env fixture

curl http://localhost:8082/.env-demo

# Traversal and enumeration together

curl "http://localhost:8082/.env-demo?file=public%2F..%2Ffake-config.txt"

These are the same requests `testing/signals/traversal.sh` sends — see
[Signal Test Scripts](docs/modules/signal-tests.md) for the full detector
suite and what to look for in the response and logs. Neither request should
be throttled (no `429`); detection is evidence-only.
