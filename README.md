
# Intelligent API Security Gateway

A smart API gateway that uses trust scoring and adaptive enforcement to protect backend APIs from malicious traffic.

## Prerequisites

- Docker and Docker Compose
- Go 1.22.2 or higher (for local development)

## Quick Start

### 1. Clone and Setup

```bash
# Navigate to project directory
cd Intelligent_API_Security_Gateway

# Copy environment file
cp .env.example .env

# Copy configuration file
cp configs/config.yaml.example configs/config.yaml
```

### 2. Configure

Edit `.env` if you want to change default credentials:

```
POSTGRES_USER=iasg_user
POSTGRES_PASSWORD=iasg_password
POSTGRES_DB=iasg_db
```

Edit `configs/config.yaml` to configure:

- Backend API URL to protect
- Trust scoring thresholds
- Rate limiting rules
- Database connections

### 3. Start Services

```bash
# Start PostgreSQL and Redis
docker compose up -d

# Verify services are running
docker ps
```

### 4. Run the Gateway

```bash
# Install Go dependencies
go mod download

# Run the gateway
go run cmd/gateway/main.go
```

The gateway will start on `http://localhost:8080` (or the port specified in your config).

## Architecture

- **Trust Engine**: Scores requests based on multiple signals
- **Enforcement**: Applies adaptive policies (block, throttle, allow)
- **Storage**: PostgreSQL for persistent data, Redis for caching
- **Proxy**: Forwards legitimate traffic to backend API

## Development

```bash
# Run tests
go test ./...

# List all packages
go list ./...

# Build binary
go build -o gateway cmd/gateway/main.go
```

## Stopping Services

```bash
docker compose down
```
