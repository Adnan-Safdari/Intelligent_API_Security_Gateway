# Build stage
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder
ARG TARGETARCH

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
# Cross-compile on the build host's architecture; emulating arm64 is far slower.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -o gateway ./cmd/server

# Final stage
FROM alpine:3.21

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/gateway .

# Copy configs
COPY configs/ ./configs/

# Create non-root user
RUN addgroup -g 1000 iasg && \
    adduser -D -u 1000 -G iasg iasg && \
    chown -R iasg:iasg /app

USER iasg

EXPOSE 8082

# The gateway answers this path itself, in front of the middleware chain, so
# the probe is never proxied to the backend nor recorded as client traffic.
# /api/health would be: the gateway forwards every path it serves.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8082/__iasg/alive || exit 1

ENTRYPOINT ["./gateway"]
