# Trivy CLI for the Docker registry image scanner (client/server mode).
FROM aquasec/trivy:0.58.0 AS trivy

# Build stage
FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /jo-ei ./cmd/jo-ei
# Stage the cache and database dirs so their runtime mount points are owned by
# the nonroot user.
RUN mkdir -p /cache /db

# Runtime stage
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /jo-ei /jo-ei
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY config.yaml /etc/jo-ei/config.yaml
# Pre-create the cache and database dirs owned by nonroot (UID 65532) so fresh
# named volumes mounted here inherit writable ownership. Without this the
# distroless nonroot process cannot create the SQLite database file and the
# proxy fails to start (telemetry persistence is required).
COPY --from=builder --chown=65532:65532 /cache /var/cache/jo-ei
COPY --from=builder --chown=65532:65532 /db /var/lib/jo-ei
EXPOSE 8080
ENTRYPOINT ["/jo-ei", "--config", "/etc/jo-ei/config.yaml"]
