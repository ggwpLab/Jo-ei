# Build stage
FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /jo-ei ./cmd/jo-ei
# Stage the cache dir so the runtime mount point is owned by the nonroot user.
RUN mkdir -p /cache

# Runtime stage
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /jo-ei /jo-ei
COPY config.yaml /etc/jo-ei/config.yaml
# Pre-create the cache dir owned by nonroot (UID 65532) so a fresh named volume
# mounted here inherits writable ownership.
COPY --from=builder --chown=65532:65532 /cache /var/cache/jo-ei
EXPOSE 8080
ENTRYPOINT ["/jo-ei", "--config", "/etc/jo-ei/config.yaml"]
