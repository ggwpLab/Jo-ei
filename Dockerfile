# Build stage
FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /sca-proxy ./cmd/sca-proxy

# Runtime stage
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /sca-proxy /sca-proxy
COPY config.yaml /etc/sca-proxy/config.yaml
EXPOSE 8080
ENTRYPOINT ["/sca-proxy", "--config", "/etc/sca-proxy/config.yaml"]
