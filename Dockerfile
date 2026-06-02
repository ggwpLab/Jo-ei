# Build stage
FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /jo-ei ./cmd/jo-ei

# Runtime stage
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /jo-ei /jo-ei
COPY config.yaml /etc/jo-ei/config.yaml
EXPOSE 8080
ENTRYPOINT ["/jo-ei", "--config", "/etc/jo-ei/config.yaml"]
