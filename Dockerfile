# Multi-stage build for ebpf-guard
# Stage 1: Build the Go binary
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make clang llvm musl-dev linux-headers

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary (CGO disabled for static binary)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=$(git describe --tags --always || echo 'dev') -X main.Commit=$(git rev-parse --short HEAD || echo 'unknown')" \
    -o ebpf-guard \
    ./cmd/ebpf-guard

# Stage 2: Create minimal runtime image
FROM gcr.io/distroless/static:nonroot

# Copy the binary from builder
COPY --from=builder /build/ebpf-guard /usr/local/bin/ebpf-guard

# Use nonroot user (65532:65532 in distroless)
USER 65532:65532

# Expose metrics port
EXPOSE 8080

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/ebpf-guard", "--help"] || exit 1

ENTRYPOINT ["/usr/local/bin/ebpf-guard"]
CMD ["--config", "/etc/ebpf-guard/config.yaml"]
