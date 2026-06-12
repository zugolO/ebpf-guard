# Multi-stage build for ebpf-guard
# Stage 1: Build the Go binary with embedded rules
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make clang llvm musl-dev linux-headers

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code (including rules/ for embedded filesystem)
COPY . .

# Build the binary (CGO disabled for static binary)
# Embed rules/ directory via Go embed.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=$(git describe --tags --always || echo 'dev') -X main.Commit=$(git rev-parse --short HEAD || echo 'unknown') -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o ebpf-guard \
    ./cmd/ebpf-guard

# Stage 2: Create minimal runtime image
# Must run as root for eBPF; users must pass --privileged to docker run.
FROM gcr.io/distroless/static:debug

# Copy the binary from builder (includes embedded rules)
COPY --from=builder /build/ebpf-guard /usr/local/bin/ebpf-guard

# Expose metrics port (9090 is the zero-config default)
EXPOSE 9090

# Health check — probe the /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/ebpf-guard", "status"] || exit 1

ENTRYPOINT ["/usr/local/bin/ebpf-guard"]

# Zero-config mode — no config file or rules directory needed.
# Embedded defaults + built-in rules. Override with --config /path/config.yaml.
CMD ["--zero-config"]
