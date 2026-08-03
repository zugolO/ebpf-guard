# ebpf-guard Makefile
# Requires: go 1.23+, clang, llvm, kernel headers

.PHONY: all generate build build-full build-rego build-kafka build-tui test test-norace test-full rule-test lint clean docker helm-lint bench bench-store bench-save-baseline bench-compare pgo-profile pgo-update build-pgo package package-deb package-rpm

# Variables
BINARY_NAME := ebpf-guard
BUILD_DIR := build
BPF_DIR := bpf
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*')
BPF_FILES := $(wildcard $(BPF_DIR)/*.bpf.c)

# BPF build flags — architecture-aware
BPF_CLANG := clang
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),aarch64)
  BPF_ARCH      := arm64
  BPF_ARCH_DEF  := __TARGET_ARCH_arm64
  BPF_INCLUDE   := /usr/include/aarch64-linux-gnu
else
  BPF_ARCH      := x86
  BPF_ARCH_DEF  := __TARGET_ARCH_x86_64
  BPF_INCLUDE   := /usr/include/x86_64-linux-gnu
endif
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf -D$(BPF_ARCH_DEF) -I$(BPF_INCLUDE)

# Default target
all: generate build

# Validate the OpenAPI spec and check that it is well-formed YAML.
# Requires python3 (for yaml parsing) — no extra tools needed.
api-docs:
	@echo "Validating api/openapi.yaml..."
	@python3 -c "import yaml,sys; s=yaml.safe_load(open('api/openapi.yaml')); assert s.get('openapi','').startswith('3.'); assert 'paths' in s; assert 'components' in s; print('OK — %d paths, %d schemas' % (len(s['paths']),len(s['components']['schemas'])))"

# Generate Go bindings from eBPF C code using bpf2go.
#
# Prerequisites (on the compilation host):
#   - clang 14+          : apt-get install clang llvm
#   - libbpf-dev         : apt-get install libbpf-dev
#   - bpf2go             : go install github.com/cilium/ebpf/cmd/bpf2go@latest
#
# Optional (only for regenerating bpf/vmlinux.h from the running kernel):
#   - linux kernel BTF   : /sys/kernel/btf/vmlinux
#   - bpftool            : apt-get install linux-tools-generic
#
# When the running kernel exposes BTF, vmlinux.h is regenerated from it and
# the updated header should be committed so builds keep working without BTF.
# Without kernel BTF, the committed bpf/vmlinux.h is used as-is (CO-RE
# relocates field offsets against the target kernel at program load time).
generate:
	@echo "Generating eBPF bindings with bpf2go..."
	@which clang > /dev/null 2>&1 || (echo "Error: clang not found. Install clang and llvm." && exit 1)
	@if test -f /sys/kernel/btf/vmlinux; then \
		which bpftool > /dev/null 2>&1 || (echo "Error: bpftool not found. Install linux-tools-generic." && exit 1); \
		echo "  Regenerating bpf/vmlinux.h from running kernel BTF..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h; \
	else \
		test -f bpf/vmlinux.h || (echo "Error: no kernel BTF (/sys/kernel/btf/vmlinux) and no committed bpf/vmlinux.h." && exit 1); \
		echo "  No kernel BTF — using committed bpf/vmlinux.h"; \
	fi
	@echo "  Running go generate (bpf2go)..."
	GOPACKAGE=bpf go generate ./internal/bpf/...
	@echo "  Removing stub bindings now superseded by generated files..."
	@rm -f internal/bpf/syscall_bpf_gen.go internal/bpf/xdp_bpf_gen.go

# Build the main binary (core only — no OPA, Kafka, or TUI).
# PGO is applied automatically when default.pgo exists in the module root.
build:
	@echo "Building $(BINARY_NAME) (core)..."
	mkdir -p $(BUILD_DIR)
	go build -pgo=auto -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/ebpf-guard

# Build with explicit PGO (same as build; useful for scripting / CI)
build-pgo:
	@echo "Building $(BINARY_NAME) with PGO..."
	mkdir -p $(BUILD_DIR)
	go build -pgo=auto -v -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/ebpf-guard

# Build with all optional subsystems enabled
build-full:
	@echo "Building $(BINARY_NAME) (core + rego + kafka + tui)..."
	mkdir -p $(BUILD_DIR)
	go build -tags rego,kafka,tui -o $(BUILD_DIR)/$(BINARY_NAME)-full ./cmd/ebpf-guard

# Build with OPA/Rego policy engine only
build-rego:
	@echo "Building $(BINARY_NAME) (core + rego)..."
	mkdir -p $(BUILD_DIR)
	go build -tags rego -o $(BUILD_DIR)/$(BINARY_NAME)-rego ./cmd/ebpf-guard

# Build with Kafka exporter only
build-kafka:
	@echo "Building $(BINARY_NAME) (core + kafka)..."
	mkdir -p $(BUILD_DIR)
	go build -tags kafka -o $(BUILD_DIR)/$(BINARY_NAME)-kafka ./cmd/ebpf-guard

# Build with TUI only
build-tui:
	@echo "Building $(BINARY_NAME) (core + tui)..."
	mkdir -p $(BUILD_DIR)
	go build -tags tui -o $(BUILD_DIR)/$(BINARY_NAME)-tui ./cmd/ebpf-guard

# Run all tests with race detector
test:
	@echo "Running tests with race detector..."
	go test -v -race ./...

# Run tests without race detector (for platforms that don't support it)
test-norace:
	@echo "Running tests without race detector..."
	go test -v ./...

# Run all tests including optional subsystems (rego, kafka, tui)
test-full:
	@echo "Running tests with all build tags..."
	go test -v -race -tags rego,kafka,tui ./...

# Run YAML rule fixture tests (no root / BPF required)
rule-test:
	@echo "Running rule fixture tests..."
	go test -v -race ./tests/...

# Run go vet and linting
lint:
	@echo "Running linters..."
	go vet ./...
	@which golangci-lint > /dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed, skipping"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	go clean

# Build Docker image
docker:
	@echo "Building Docker image..."
	docker build -t ebpf-guard:latest .

# Lint Helm charts
helm-lint:
	@echo "Linting Helm charts..."
	@which helm > /dev/null 2>&1 && helm lint deploy/helm/ || echo "helm not installed, skipping"

# Development helpers
fmt:
	go fmt ./...

vet:
	go vet ./...

mod-tidy:
	go mod tidy

# Run the agent locally (requires root for eBPF)
run: build
	sudo $(BUILD_DIR)/$(BINARY_NAME)

# Install dependencies
deps:
	go mod download
	go mod verify

# Run storage benchmarks
bench-store:
	@echo "Running storage benchmarks..."
	go test -bench=BenchmarkStore -benchtime=10s -count=3 ./internal/store/...

# Run all benchmarks
bench:
	@echo "Running all benchmarks..."
	go test -bench=. -benchtime=10s -count=3 ./...

# Save current benchmark results as the baseline for future comparisons
bench-save-baseline:
	@echo "Saving benchmark baseline..."
	go test -bench=. -benchtime=10s -count=5 -run='^$$' ./... | tee bench-baseline.txt

# Compare current benchmarks against the saved baseline using benchstat
# Run 'make bench-save-baseline' first to create bench-baseline.txt
bench-compare:
	go test -bench=. -benchtime=10s -count=5 -run='^$$' ./... | tee bench-new.txt
	benchstat bench-baseline.txt bench-new.txt

# ── PGO targets ────────────────────────────────────────────────────────────

# Regenerate default.pgo from hot-path benchmarks (correlator + profiler).
# The profile is committed to the repo root and picked up by 'go build' automatically.
# Re-run after significant changes to RuleEngine.EvaluateInto or EWMA scoring.
pgo-profile:
	@echo "Regenerating default.pgo from hot-path benchmarks..."
	BENCH_TIME=2s bash scripts/pgo-update.sh default.pgo
	@echo "Done. Review with: go tool pprof -top default.pgo"

# Alias: regenerate and confirm the profile is valid.
pgo-update: pgo-profile
	@go tool pprof -top default.pgo 2>/dev/null | head -10
	@echo ""
	@echo "Profile updated. Commit default.pgo to keep PGO active in CI builds."

# ── Release targets ────────────────────────────────────────────────────────

# Build release binaries for all supported architectures.
release: generate
	@echo "Building release binaries..."
	@mkdir -p build
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags="-w -s -X main.Version=$$(git describe --tags --always || echo 'dev') -X main.Commit=$$(git rev-parse --short HEAD || echo 'unknown')" \
		-o build/ebpf-guard-linux-amd64 ./cmd/ebpf-guard
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
		-ldflags="-w -s -X main.Version=$$(git describe --tags --always || echo 'dev') -X main.Commit=$$(git rev-parse --short HEAD || echo 'unknown')" \
		-o build/ebpf-guard-linux-arm64 ./cmd/ebpf-guard
	@echo "Release binaries built in build/"

# Build .deb/.rpm packages for amd64+arm64 via nfpm (issue #311).
# Requires 'make release' to have built build/ebpf-guard-linux-{amd64,arm64}
# first. Installs nfpm on the fly via 'go run' if it isn't on PATH.
NFPM := $(shell command -v nfpm 2>/dev/null || echo "go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0")
PKG_VERSION := $(shell git describe --tags --always 2>/dev/null | sed 's/^v//' || echo 0.0.0-dev)

package: package-deb package-rpm

package-deb:
	@mkdir -p dist
	@for arch in amd64 arm64; do \
		bin="build/ebpf-guard-linux-$$arch"; \
		test -f "$$bin" || { echo "  $$arch: binary not found — run 'make release' first"; exit 1; }; \
		VERSION=$(PKG_VERSION) ARCH=$$arch BIN_PATH=$$bin \
			$(NFPM) package --config packaging/nfpm.yaml --packager deb --target dist/; \
	done

package-rpm:
	@mkdir -p dist
	@for arch in amd64 arm64; do \
		bin="build/ebpf-guard-linux-$$arch"; \
		test -f "$$bin" || { echo "  $$arch: binary not found — run 'make release' first"; exit 1; }; \
		VERSION=$(PKG_VERSION) ARCH=$$arch BIN_PATH=$$bin \
			$(NFPM) package --config packaging/nfpm.yaml --packager rpm --target dist/; \
	done

# Update the SHA-256 checksums in scripts/install.sh for the current build.
checksums:
	@echo "Computing checksums for install.sh..."
	@for arch in amd64 arm64; do \
		bin="build/ebpf-guard-linux-$$arch"; \
		if [ -f "$$bin" ]; then \
			sha=$$(sha256sum "$$bin" | cut -d' ' -f1); \
			sed -i "s/CHECKSUM_linux_$$arch=.*/CHECKSUM_linux_$$arch=\"$$sha\"/" scripts/install.sh; \
			echo "  $$arch: $$sha"; \
		else \
			echo "  $$arch: binary not found — run 'make release' first"; \
		fi; \
	done
