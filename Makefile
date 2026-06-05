# ebpf-guard Makefile
# Requires: go 1.23+, clang, llvm, kernel headers

.PHONY: all generate build test lint clean docker helm-lint bench bench-store bench-save-baseline bench-compare

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

# Generate Go bindings from eBPF C code using bpf2go
# This requires clang and kernel headers to be installed
generate:
	@echo "Generating eBPF bindings with bpf2go..."
	@which clang > /dev/null 2>&1 || (echo "Error: clang not found. Install clang and llvm." && exit 1)
	go generate ./...

# Build the main binary
build:
	@echo "Building $(BINARY_NAME)..."
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/ebpf-guard

# Run all tests with race detector
test:
	@echo "Running tests with race detector..."
	go test -v -race ./...

# Run tests without race detector (for platforms that don't support it)
test-norace:
	@echo "Running tests without race detector..."
	go test -v ./...

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
