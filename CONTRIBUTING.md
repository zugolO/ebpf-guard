# Contributing to ebpf-guard

Thank you for your interest in contributing to ebpf-guard! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Pull Request Process](#pull-request-process)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Developer Certificate of Origin (DCO)](#developer-certificate-of-origin-dco)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Security Issues](#security-issues)

## Code of Conduct

This project adheres to the [CNCF Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Go 1.23 or later
- Clang/LLVM 15+ (for eBPF compilation)
- Linux kernel 5.15+ (for running eBPF programs)
- Docker (for containerized builds)

### Setting Up Your Development Environment

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/ebpf-guard.git
   cd ebpf-guard
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/zugolO/ebpf-guard.git
   ```

4. **Install dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install -y clang-15 llvm-15 libbpf-dev

   # Or use the Makefile
   make deps
   ```

5. **Build the project**:
   ```bash
   make build
   ```

6. **Run tests**:
   ```bash
   make test
   ```

## Development Workflow

### Branch Naming

Use the following prefixes for branch names:

- `feature/` - New features or enhancements
- `bugfix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `test/` - Test additions or improvements
- `chore/` - Maintenance tasks

Examples:
```
feature/tls-inspection
bugfix/race-condition-collector
docs/api-reference
```

### Keeping Your Fork Updated

```bash
git fetch upstream
git checkout main
git rebase upstream/main
git push origin main
```

## Pull Request Process

1. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make your changes** following our [coding standards](#coding-standards)

3. **Test your changes**:
   ```bash
   make test
   make lint
   ```

4. **Commit with sign-off** (see [DCO](#developer-certificate-of-origin-dco)):
   ```bash
   git commit -s -m "feat: add new feature"
   ```

5. **Push to your fork**:
   ```bash
   git push origin feature/my-feature
   ```

6. **Create a Pull Request** against the `main` branch

### PR Checklist

Before submitting a PR, ensure:

- [ ] Code follows the project's coding standards
- [ ] All tests pass (`make test`)
- [ ] New code has appropriate test coverage
- [ ] Documentation is updated (if applicable)
- [ ] Commit messages follow our guidelines
- [ ] All commits are signed off (`git commit -s`)
- [ ] PR description explains the changes and motivation
- [ ] Linked any related issues

### PR Review Process

1. Maintainers will review your PR within 5 business days
2. Address review comments by pushing additional commits
3. Once approved, a maintainer will merge your PR
4. Squash merges are used to keep history clean

## Commit Message Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation only
- `style` - Code style (formatting, semicolons, etc.)
- `refactor` - Code refactoring
- `perf` - Performance improvements
- `test` - Adding or updating tests
- `chore` - Build process or auxiliary tool changes

### Scopes

Common scopes for this project:

- `bpf` - eBPF programs
- `collector` - Event collectors
- `correlator` - Event correlation engine
- `profiler` - Anomaly profiler
- `exporter` - Metrics and alert exporters
- `config` - Configuration management
- `cli` - Command-line interface
- `docs` - Documentation

### Examples

```
feat(collector): add TLS inspection via uprobes

Implement uprobe-based TLS plaintext capture for OpenSSL.
Captures data before encryption in SSL_write and after
decryption in SSL_read.

Signed-off-by: Jane Doe <jane@example.com>
```

```
fix(correlator): resolve race condition in sharded buffer

The previous implementation had a TOCTOU race when checking
buffer size before eviction. Use atomic operations for
counter updates.

Fixes #123

Signed-off-by: John Smith <john@example.com>
```

## Developer Certificate of Origin (DCO)

We require all commits to be signed off according to the [Developer Certificate of Origin](https://developercertificate.org/):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### Signing Off Commits

Add the `-s` flag to your git commit:

```bash
git commit -s -m "feat: add new feature"
```

Or manually add the sign-off line:

```
Signed-off-by: Your Name <your.email@example.com>
```

### Fixing DCO on Existing Commits

If you forgot to sign off:

```bash
git rebase --signoff HEAD~N  # N = number of commits to fix
git push --force-with-lease
```

## Coding Standards

### Go Code

- Follow [Effective Go](https://go.dev/doc/effective_go)
- Run `go fmt` before committing
- Run `golangci-lint` and fix all issues
- Use meaningful variable names
- Add godoc comments for all exported symbols
- Keep functions focused and small
- Handle all errors explicitly

### eBPF C Code

- Target kernel 5.15+ minimum
- Use `__always_inline` for helper functions
- Validate all pointer accesses with `bpf_probe_read_*`
- Include comments explaining complex logic
- Follow kernel coding style for C code

### Testing

- Write table-driven tests for business logic
- Use `testify/assert` for assertions
- Aim for >70% code coverage
- Include race detector tests for concurrent code
- Add integration tests for new collectors

#### E2E Tests

The `e2e/` directory contains end-to-end and integration tests split into two tiers:

| Tier | Tests | When it runs |
|------|-------|--------------|
| **Fast** | `TestIntegration*`, `TestContention*`, `TestAnomaly*` | Every PR and push |
| **Load** | `TestLoad*`, `TestPerformance*`, `TestSustained*` | Nightly (scheduled) |

**Running fast E2E tests locally** (requires Docker):

```bash
go test -v -timeout=8m ./e2e/... -run "TestIntegration|TestContention|TestAnomaly"
```

**Running all E2E tests locally**:

```bash
go test -v -timeout=30m ./e2e/...
```

The fast E2E suite runs without the `-short` flag; to skip it in local unit-test runs pass `-short`:

```bash
go test -short ./...
```

### Example Test Structure

```go
func TestMyFunction(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {
            name:     "valid input",
            input:    "test",
            expected: "TEST",
            wantErr:  false,
        },
        {
            name:    "empty input",
            input:   "",
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := MyFunction(tt.input)
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            assert.NoError(t, err)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

## Documentation

- Update `README.md` for user-facing changes
- Update `docs/` for detailed documentation
- Add godoc comments for new APIs
- Update `CHANGELOG.md` with significant changes
- Include examples where helpful

## Security Issues

Please do **not** open public issues for security vulnerabilities. Instead:

1. Email security@ebpf-guard.io (or contact maintainers directly)
2. Include detailed description and reproduction steps
3. Allow time for assessment before public disclosure

See [SECURITY.md](SECURITY.md) for our security policy.

## Questions?

- Join our [Discord](https://discord.gg/ebpf-guard) (coming soon)
- Open a [GitHub Discussion](https://github.com/zugolO/ebpf-guard/discussions)
- Contact maintainers (see [MAINTAINERS.md](MAINTAINERS.md))

## Recognition

Contributors will be recognized in our release notes and CONTRIBUTORS file. Thank you for helping make ebpf-guard better!
