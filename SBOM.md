# Software Bill of Materials (SBOM)

This document describes how to access and verify the Software Bill of Materials (SBOM) for ebpf-guard.

## What is an SBOM?

A Software Bill of Materials (SBOM) is a complete inventory of all software components, libraries, and dependencies used in a project. SBOMs help with:

- **Security**: Identifying vulnerable dependencies quickly
- **Compliance**: Meeting regulatory and organizational requirements
- **Transparency**: Understanding what goes into the software you run

## SBOM Formats

We provide SBOMs in two standard formats:

| Format | File Extension | Specification |
|--------|---------------|---------------|
| SPDX | `.spdx.json` | [SPDX 2.3](https://spdx.dev/specifications/) |
| CycloneDX | `.cyclonedx.json` | [CycloneDX 1.5](https://cyclonedx.org/specification/overview/) |

## Accessing SBOMs

### Release Artifacts

Every release includes SBOMs as attached artifacts:

```bash
# Download SBOM for a specific release
curl -L -o ebpf-guard.spdx.json \
  https://github.com/ebpf-guard/ebpf-guard/releases/download/v0.1.0/ebpf-guard-linux-amd64.spdx.json
```

### GitHub Actions Artifacts

SBOMs are generated on every push to main and available as workflow artifacts:

1. Go to [Actions → SBOM workflow](https://github.com/ebpf-guard/ebpf-guard/actions/workflows/sbom.yml)
2. Select the latest run
3. Download the `sbom` artifact

### Generate Locally

You can generate an SBOM locally using [syft](https://github.com/anchore/syft):

```bash
# Install syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Generate SPDX SBOM
syft . -o spdx-json=ebpf-guard.spdx.json

# Generate CycloneDX SBOM
syft . -o cyclonedx-json=ebpf-guard.cyclonedx.json
```

## Verifying SBOM Completeness

To verify that an SBOM contains all expected dependencies:

```bash
# Count Go modules in go.sum
cat go.sum | wc -l

# Count packages in SPDX SBOM
cat ebpf-guard.spdx.json | jq '.packages | length'
```

The package count should closely match the number of dependencies in `go.sum`.

## Vulnerability Scanning

You can scan the SBOM for known vulnerabilities using [Grype](https://github.com/anchore/grype):

```bash
# Install grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Scan SBOM
grype sbom:ebpf-guard.spdx.json
```

Our CI pipeline automatically scans SBOMs on every release and weekly on the main branch.

## SBOM Contents

The SBOM includes:

- **Go modules**: All dependencies from `go.mod` and `go.sum`
- **Container image layers**: Base image and installed packages (for Docker images)
- **Build tools**: Compiler versions and build-time dependencies

## Integration with Security Tools

### Dependency Track

Upload CycloneDX SBOM to [Dependency Track](https://dependencytrack.org/):

```bash
curl -X POST "https://dependency-track.example.com/api/v1/bom" \
  -H "X-Api-Key: $API_KEY" \
  -H "Content-Type: multipart/form-data" \
  -F "project=$PROJECT_UUID" \
  -F "bom=@ebpf-guard.cyclonedx.json"
```

### Snyk

```bash
snyk monitor --file=go.mod
```

## Questions?

For questions about SBOMs or supply chain security, please:

1. Open an issue in the [GitHub repository](https://github.com/ebpf-guard/ebpf-guard/issues)
2. Contact the maintainers (see [MAINTAINERS.md](MAINTAINERS.md))
