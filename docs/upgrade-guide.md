# Upgrade Guide

This guide explains how to migrate your ebpf-guard configuration between schema versions.

## Quick start

```bash
# 1. Check your current config for compatibility issues
ebpf-guard config validate --config /etc/ebpf-guard/config.yaml

# 2. Auto-fix all issues
ebpf-guard config migrate --config /etc/ebpf-guard/config.yaml \
    --to v0.2.0 \
    --out /etc/ebpf-guard/config.yaml.new

# 3. Review the migrated file, then replace the original
mv /etc/ebpf-guard/config.yaml /etc/ebpf-guard/config.yaml.bak
mv /etc/ebpf-guard/config.yaml.new /etc/ebpf-guard/config.yaml
```

## Commands

### `ebpf-guard config validate`

Reads a config file and reports deprecated or removed fields:

```
✓ server: OK
✓ bpf: OK
✗ profiler.ewma_weight: deprecated, renamed to profiler.ewma.weight (since v0.2.0)
✗ alerting.webhook_url: removed since v0.2.0: use alerting.alertmanager.url instead

2 issue(s) found. Run 'ebpf-guard config migrate' to auto-fix.
```

Exit code is `0` when the config has no issues, `1` when problems are detected.

### `ebpf-guard config migrate`

Applies rename and removal transformations and writes a new YAML file:

```bash
ebpf-guard config migrate \
    --config config.yaml \
    --to v0.2.0 \
    --out config.migrated.yaml
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `config/config.yaml` | Source config file |
| `--to` | `v0.2.0` | Target schema version |
| `--out` | `<config>.migrated.yaml` | Output file path |

> **Note:** YAML comments are not preserved in the migrated output because
> the document is round-tripped through a generic map. Review the generated
> file before replacing your production config.

## The `config_version` field

Starting with v0.1, every config file should declare its schema version:

```yaml
config_version: "v0.1"
```

The `validate` and `migrate` commands use this field to determine which
migrations to apply. If `config_version` is absent, the file is treated as
`v0.1`.

## v0.1 → v0.2.0 changes

### `profiler.ewma_weight` renamed to `profiler.ewma.weight`

EWMA (Exponentially Weighted Moving Average) settings were grouped under a
dedicated `profiler.ewma` block.

**Before (v0.1):**
```yaml
profiler:
  ewma_weight: 0.3
```

**After (v0.2.0):**
```yaml
profiler:
  ewma:
    weight: 0.3
```

### `alerting.webhook_url` removed

The top-level `alerting.webhook_url` field was removed. Configure the
Alertmanager endpoint via the dedicated sub-section instead.

**Before (v0.1):**
```yaml
alerting:
  enabled: true
  webhook_url: "https://alertmanager.example.com/api/v2/alerts"
```

**After (v0.2.0):**
```yaml
alerting:
  enabled: true
  alertmanager:
    url: "https://alertmanager.example.com/api/v2/alerts"
```

## CI integration

The `config-validate` workflow runs automatically on every pull request that
touches config files. It builds the binary and executes:

```bash
ebpf-guard config validate --config config/config.yaml
```

To run the same check locally before pushing:

```bash
make build
./build/ebpf-guard config validate --config config/config.yaml
```
