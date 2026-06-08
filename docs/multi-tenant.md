# Multi-Tenant Namespace Isolation

ebpf-guard supports multi-team Kubernetes clusters through namespace-scoped API tokens
and per-namespace rule sets. Each team receives its own bearer token that restricts
access to the alerts, rules, and incidents from their namespaces only.

## Quick Start

```yaml
# config.yaml
auth:
  enabled: true
  tokens:
    - token: "token-for-team-a"     # generate with: openssl rand -hex 32
      role: viewer
      namespaces: ["team-a"]
    - token: "token-for-team-b"
      role: viewer
      namespaces: ["team-b"]
    - token: "global-admin-token"
      role: admin
      namespaces: []                 # empty = all namespaces
```

## Token Roles and Namespace Scopes

Each token in `auth.tokens` has two properties:

| Field | Values | Description |
|---|---|---|
| `role` | `viewer` / `admin` | RBAC role (viewer = read-only) |
| `namespaces` | `[]string` | Namespaces the token may access |

**Namespace rules:**
- Empty `namespaces: []` → access to **all** namespaces (global token).
- `namespaces: ["*"]` → same as empty (explicit wildcard).
- `namespaces: ["team-a", "team-b"]` → access restricted to those two namespaces.

The legacy `auth.viewer_token` and `auth.admin_token` fields continue to work as
global tokens (no namespace restriction) alongside the new `tokens` list.

## API Enforcement

### GET /api/v1/alerts

The namespace scope is enforced automatically:

```bash
# Token for team-a — returns only alerts from team-a pods
curl -H "Authorization: Bearer token-for-team-a" \
  http://ebpf-guard:9090/api/v1/alerts

# Requesting a namespace outside scope → 403 Forbidden
curl -H "Authorization: Bearer token-for-team-a" \
  http://ebpf-guard:9090/api/v1/alerts?namespace=team-b
# → 403: Forbidden: namespace "team-b" not in token scope

# Admin token (no namespace restriction)
curl -H "Authorization: Bearer global-admin-token" \
  http://ebpf-guard:9090/api/v1/alerts?namespace=team-b
# → 200 OK with team-b alerts
```

### GET /api/v1/incidents

Same enforcement applies to `/api/v1/incidents`:

```bash
curl -H "Authorization: Bearer token-for-team-a" \
  http://ebpf-guard:9090/api/v1/incidents
# Returns only incidents from team-a pods
```

## Per-Namespace Rule Sets

You can extend (or replace) the global rule set with namespace-specific rules:

```yaml
rules:
  path: rules/global.yaml          # rules applied to all namespaces
  hot_reload: true
  namespaces:
    - selector: "team=security"    # Kubernetes namespace label selector
      path: rules/security-team/
      override: false              # merge with global rules (default)
    - selector: "env=production"
      path: rules/prod-only/
      override: false
```

**Note:** Namespace-specific rule loading is schema-ready. The rule engine
applies global rules by default; per-namespace rule routing will be wired
into the correlation pipeline in a follow-up once namespace labels are
propagated from the K8s enricher into the correlation context.

## Prometheus Metrics

The `ebpf_guard_alerts_total` counter now includes a `namespace` label:

```
ebpf_guard_alerts_total{rule_id="rule_001", severity="warning", namespace="team-a"} 5
ebpf_guard_alerts_total{rule_id="rule_001", severity="warning", namespace="team-b"} 2
```

### Grafana Dashboard Query

```promql
# Alerts per namespace in the last hour
sum by (namespace) (
  increase(ebpf_guard_alerts_total[1h])
)
```

```promql
# Top rules per namespace
topk(5, sum by (namespace, rule_id) (
  rate(ebpf_guard_alerts_total[5m])
))
```

## Kubernetes DaemonSet Setup

Generate per-team tokens and store them in a Secret:

```bash
# Generate tokens
TOKEN_TEAM_A=$(openssl rand -hex 32)
TOKEN_TEAM_B=$(openssl rand -hex 32)
TOKEN_ADMIN=$(openssl rand -hex 32)

kubectl create secret generic ebpf-guard-tokens \
  --from-literal=token-team-a="$TOKEN_TEAM_A" \
  --from-literal=token-team-b="$TOKEN_TEAM_B" \
  --from-literal=token-admin="$TOKEN_ADMIN"
```

Reference in the Helm values:

```yaml
# values-multitenant.yaml
config:
  auth:
    enabled: true
    tokens:
      - token: "${TOKEN_TEAM_A}"
        role: viewer
        namespaces: ["team-a"]
      - token: "${TOKEN_TEAM_B}"
        role: viewer
        namespaces: ["team-b"]
      - token: "${TOKEN_ADMIN}"
        role: admin
        namespaces: []
```

## Security Notes

- Namespace isolation is enforced **server-side** by the authenticated token's scope, not by query parameters. A client cannot bypass the restriction by omitting `?namespace=`.
- Tokens use constant-time comparison to prevent timing attacks.
- Cross-tenant alert correlation is intentionally not supported.
- Different BPF programs per tenant is not feasible at the kernel level; all tenants share a single BPF ring buffer, filtered post-collection.
