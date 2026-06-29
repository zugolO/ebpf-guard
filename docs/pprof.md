# Profiling ebpf-guard with pprof

ebpf-guard ships with Go's standard `net/http/pprof` endpoints pre-wired to the
HTTP server. They are **disabled by default** and, when enabled, remain behind the
same bearer-token / RBAC authentication as all other API routes.

## Enabling pprof

Set `server.enable_pprof: true` in your config file:

```yaml
server:
  bind_address: ":9090"
  enable_pprof: true   # default: false — never enable in production without a plan
```

Or in Kubernetes via Helm (see [Helm section](#helm) below).

The agent logs a startup notice when pprof is active:

```
INFO exporter/server: enabling pprof endpoints at /debug/pprof
```

## Available endpoints

All endpoints are served under the prefix `/debug/pprof/`:

| Endpoint | Description |
|---|---|
| `/debug/pprof/` | Index page with links to all profiles |
| `/debug/pprof/profile` | 30-second CPU profile (blocking) |
| `/debug/pprof/heap` | In-use and allocated heap objects |
| `/debug/pprof/allocs` | Allocation sampling profile |
| `/debug/pprof/goroutine` | Stack traces of all current goroutines |
| `/debug/pprof/block` | Stack traces that led to goroutine blocking |
| `/debug/pprof/mutex` | Stack traces of goroutines holding contended mutexes |
| `/debug/pprof/threadcreate` | Stack traces that led to OS thread creation |
| `/debug/pprof/cmdline` | Process command-line arguments |
| `/debug/pprof/symbol` | Symbol lookup by address |
| `/debug/pprof/trace` | Execution trace (use `go tool trace`) |

## Authentication

pprof endpoints are **not public**. The same RBAC middleware that protects
`/metrics` and `/api/v1/alerts` also covers `/debug/pprof/`:

- Requests without a valid `Authorization: Bearer <token>` header receive **401 Unauthorized**.
- Requests authenticated with a **viewer** token receive **403 Forbidden** —
  pprof is restricted to the **admin** role only.
- Requests authenticated with an **admin** token are allowed through.

```bash
# Verify auth is enforced (expect 401):
curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/debug/pprof/heap
# → 401

# Correct call with admin token:
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9090/debug/pprof/heap -o heap.out
```

## Capturing profiles with `go tool pprof`

### CPU profile (30 seconds)

```bash
go tool pprof -http=:6060 \
  "http://localhost:9090/debug/pprof/profile?seconds=30" \
  --header "Authorization: Bearer $ADMIN_TOKEN"
```

### Heap profile

```bash
go tool pprof -http=:6060 \
  "http://localhost:9090/debug/pprof/heap" \
  --header "Authorization: Bearer $ADMIN_TOKEN"
```

### Goroutine dump

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:9090/debug/pprof/goroutine?debug=2"
```

### Execution trace

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:9090/debug/pprof/trace?seconds=5" -o trace.out
go tool trace trace.out
```

## Helm

Add `config.server.enable_pprof: true` to your `values.yaml` override when
deploying with Helm. The default value is `false`.

```yaml
# values-debug.yaml  — NEVER use this file in production
config:
  server:
    enable_pprof: true  # exposes goroutine/heap details; restrict network access
```

Apply temporarily during a debugging session:

```bash
helm upgrade ebpf-guard ./deploy/helm/ebpf-guard \
  -f values-debug.yaml \
  --reuse-values
```

Roll back to the default (pprof off) when done:

```bash
helm upgrade ebpf-guard ./deploy/helm/ebpf-guard \
  --set config.server.enable_pprof=false \
  --reuse-values
```

## Security considerations

- **Never enable pprof in production without a plan.** Heap and goroutine profiles
  can expose sensitive data (keys, credentials, request bodies) held in memory.
- pprof is **not** exposed without a valid admin-token, but the information
  inside profiles is sensitive regardless of who can reach the endpoint.
- In Kubernetes, consider restricting network access to the agent's metrics port
  (default `:9090`) via `NetworkPolicy` before enabling pprof.
- The `/debug/pprof/profile` endpoint blocks the HTTP response for the duration
  of the CPU profile (default 30 s). On a heavily loaded node this may affect the
  scrape timeout of Prometheus. Reduce the duration with `?seconds=N`.
- Re-disable pprof (`enable_pprof: false`) and roll out the change as soon as the
  profiling session is complete.
