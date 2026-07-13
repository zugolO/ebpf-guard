# ebpf-guard demo

Sets up a fresh Linux VPS to run the ebpf-guard live demo: build tooling for
eBPF, the `ebpf-guard` binary itself, and two intentionally vulnerable
targets to attack.

## Quick start

```bash
sudo ./demo/setup-vps.sh
```

This installs, in order:

1. **Build dependencies** — clang, llvm, libbpf-dev, matching `linux-headers`,
   `linux-tools`, make, git, curl, python3
2. **Go 1.23+** (to `/usr/local/go`, if not already present)
3. **bpf2go** (`go install github.com/cilium/ebpf/cmd/bpf2go@latest`)
4. **Docker** (via `get.docker.com`, if not already present) and starts
   **OWASP Juice Shop** on `http://127.0.0.1:3000` (`demo/docker-compose.yml`)
5. Compiles the BPF C programs (`scripts/compile_bpf.sh`)
6. Generates Go bindings (`make generate`)
7. Builds the binary (`make build` → `build/ebpf-guard`)
8. Restricts the demo target ports (`8080`, `3000`) to localhost via iptables

## Targets

| Target | Port | Purpose |
|---|---|---|
| `demo/target-app/app.py` | 8080 | Minimal Python app with direct RCE/file-read/command-injection endpoints — drives `demo/attack-scripts/attack.sh` |
| Juice Shop (Docker) | 3000 | Full OWASP Juice Shop app for broader web-attack scenarios (SQLi, auth bypass, XSS, etc.) |

Start/stop Juice Shop independently:

```bash
docker compose -f demo/docker-compose.yml up -d
docker compose -f demo/docker-compose.yml down
```

## Running the demo

```bash
# 1. Start ebpf-guard (real eBPF, requires root)
sudo ./build/ebpf-guard --config config/config.yaml &
ADMIN_TOKEN=$(awk -F= '/admin/{print $2}' /run/ebpf-guard/token)

# 2. Start the lightweight vulnerable target
python3 demo/target-app/app.py &
# Juice Shop is already running from setup-vps.sh: http://localhost:3000

# 3. Launch attacks against target-app and check ebpf-guard alerts
./demo/attack-scripts/attack.sh localhost:8080 localhost:9090 "$ADMIN_TOKEN"
```
