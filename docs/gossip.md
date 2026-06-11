# Gossip: Cross-Node IOC Sharing

The gossip subsystem (`internal/gossip`) enables ebpf-guard agents running on different nodes in a cluster to share Indicators of Compromise (IOCs) and alert amplification signals in near-real time. When a node detects a malicious IP, domain, or alert fingerprint, it broadcasts those IOCs to all configured peers so they can match the same threat without waiting for a centralised rule update.

## Threat Model

Gossip addresses lateral movement and multi-node attacks: if a container on Node A exfiltrates data to `attacker.example.com`, the DNS IOC is shared with agents on Nodes B–Z within one push interval. Any new connection to that domain on any node raises an alert immediately.

## Architecture

```
Node A                        Node B
┌─────────────────────┐       ┌─────────────────────┐
│  CorrelationEngine  │       │  CorrelationEngine  │
│   ├── IOCMatcher ◄──┼───────┼── Manager.MergeFromPeer │
│   └── ExtractFromAlert──────┼──► Manager.PushIOCs  │
└─────────────────────┘  mTLS └─────────────────────┘
```

Each Manager maintains an in-memory `IOCStore` (LRU, max `max_iocs` entries). On every `push_interval`, the delta of new IOCs is pushed to all peers concurrently (one goroutine per peer). Peers expose `POST /gossip/iocs` and `POST /gossip/amplifications` endpoints that the gossip HTTP client calls.

IOCs are typed: `ip`, `dns`, or `fingerprint`. Only public (non-RFC1918) IPs are shared to avoid broadcasting cluster-internal addresses.

## Configuration

```yaml
gossip:
  enabled: false              # Disabled by default; enable explicitly
  node_name: ""               # Defaults to system hostname
  secret: ""                  # Shared authentication token (required when enabled)
  secret_previous: ""         # Old secret during rolling rotation (see below)
  secret_rotation_ttl: 5m     # How long secret_previous remains valid after startup
  peers:                      # List of peer base URLs
    - https://10.0.0.2:9090
    - https://10.0.0.3:9090
  ioc_ttl: 1h                 # How long a received IOC remains valid
  max_iocs: 100000            # Maximum IOC store size (LRU eviction)
  push_interval: 30s          # How often the delta is flushed to peers
  deduplication_ttl: 5m       # How long a fingerprint suppresses re-alerting from peers

  tls_enabled: false          # Enable mTLS for all peer connections (strongly recommended)
  tls_cert_file: ""           # Path to PEM client certificate
  tls_key_file: ""            # Path to PEM private key
  tls_ca_file: ""             # Path to PEM CA bundle
```

## Network Overhead

The following estimates assume a 10-node cluster with 5 new IOCs generated per push interval, shared to all 9 peers.

| Parameter | Value |
|---|---|
| Push interval | 30 s (default) |
| IOCs per push | ~5 (incident rate dependent) |
| IOC JSON size | ~150 bytes each |
| Push payload | ~750 bytes per peer per push |
| Pushes/hour/peer | 120 |
| Traffic per pair/hour | ~90 KB |
| Total cluster traffic/hour (10 nodes) | ~8 MB |

During an active incident, IOC generation rates spike. With 100 IOCs/push the per-pair rate grows to ~1.8 MB/hour, still well within typical inter-node bandwidth limits.

Amplification signals (critical alert broadcasts) are ~200 bytes each and fire only on `severity: critical` alerts with a Kubernetes namespace, so their contribution to traffic is negligible under normal conditions.

## mTLS Setup

Peer-to-peer communication should always use mTLS to prevent an attacker from injecting false IOCs. Generate a per-node client certificate signed by a shared cluster CA:

```bash
# Generate cluster CA (once)
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/CN=ebpf-guard-cluster-ca"

# Generate per-node cert (repeat for each node)
openssl genrsa -out node-1.key 2048
openssl req -new -key node-1.key -out node-1.csr \
  -subj "/CN=node-1"
openssl x509 -req -in node-1.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -days 365 -out node-1.crt

# Config on node-1:
# tls_enabled: true
# tls_cert_file: /etc/ebpf-guard/certs/node-1.crt
# tls_key_file:  /etc/ebpf-guard/certs/node-1.key
# tls_ca_file:   /etc/ebpf-guard/certs/ca.crt
```

All peers must trust the same CA. When using `secret_previous` for rolling secret rotation, both the new and old secrets are accepted for `secret_rotation_ttl` before the old secret is rejected.

## Kubernetes DaemonSet Topology

The typical deployment is one ebpf-guard Pod per node (DaemonSet). Peer discovery uses the static `peers` list in the ConfigMap. For dynamic peer discovery, update the ConfigMap peers list and set `hot_reload: true` on the gossip section.

Recommended Kubernetes configuration:

```yaml
# In your Helm values or DaemonSet manifest:
gossip:
  enabled: true
  peers:
    - https://10.0.0.2:9090   # Node IPs or DNS names
    - https://10.0.0.3:9090
    - https://10.0.0.4:9090
  tls_enabled: true
  tls_cert_file: /etc/ebpf-guard/certs/tls.crt
  tls_key_file:  /etc/ebpf-guard/certs/tls.key
  tls_ca_file:   /etc/ebpf-guard/certs/ca.crt
```

Use a Kubernetes `Secret` for the TLS files and a `headless Service` or `StatefulSet` DNS names for the peer list. For clusters larger than 50 nodes, consider using a hub-and-spoke topology (dedicated aggregator nodes) to reduce total push fan-out.

**Port configuration.** The gossip HTTP endpoint is served by the main API server (default `:9090`). No additional port is required; configure `NetworkPolicy` to allow ingress on port 9090 between DaemonSet Pods.

## Failure Behavior

When a peer is unreachable, the push goroutine increments `ebpf_guard_gossip_push_errors_total` and logs at debug level. The delta is **dropped** (not retried) to avoid unbounded memory growth. Configure Alertmanager or Prometheus alerting rules on `gossip_push_errors_total > 0` to detect connectivity issues.

The IOC store remains functional on the local node regardless of peer connectivity. A node that cannot reach peers continues to detect threats using IOCs already in its local store until they expire per `ioc_ttl`.

## Metrics

| Metric | Description |
|---|---|
| `ebpf_guard_gossip_iocs_received_total` | IOCs received from peer agents |
| `ebpf_guard_gossip_match_hits_total` | Events matched against gossip IOCs |
| `ebpf_guard_gossip_push_total` | IOC batch pushes sent to peers |
| `ebpf_guard_gossip_push_errors_total` | Failed IOC batch pushes |
| `ebpf_guard_gossip_store_size` | Current IOC store entry count |
| `ebpf_guard_gossip_amplifications_received_total` | Amplification signals received |
| `ebpf_guard_gossip_amplifications_active` | Currently active amplification signals |

## Alert Amplification

When a `severity: critical` alert fires on a node with a Kubernetes namespace, the Manager broadcasts an `AmplificationSignal` to all peers. Receiving peers temporarily lower their anomaly detection threshold for that namespace by a configurable multiplier. This makes the cluster collectively more sensitive during an active attack — if Node A sees a container escape, Nodes B–Z will alert on subtler anomalies in the same namespace for the duration of the amplification TTL.

Amplification signals are fingerprint-deduplicated: the same fingerprint received from multiple peers is counted once, so a cluster of 100 nodes will not generate 100× duplicate alerts for a single event.
