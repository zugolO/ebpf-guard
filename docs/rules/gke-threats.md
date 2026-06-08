# GKE Threat Detection Rules

Rule file: `rules/gke-threats.yaml`  
Test suite: `tests/rules/gke_threats_test.yaml`

Detection rules for Google Kubernetes Engine (GKE)-specific attack patterns, covering GKE metadata server exploitation, Workload Identity token abuse, GCP service account key theft, kubelet read-only port exposure, and Cloud SQL lateral movement.

## Rules

### `gke_metadata_server_access` — GKE metadata server access

**Severity:** critical | **Event type:** network | **MITRE:** T1552.005

Fires when any process connects to `169.254.169.252/32` or `169.254.169.254/32`. The GKE metadata concealment proxy at `169.254.169.252` is GKE-specific; `169.254.169.254` is the standard GCE IMDS. Without Workload Identity enforced, containers can obtain the node GCP service account's OAuth2 token from either endpoint and escalate to GCP project-level access.

**Mitigation:** Enable Workload Identity Federation on all node pools (`--workload-pool`). Use metadata concealment to block pod access to the legacy metadata endpoint.

---

### `gke_workload_identity_endpoint_abuse` — Workload Identity agent port 988

**Severity:** critical | **Event type:** network | **MITRE:** T1528, T1552.005

Fires when a process connects to `169.254.169.252:988`, the GKE Workload Identity agent's token exchange port. Direct access to this port bypasses normal SDK flow and may represent token theft or configuration probing.

---

### `gke_kubelet_readonly_port_access` — Kubelet unauthenticated read-only port

**Severity:** warning | **Event type:** network | **MITRE:** T1613

Fires on any connection to port `10255` (kubelet read-only API). This unauthenticated endpoint exposes pod specs, container status, and node metrics. From inside a pod it enables enumeration of all co-hosted workloads to identify high-value targets.

**Mitigation:** Set `--read-only-port=0` in the kubelet configuration (required by CIS GKE Benchmark 4.2.4).

---

### `gke_gcp_sa_json_key_access` — GCP service account JSON key file access

**Severity:** critical | **Event type:** file | **MITRE:** T1552.001

Fires when a process accesses GCP service account JSON key files under well-known mount paths (`/var/run/secrets/google/`, `/etc/gcp/`, `/etc/google/`, `/run/secrets/gcp/`). These files contain a private RSA key and service account email that grant persistent, time-unlimited GCP access.

**Mitigation:** Replace service account key mounts with Workload Identity Federation. Rotate and delete unused service account keys regularly.

---

### `gke_gcloud_credential_access` — gcloud SDK credentials directory access

**Severity:** warning | **Event type:** file | **MITRE:** T1552.001

Fires on access to `/root/.config/gcloud/` or `/.config/gcloud/`. This directory holds OAuth2 user tokens, service account impersonation credentials, and Application Default Credentials. Unexpected access in a pod indicates leaked developer or CI/CD credentials.

---

### `gke_cloudsql_proxy_socket_access` — Cloud SQL Auth Proxy socket access

**Severity:** warning | **Event type:** file | **MITRE:** T1078

Fires when a process accesses `/tmp/cloudsql/` or `/cloudsql/`, where the Cloud SQL Auth Proxy creates Unix sockets. Any process that can open the socket gets unauthenticated SQL access; the proxy relies on pod isolation for security.

---

### `gke_service_account_key_creation` — GCP service account key created (cloud audit)

**Severity:** critical | **Event type:** cloud_audit | **MITRE:** T1528, T1078.004

Fires when a `CreateServiceAccountKey` call is recorded in GCP audit logs. Creating a new service account key from within a Kubernetes workload is a persistence mechanism — the key survives pod and cluster replacement.

> **Note:** This rule requires GCP Cloud Audit Logs to be ingested via the cloud_audit collector. See `internal/correlator/cloud_audit_test.go` for unit test patterns.

## Tags

| Tag | Meaning |
|---|---|
| `gke` | GKE-specific rule |
| `gcp` | Google Cloud Platform |
| `metadata-server` | GKE metadata concealment proxy |
| `workload-identity` | GKE Workload Identity Federation |
| `service-account-key` | GCP SA JSON key file |
| `cis-benchmark` | CIS GKE Benchmark control |
| `mitre:T1552.005` | Cloud Instance Metadata API |
| `mitre:T1528` | Steal Application Access Token |
| `mitre:T1613` | Container and Resource Discovery |

## References

- [GKE Security Best Practices — Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
- [GKE CIS Benchmark](https://cloud.google.com/kubernetes-engine/docs/concepts/cis-benchmarks)
- [MITRE ATT&CK T1552.005](https://attack.mitre.org/techniques/T1552/005/)
- [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/)
