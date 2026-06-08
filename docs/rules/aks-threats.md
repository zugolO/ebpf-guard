# AKS Threat Detection Rules

Rule file: `rules/aks-threats.yaml`  
Test suite: `tests/rules/aks_threats_test.yaml`

Detection rules for Azure Kubernetes Service (AKS)-specific attack patterns, covering Azure IMDS / managed identity token theft, cluster service principal credential access, AKS Workload Identity token abuse, Azure Linux Agent (waagent) exploitation, and node bootstrap credential theft.

## Rules

### `aks_imds_access` — Azure IMDS managed identity token theft

**Severity:** critical | **Event type:** network | **MITRE:** T1552.005

Fires when any process connects to `169.254.169.254` (the Azure Instance Metadata Service). On AKS nodes the `/metadata/identity/oauth2/token` endpoint issues OAuth2 tokens for the node's system-assigned or user-assigned managed identity. The node's managed identity typically holds Contributor rights over the node resource group, enabling VM creation, Key Vault access, and network reconfiguration.

**Mitigation:** Enable AKS Workload Identity (federated credentials) for all workloads. Restrict the node managed identity to the minimum permissions required for cluster operation. Consider deploying Azure Policy to block pod access to the IMDS endpoint.

---

### `aks_service_principal_secret_access` — Cluster service principal credential file

**Severity:** critical | **Event type:** file | **MITRE:** T1552.001

Fires when a process accesses `/etc/kubernetes/azure.json` or its backup. This file contains the AKS cluster's service principal `client_id` and `client_secret` (or user-assigned managed identity resource ID), used by the cloud-controller-manager and kubelet. Reading this file from a pod via hostPath escape exposes credentials with control plane management permissions.

**Mitigation:** Use managed identity instead of service principal for new AKS clusters. Restrict hostPath volumes via Pod Security Admission or Azure Policy.

---

### `aks_workload_identity_token_read` — AKS Workload Identity OIDC token theft

**Severity:** critical | **Event type:** file | **MITRE:** T1528

Fires when a process reads from `/var/run/secrets/azure/tokens/`. The OIDC token at this path is exchanged for Azure AD access tokens via federated identity credentials. Unexpected readers indicate T1528 — an attacker harvesting the token to impersonate the pod's Azure managed identity.

**Mitigation:** Use RBAC to prevent `exec` access to pods with Workload Identity bindings. Monitor OIDC token exchange calls in Azure AD Sign-in logs.

---

### `aks_azure_linux_agent_access` — Azure Linux Agent directory access

**Severity:** critical | **Event type:** file | **MITRE:** T1552.001, T1611

Fires on access to `/var/lib/waagent/`. The Azure Linux Agent stores provisioning configuration, extension data, and certificates here. On AKS nodes waagent extensions may store secrets written during cluster bootstrap. Access via hostPath or container escape can expose node identity configuration.

---

### `aks_bootstrap_kubeconfig_access` — Node bootstrap kubeconfig access

**Severity:** critical | **Event type:** file | **MITRE:** T1552.001, T1611

Fires when a process accesses `/etc/kubernetes/bootstrap-kubeconfig`, `/etc/kubernetes/kubeconfig`, or `/etc/kubernetes/node-kubeconfig`. These files contain the kubelet's TLS client certificate for authenticating as `system:node`. The `system:node` RBAC role allows reading all Secrets on pods scheduled to the current node — a powerful lateral movement primitive.

**Mitigation:** Block hostPath mounts to `/etc/kubernetes/` via Pod Security Admission. Rotate node credentials periodically using certificate rotation (`--rotate-certificates`).

---

### `aks_managed_identity_token_abuse` — Azure managed identity token request (cloud audit)

**Severity:** warning | **Event type:** cloud_audit | **MITRE:** T1078.004, T1552.005

Fires when Azure Activity Logs record managed identity operations from unexpected workloads. Correlates with EWMA anomaly scoring to distinguish baseline managed identity usage from suspicious token requests.

> **Note:** This rule requires Azure Activity Logs to be ingested via the cloud_audit collector. See `internal/correlator/cloud_audit_test.go` for unit test patterns.

## Tags

| Tag | Meaning |
|---|---|
| `aks` | AKS-specific rule |
| `azure` | Microsoft Azure cloud provider |
| `imds` | Azure Instance Metadata Service |
| `managed-identity` | Azure Managed Identity (MSI) |
| `workload-identity` | AKS Workload Identity (federated credentials) |
| `service-principal` | Azure AD application service principal |
| `waagent` | Azure Linux Agent |
| `mitre:T1552.005` | Cloud Instance Metadata API |
| `mitre:T1528` | Steal Application Access Token |
| `mitre:T1552.001` | Credentials in Files |
| `mitre:T1611` | Escape to Host |

## References

- [AKS Security Best Practices](https://learn.microsoft.com/en-us/azure/aks/operator-best-practices-cluster-security)
- [AKS Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)
- [Azure IMDS documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
- [MITRE ATT&CK T1552.005](https://attack.mitre.org/techniques/T1552/005/)
- [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/)
