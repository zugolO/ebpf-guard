# EKS Threat Detection Rules

Rule file: `rules/eks-threats.yaml`  
Test suite: `tests/rules/eks_threats_test.yaml`

Detection rules for Amazon Elastic Kubernetes Service (EKS)-specific attack patterns, covering EC2 IMDS credential theft, IRSA / Pod Identity token abuse, static AWS credential harvesting, and ECR supply-chain attacks.

## Rules

### `eks_imds_credential_theft` — EC2 IMDS IAM credential theft

**Severity:** critical | **Event type:** network | **MITRE:** T1552.005

Fires when any process connects to `169.254.169.254` (the EC2 Instance Metadata Service). From inside a pod this means an attempt to steal the EC2 node's IAM role credentials (access key, secret, session token) and escalate from pod-level to AWS account-level access.

**Mitigation:** Enforce IMDSv2 and set `--metadata-options HttpPutResponseHopLimit=1` on all node groups. With hop-limit=1 the PUT token exchange fails from within a container network namespace.

---

### `eks_fargate_task_metadata_access` — ECS/Fargate task credential endpoint

**Severity:** critical | **Event type:** network | **MITRE:** T1552.005

Fires when a process connects to `169.254.170.2`, the ECS task metadata service used by Fargate nodes. The `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` environment variable points to a path on this endpoint that returns temporary IAM credentials for the task execution role.

**Mitigation:** Use IRSA or EKS Pod Identity instead of task-role credentials. Audit workloads that read `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.

---

### `eks_irsa_token_read` — IRSA service account token theft

**Severity:** critical | **Event type:** file | **MITRE:** T1528

Fires when a process reads from `/var/run/secrets/eks.amazonaws.com/`. The OIDC token at this path is exchanged for AWS STS credentials via `sts:AssumeRoleWithWebIdentity`. Unexpected readers (shells, `curl`, Python scripts) indicate active credential harvesting.

**Mitigation:** Use least-privilege IAM roles per service account. Audit RBAC to prevent `exec` access to pods with IRSA roles.

---

### `eks_pod_identity_token_read` — EKS Pod Identity token theft

**Severity:** critical | **Event type:** file | **MITRE:** T1528

Fires when a process reads from `/var/run/secrets/pods.eks.amazonaws.com/`. EKS Pod Identity (EKS 1.29+) replaces IRSA; the token here is exchanged for AWS credentials via the Pod Identity Agent sidecar.

---

### `eks_aws_credentials_file_read` — Static AWS credentials file access

**Severity:** warning | **Event type:** file | **MITRE:** T1552.001

Fires when a process accesses `/root/.aws/credentials` or `/.aws/credentials`. Long-lived IAM access keys mounted into pods are a persistence vector. Prefer IRSA or Pod Identity — never mount static credentials.

---

### `eks_aws_config_dir_access` — AWS configuration directory traversal

**Severity:** warning | **Event type:** file | **MITRE:** T1552.001, T1087

Fires on any access to `/root/.aws/` or `/.aws/`. Broader than the credentials-file rule — catches SSO tokens, named profiles, and assume_role configurations.

---

### `eks_ecr_credential_helper_access` — Docker/ECR credential helper config

**Severity:** warning | **Event type:** file | **MITRE:** T1552.001, T1525

Fires when a process reads `/root/.docker/config.json` or `/.docker/config.json`. On EKS nodes this typically references `amazon-ecr-credential-helper`, revealing the ECR registry endpoint. Combined with harvested IAM credentials, an attacker can push backdoored images to private ECR repositories.

---

### `eks_irsa_unusual_assume_role` — Unusual AssumeRoleWithWebIdentity (cloud audit)

**Severity:** warning | **Event type:** cloud_audit | **MITRE:** T1528, T1078.004

Fires on any `sts:AssumeRoleWithWebIdentity` call in AWS CloudTrail. Intended for correlation with anomaly scoring — a legitimate per-service-account baseline learned via EWMA will suppress expected calls; deviations indicate a replayed or exfiltrated OIDC token.

> **Note:** This rule requires CloudTrail events to be ingested via the cloud_audit collector. It is not tested by the YAML test suite; see `internal/correlator/cloud_audit_test.go` for unit tests covering the cloud_audit event type.

## Tags

| Tag | Meaning |
|---|---|
| `eks` | Amazon EKS-specific rule |
| `aws` | AWS cloud provider |
| `imds` | EC2 Instance Metadata Service |
| `irsa` | IAM Roles for Service Accounts |
| `pod-identity` | EKS Pod Identity (v2 credential mechanism) |
| `token-theft` | Credential token harvesting |
| `supply-chain` | ECR image supply-chain risk |
| `mitre:T1552.005` | Cloud Instance Metadata API |
| `mitre:T1528` | Steal Application Access Token |
| `mitre:T1552.001` | Credentials in Files |

## References

- [EKS Best Practices — IAM](https://aws.github.io/aws-eks-best-practices/security/docs/iam/)
- [EKS Pod Identity documentation](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html)
- [MITRE ATT&CK T1552.005](https://attack.mitre.org/techniques/T1552/005/)
- [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/)
