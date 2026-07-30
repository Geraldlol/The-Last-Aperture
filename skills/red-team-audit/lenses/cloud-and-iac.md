---
name: cloud-and-iac
title: Cloud and infrastructure as code
runs_in: fanout
activates_on:
  paths:
    - '**/*.tf'
    - '**/*.tfvars'
    - '**/*.tf.json'
    - '**/.terraform.lock.hcl'
    - '**/terragrunt.hcl'
    - '**/*.tfstate'
    - '**/*.tfstate.backup'
    - '**/Pulumi.yaml'
    - '**/Pulumi.*.yaml'
    - '**/cdk.json'
    - '**/cdk.context.json'
    - '**/cdk.out/**'
    - '**/template.y*ml'
    - '**/*.cfn.y*ml'
    - '**/*.cfn.json'
    - '**/cloudformation/**'
    - '**/samconfig.toml'
    - '**/serverless.y*ml'
    - '**/*.bicep'
    - '**/*.bicepparam'
    - '**/azuredeploy.json'
    - '**/arm/**/*.json'
    - '**/Dockerfile'
    - '**/Dockerfile.*'
    - '**/*.dockerfile'
    - '**/.dockerignore'
    - '**/docker-compose*.y*ml'
    - '**/k8s/**/*.y*ml'
    - '**/kubernetes/**/*.y*ml'
    - '**/manifests/**/*.y*ml'
    - '**/kustomization.y*ml'
    - '**/overlays/**/*.y*ml'
    - '**/base/**/*.y*ml'
    - '**/Chart.yaml'
    - '**/Chart.lock'
    - '**/values*.y*ml'
    - '**/templates/*.y*ml'
    - '**/skaffold.y*ml'
    - '**/eksctl*.y*ml'
    - '**/*.rego'
    - '**/policy/**/*.y*ml'
    - '**/.checkov.y*ml'
    - '**/.tflint.hcl'
    - '**/app.yaml'
    - '**/cloud-init*.y*ml'
    - '**/user-data*.sh'
    - '**/firestore.rules'          # added with baas-security-rules, moved here from mobile
    - '**/storage.rules'            # added, same
    - '**/database.rules.json'      # added, same
    - '**/firebase.json'            # added, same
  signals:
    - 'provider "aws"'
    - 'provider "azurerm"'
    - 'provider "google"'
    - 'terraform { backend "s3"'
    - 'backend "azurerm"'
    - 'backend "gcs"'
    - 'data "aws_iam_policy_document"'
    - 'aws_iam_role assume_role_policy'
    - 'aws_s3_bucket_public_access_block'
    - 'aws_security_group ingress'
    - 'cidr_blocks = ["0.0.0.0/0"]'
    - 'publicly_accessible = true'
    - 'metadata_options { http_tokens'
    - 'lifecycle { prevent_destroy'
    - 'use_lockfile'
    - 'AWSTemplateFormatVersion'
    - 'Transform: AWS::Serverless-2016-10-31'
    - 'NoEcho'
    - '{{resolve:secretsmanager:'
    - 'aws-cdk-lib'
    - 'constructs'
    - '@pulumi/aws'
    - '@pulumi/kubernetes'
    - 'pulumi_aws'
    - 'boto3'
    - 'botocore'
    - '@aws-sdk/client-s3'
    - '@aws-sdk/client-sts'
    - 'azure-identity'
    - 'azure-mgmt-resource'
    - '@azure/identity'
    - '@azure/arm-'
    - "publicNetworkAccess: 'Enabled'"
    - "startIpAddress: '0.0.0.0'"
    - "defaultAction: 'Allow'"
    - 'Microsoft.Insights/diagnosticSettings'
    - 'Microsoft.Network/privateEndpoints'
    - 'google-cloud-storage'
    - 'google-auth'
    - '@google-cloud/'
    - 'kubernetes (python client)'
    - '@kubernetes/client-node'
    - 'k8s.io/client-go'
    - 'apiVersion: rbac.authorization.k8s.io'
    - 'kind: ClusterRoleBinding'
    - 'kind: NetworkPolicy'
    - 'kind: PodSecurityPolicy'
    - 'securityContext:'
    - 'privileged: true'
    - 'hostNetwork: true'
    - 'hostPID: true'
    - 'hostPath:'
    - 'automountServiceAccountToken'
    - 'serviceAccountName:'
    - 'imagePullPolicy:'
    - 'type: LoadBalancer'
    - 'pod-security.kubernetes.io/enforce'
    - 'eks.amazonaws.com/role-arn'
    - 'iam.gke.io/gcp-service-account'
    - 'azure.workload.identity/use'
    - 'token.actions.githubusercontent.com'
    - 'FROM ...:latest'
    - 'USER root'
    - 'RUN curl ... | sh'
    - 'COPY .env'
    - '--mount=type=secret'
    - '169.254.169.254'
    - 'metadata.google.internal'
    - 'allUsers'
    - 'allAuthenticatedUsers'
    - '--allow-unauthenticated'
    - 'AuthType: NONE'
    - 'authLevel: anonymous'
    - 'checkov'
    - 'tfsec'
    - 'terrascan'
    - 'trivy'
    - 'grype'
    - 'kubescape'
    - 'conftest'
    - 'kyverno'
    - 'gatekeeper'
    - 'helm'
    - 'allow read, write: if true'   # added with baas-security-rules
owns:
  - iam-policy-and-privilege-scope
  - cloud-oidc-trust-policy
  - network-exposure-and-segmentation
  - object-storage-exposure
  - imds-hardening
  - encryption-at-rest-configuration
  - kms-key-lifecycle-and-policy
  - resource-tls-enforcement-flags
  - kubernetes-workload-hardening
  - kubernetes-rbac-and-admission
  - dockerfile-and-image-content
  - image-cve-exposure
  - deploy-time-signature-enforcement
  - serverless-function-exposure
  - terraform-state-protection
  - managed-secret-service-configuration
  - control-plane-audit-logging
  - backup-and-replica-configuration
  - data-region-inventory
  - baas-security-rules
  - helm-and-manifest-source-pinning
defers:
  injection-sql-nosql-orm: web-and-api
  xss-and-output-encoding: web-and-api
  authz-object-level: web-and-api
  session-and-cookie-management: web-and-api
  security-headers-and-csp: web-and-api
  ssrf-application-path: web-and-api
  workflow-trigger-and-script-injection: cicd-and-supply-chain
  runner-and-build-environment-trust: cicd-and-supply-chain
  ci-secret-and-token-handling: cicd-and-supply-chain
  ci-oidc-workflow-configuration: cicd-and-supply-chain
  action-and-workflow-ref-pinning: cicd-and-supply-chain
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  package-dependency-cves: cicd-and-supply-chain
  artifact-signing-and-provenance-emission: cicd-and-supply-chain
  sbom-generation-and-attachment: cicd-and-supply-chain
  pipeline-scanner-gating: cicd-and-supply-chain
  privileged-deploy-gate: cicd-and-supply-chain
  tls-and-certificate-validation: crypto-and-key-management
  jwt-jws-and-jwks-verification: crypto-and-key-management
  password-hashing-and-kdf-parameters: crypto-and-key-management
  symmetric-encryption-and-nonce-handling: crypto-and-key-management
  rag-retrieval-authorization: llm-and-ai
  mobile-local-data-storage: mobile-app-security
  platform-keystore-key-custody: mobile-app-security
  apex-sharing-declaration: salesforce-platform
  phi-classification: hipaa-and-phi
  phi-severity-uplift: hipaa-and-phi
  phi-access-audit-controls: hipaa-and-phi
  hipaa-policy-documentation-retention: hipaa-and-phi
  cross-border-transfer-route: privacy-and-data-protection
  retention-lawfulness-and-deletion-completeness: privacy-and-data-protection
  personal-data-severity-uplift: privacy-and-data-protection
  pci-scope-and-cardholder-data: privacy-and-data-protection
  architecture-trust-design-gaps: threat-modeling
  pivot-feasibility: threat-modeling
frameworks:
  - cis-benchmarks
  - kubernetes-pod-security-standards
  - kubernetes-rbac
  - cwe
severity_floor: low
---

## Scope

This lens audits infrastructure as an artifact: Terraform, Terragrunt, Pulumi, CDK and CloudFormation/SAM, Bicep and ARM, Serverless Framework, Kubernetes manifests, Kustomize overlays and Helm charts, Dockerfiles and Compose files, Rego and admission policy, BaaS security rules, and the cloud SDK calls that stand in for configuration when nobody wrote the IaC. The unit of work is a *configuration defect with a stated reachability assumption* — never a demonstrated exploit, because almost nothing in this domain can be exercised without the live account, and the live account is out of bounds.

Three properties make this lens behave differently from every application-code lens.

- **Most findings are an absence, not a presence.** No `metadata_options` block, no `pod-security.kubernetes.io/enforce` label, no `aws_s3_account_public_access_block`, no `lifecycle { prevent_destroy = true }`, no `Deny` on `aws:SecureTransport`. A grep keyed to the dangerous *value* reports every vulnerable file clean, because the dangerous state is the platform default and nobody typed it. Every checklist item states which direction it greps.
- **A safety-shaped token is not safety.** `aws_s3_bucket_public_access_block` with all four flags `false` is worse than no block at all, because it reads as deliberate. `pod-security.kubernetes.io/enforce: privileged` contains the exact label a "do they use Pod Security Admission?" grep looks for. `#checkov:skip=CKV_AWS_20` sits on the line above the finding it suppresses. Read what the grep matched before you count it.
- **Defaults move, and they move in the safe direction.** S3 server-side encryption became unconditional in January 2023; new-bucket Block Public Access with ACLs disabled became the default in April 2023. That is not a reason to stop checking. It is the reason the surviving finding is *narrower and higher-confidence* than it used to be — a public bucket now generally had to be made public on purpose.

### Two AWS authorization inversions the source material taught backwards

The reference file this lens replaces stated AWS policy evaluation backwards in two places. Both wordings are quoted here **only** so a reader who has seen them knows they were repudiated deliberately. **Nothing in this block is an instruction**; every operative statement is in the Checklist.

| What the source said | What is true |
|---|---|
| `Bucket policies overriding account-level "block public access"` | Backwards. Block Public Access is a **backstop that overrides bucket policies and ACLs** — never the reverse. `BlockPublicPolicy` rejects a policy that grants public access when it is PUT, and `RestrictPublicBuckets` limits access under an already-public policy to service principals and authorized principals in the owning account. The finding is therefore **BPA disabled or absent**, not a policy that beat it. See Checklist item 4. |
| `Resource-based policies overriding identity-based denies in unexpected ways` | Backwards. An explicit `Deny` in **any** applicable policy — identity, resource, SCP, permissions boundary, session policy — always wins, and nothing overrides it. The real pitfall runs the other way: **inside one account, access is granted if *either* the identity policy or the resource policy allows it.** An IAM-only review therefore misses every grant that lives in an S3 bucket policy, KMS key policy, SQS queue policy, SNS topic policy, Lambda resource policy, ECR repository policy or EventBridge bus policy — including the **confused-deputy** case, where a resource policy names a *service* principal and carries no `aws:SourceAccount` or `aws:SourceArn` condition, so that service acting for any customer can reach the resource. See Checklist item 1. |

The second inversion is the more expensive of the two, because it sends the reviewer to the wrong file. A reviewer who reads only `aws_iam_policy` and `aws_iam_role_policy` and concludes "least privilege looks reasonable" has audited half the grant graph and cleared the other half without opening it.

### Checks keyed to things that no longer exist

Each of these ran, matched nothing, and reported clean — the worst failure mode this lens has, because a clean result is never re-opened. Each is corrected at the point of use below; the row exists so the dead spelling is not reintroduced.

| Dead check | Why it can never fire | What replaces it |
|---|---|---|
| `kind: PodSecurityPolicy`, "PSP not enforced" | PSP was **removed in Kubernetes 1.25**. No supported cluster has one, so "PSP not enforced" is not a finding anywhere. | Pod Security Admission namespace labels — `pod-security.kubernetes.io/enforce`, `-audit`, `-warn` — **and their values**, plus a real admission policy: Kyverno `kind: ClusterPolicy`, Gatekeeper `kind: ConstraintTemplate` and its constraints, or `kind: ValidatingAdmissionPolicy`. Checklist item 10. |
| `hostPath` "especially `/var/run/docker.sock`" | Dockershim was **removed in Kubernetes 1.24**, so a modern node has no Docker socket to mount. Ranking it first walks the reviewer past the sockets that are actually present. | `/run/containerd/containerd.sock` and `/run/crio/crio.sock` first; `/var/run/docker.sock` kept last, because it is still real on Compose hosts and in Docker-in-Docker build pods. Checklist item 9. |
| `create` on `serviceaccounts/tokenrequest` | Not an RBAC resource string. No cluster's RBAC ever reads that way, so the escalation grant it was meant to catch was invisible. | The subresource is **`serviceaccounts/token`**, plus the escalation grants the source omitted entirely. Checklist item 10. |
| `Azure AD`, `AAD` | Renamed **Microsoft Entra ID** in July 2023. The old name now matches documentation prose and stale comments, not current Bicep/ARM/Terraform. "Azure AD Pod Identity" is retired outright. | Entra ID; **Entra Workload ID** for the pod-identity case (`azure.workload.identity/use`). Checklist items 1, 2 and 9. |
| `prevent_destroy = false` | `prevent_destroy` is a `lifecycle` **meta-argument** whose default is already `false`, so the literal appears in almost no real configuration. | Grep for the **absence** of `lifecycle { prevent_destroy = true }` on stateful resources, and keep it Low/Medium: it is a guard rail against an operator mistake, not a security control. Checklist item 15. |
| ServiceAccount "tokens with no expiry (pre-1.22)" | Projected, audience-bound, expiring tokens have been the default since 1.22, and since 1.24 Kubernetes no longer auto-creates a token Secret for each ServiceAccount. Phrased as a version-history note it is unactionable. | The live version of the check: a hand-written `kind: Secret` with `type: kubernetes.io/service-account-token`, which still yields a non-expiring credential. Checklist item 10. |

### Controls the source material named wrongly

Naming the wrong mitigating control is worse than a dead check: the reviewer accepts an artifact that does not do the job and closes the item.

| Source claim | Correction |
|---|---|
| `No image signature verification (Cosign, Notary)` | "Notary" means Notary v1 / Docker Content Trust — legacy and effectively unmaintained. The current mechanisms are **Sigstore Cosign** and the Notary Project's **Notation** (Notary v2, OCI 1.1 referrers), enforced at admission by Kyverno or Gatekeeper, by AWS Signer with ECR, or by GCP Binary Authorization — and paired with provenance verification, not a signature-only check. Checklist item 13. |
| `No automated unused permission detection (AWS Access Analyzer, Azure PIM, GCP Recommender)` | **Entra PIM is just-in-time elevation with eligibility and approval. It does not detect unused permissions.** Leaving it here causes a reviewer to accept the wrong control as the mitigation. Use **IAM Access Analyzer unused access findings** (unused roles, keys, permissions), **Entra Permissions Management** (CIEM) with Entra ID access reviews for governance and PIM only for JIT, and **GCP IAM Recommender / Policy Analyzer**. The AWS product name is IAM Access Analyzer. Checklist item 1. |
| `secrets mounted as env vars … leak via kubectl describe` | False as stated. `kubectl describe pod` renders a `valueFrom.secretKeyRef` as `<set to the key 'x' in secret 'y'>` — the value is not printed. Only a literal `value:` is displayed, and that is a *different* finding (secret hardcoded in a manifest). The accurate reasons are in Checklist item 16. The `docker inspect` half of the original claim is kept: that one does print values. |
| `KMS key policies that grant kms:* to the root user of "any account"` | As written it fires on essentially every key. `"Principal": {"AWS": "arn:aws:iam::<own-account>:root"}` with `kms:*` is AWS's **default** key policy; the ARN does not designate the root *user*, it delegates authorization to that account's IAM policies, and deleting it can make the key unmanageable. Split into the two real findings in Checklist item 7. |
| GCP `primitive roles` | The current name is **basic roles**: `roles/owner`, `roles/editor`, `roles/viewer`. |

### What `cis-benchmarks` means here

`frameworks` carries `cis-benchmarks` with **no version, deliberately**. There is no global CIS Benchmark version — each benchmark is versioned independently per technology and platform, on its own schedule. Pinning one number in frontmatter would be wrong for every other benchmark in the set.

Two obligations follow, both on the auditor:

- **Name the benchmark and the version you actually opened**, in the finding text: document title, section, control number, version. A citation you cannot name is dropped and the finding is justified on the artifact alone. Do not reconstruct a control number from memory — a wrong CIS citation discredits every correct finding around it.
- **CIS Level 2 profile items are hardening, not vulnerabilities.** Level 1 is the "apply everywhere" profile; Level 2 trades functionality for defense in depth. A Level 2 gap is Low or Info here, never displaces a real finding in the ranked list, and must say in the finding that it is a Level 2 item.

### Owns

| Topic | What that means here |
|---|---|
| `iam-policy-and-privilege-scope` | Identity **and resource** policy documents on every cloud: action and resource breadth, escalation actions, conditions that are load-bearing versus decorative, the confused-deputy shape. Azure role assignments and their scope; GCP basic roles, service-account keys and impersonation. |
| `cloud-oidc-trust-policy` | The cloud-side trust document for federated identity: `sts:AssumeRoleWithWebIdentity` conditions on `sub` and `aud`, GCP Workload Identity Federation attribute mappings and conditions, Entra federated credentials. IRSA, GKE Workload Identity and `azure.workload.identity/use` annotations. |
| `network-exposure-and-segmentation` | Security groups, NSGs, GCP firewall rules, NACLs, subnet placement and public-IP assignment, Kubernetes `Service` type and `NetworkPolicy`, private endpoints and VPC Service Controls. |
| `object-storage-exposure` | S3, Blob and GCS reachability: Block Public Access state, ACL enablement, bucket-policy and IAM grants to anonymous or all-authenticated principals, public listing, CloudFront origin access. |
| `imds-hardening` | `http_tokens`, hop limit, whether the metadata service is reachable from a workload that should not have it, and the credential blast radius behind it. |
| `encryption-at-rest-configuration` | Whether a store is encrypted at all, and — where the data class or a contract requires key ownership and revocability — whether it uses a customer-managed key. EBS and managed disks, RDS/Cloud SQL/Azure SQL, snapshots, Kubernetes Secret encryption configuration. |
| `kms-key-lifecycle-and-policy` | Key policies and grants, rotation, deletion windows, `kms:ViaService` and `kms:CallerAccount` scoping, and `CreateGrant` paths a policy reader would never see. |
| `resource-tls-enforcement-flags` | The configuration switches that force transport security: `min_tls_version`, load-balancer and API-gateway TLS policy, `aws:SecureTransport` deny statements, `require_ssl` on managed databases, HTTP-to-HTTPS redirect. |
| `kubernetes-workload-hardening` | Pod and container `securityContext`; `privileged`, `hostNetwork`, `hostPID`, `hostIPC`, `hostPath`; capabilities, seccomp, read-only root filesystem, service-account token mounting, resource limits. |
| `kubernetes-rbac-and-admission` | Roles, ClusterRoles and their bindings; escalation verbs and subresources; Pod Security Admission labels; whether any admission engine gates the cluster and whether it is audit-only. |
| `dockerfile-and-image-content` | Base-image reference form, `USER`, build-time secret handling, what lands in a layer, `.dockerignore`, and the hygiene items that stay Low. |
| `image-cve-exposure` | Known vulnerabilities in the base image and OS layers, and whether anything scans them. Application dependency CVEs are cicd's. |
| `deploy-time-signature-enforcement` | Verification at admission or deploy time: Cosign and Notation invocation correctness, the identity constraints that make `verify` mean anything, and whether an enforcing policy exists in the deploy path. |
| `serverless-function-exposure` | Function URLs and HTTP triggers with no auth, function role breadth, timeout and concurrency as availability controls, secrets in function environment configuration. |
| `terraform-state-protection` | Backend encryption and locking, state access control, state committed to the tree, `sensitive = true` on outputs, and the `lifecycle` guard rails. |
| `managed-secret-service-configuration` | How a secret reaches a workload: secret-manager references versus literals, `NoEcho`, Kubernetes Secret delivery shape, rotation configuration, and whether a fetched secret is then written to disk or the environment. |
| `control-plane-audit-logging` | CloudTrail, Azure Activity log and diagnostic settings, Cloud Audit Logs: existence, coverage, integrity protection, destination account, retention. |
| `backup-and-replica-configuration` | Backup existence and retention, deletion protection, snapshot sharing, and whether a replica or export inherits the primary's protections. |
| `data-region-inventory` | The factual inventory of regions and replication destinations. The legal question is privacy's. |
| `baas-security-rules` | `firestore.rules`, `storage.rules`, `database.rules.json`, `firebase.json` — client-authoritative datastore rules, moved here from mobile because a rules file is server-side authorization configuration and the same file governs a web client. |
| `helm-and-manifest-source-pinning` | Chart and remote-manifest provenance: repository trust, version and digest pinning, `Chart.lock`, remote Kustomize bases, `kubectl apply -f https://…`, and operator permission breadth. |

### Does not own

Do not raise findings on these. Where the configuration shows one, note it in the candidate's `impact` as an aggravator and hand it to the owning lens with the file and line.

- **web-and-api** — `injection-sql-nosql-orm`, `xss-and-output-encoding`, `authz-object-level`, `session-and-cookie-management`, `security-headers-and-csp`, `ssrf-application-path`. Application code stays theirs even when it lives in a Lambda handler or a container entrypoint in this repository. One seam is load-bearing: **`ssrf-application-path` is theirs; `imds-hardening` is this lens's.** The code that fetches a user-supplied URL is their finding; whether `http_tokens` is `required` is this lens's. Together they are the Capital One chain — file both and let `attack-chaining` compose them.
- **cicd-and-supply-chain** — `workflow-trigger-and-script-injection`, `runner-and-build-environment-trust`, `ci-secret-and-token-handling`, `ci-oidc-workflow-configuration`, `action-and-workflow-ref-pinning`, `dependency-pinning-and-lockfiles`, `package-dependency-cves`, `artifact-signing-and-provenance-emission`, `sbom-generation-and-attachment`, `pipeline-scanner-gating`, `privileged-deploy-gate`. Four seams:
  - **`ci-oidc-workflow-configuration` is theirs; `cloud-oidc-trust-policy` is this lens's.** `permissions: id-token: write` and which workflow may request a token are theirs. The `sub` and `aud` conditions on the cloud role that accepts the token are this lens's.
  - **`pipeline-scanner-gating` is theirs; `image-cve-exposure` is this lens's.** Whether the pipeline blocks on a scanner result is theirs; the CVEs in the base image, and whether anything scans it at all, are this lens's.
  - **`artifact-signing-and-provenance-emission` is theirs; `deploy-time-signature-enforcement` is this lens's.** Producing a signature and an attestation is theirs; requiring one at admission is this lens's.
  - **`dependency-pinning-and-lockfiles` is theirs; `helm-and-manifest-source-pinning` is this lens's.** `package-lock.json` and `uv.lock` are theirs; `Chart.lock`, chart-repository trust and remote Kustomize bases are this lens's.
- **crypto-and-key-management** — `tls-and-certificate-validation`, `jwt-jws-and-jwks-verification`, `password-hashing-and-kdf-parameters`, `symmetric-encryption-and-nonce-handling`. **A configuration flag is this lens's; a code path is theirs.** `min_tls_version = "TLS1_0"` on a storage account and an `ssl_policy` on a load balancer are `resource-tls-enforcement-flags` here; `InsecureSkipVerify` and an empty `checkServerTrusted` are theirs. A bucket's SSE setting is `encryption-at-rest-configuration` here; the code that calls the KMS and builds a nonce is theirs.
- **llm-and-ai** — `rag-retrieval-authorization`. A vector store's network exposure and IAM are this lens's; whether the retrieval query is scoped to the requesting subject is theirs.
- **mobile-app-security** — `mobile-local-data-storage`, `platform-keystore-key-custody`. On-device storage and Keychain/Keystore custody are theirs, as is a secret compiled into an app binary. **`firestore.rules`, `storage.rules`, `database.rules.json` and `firebase.json` moved here** as `baas-security-rules`: the rules file is server-side authorization configuration, and the same file governs every client.
- **salesforce-platform** — `apex-sharing-declaration`.
- **hipaa-and-phi** — `phi-classification`, `phi-severity-uplift`, `phi-access-audit-controls`, `hipaa-policy-documentation-retention`. **This lens reports the exposure and never grades the data class.** "Public bucket" is this lens's finding; "public bucket containing ePHI, therefore Critical" is their uplift applied to it. Supply the storage-layer facts — encrypted or not, which key, who can read — and let them decide sufficiency.
- **privacy-and-data-protection** — `cross-border-transfer-route`, `retention-lawfulness-and-deletion-completeness`, `personal-data-severity-uplift`, `pci-scope-and-cardholder-data`. `data-region-inventory` here is a factual list of regions and replication destinations; whether a route is a lawful transfer is theirs. Backup *retention configuration* is this lens's; whether the period is lawful is theirs.
- **threat-modeling** — `architecture-trust-design-gaps`, `pivot-feasibility`. Do not write "an attacker who compromises the web tier could then reach the database" as a cloud finding. Report the segmentation defect; the pivot narrative is theirs.

Two boundaries with no `defers` entry, stated so nothing is double-filed:

- **A private key or credential literal committed to the tree is crypto's** (`hardcoded-credentials-and-key-material`) wherever it appears, including inside a `.tf` file. What is this lens's is the *container*: a `*.tfstate` tracked in git, a state backend with no encryption, a `NoEcho: false` parameter, a secret pasted into a manifest's `value:`. One defect, one finding — cite crypto's finding rather than restating it.
- **A local-development artifact is not a production exposure.** A `docker-compose.yml` binding Postgres to `0.0.0.0` with a default password is a Low hygiene note unless something in the repository deploys it. Establish which by reading what consumes the file, and say which you established.

### What cannot be determined from a repository

State these as assumptions with a verification step. Never as findings — and, the direction that costs more, **never as clearances.**

- **Whether a security group is attached to anything internet-reachable.** Route tables, ENIs, load-balancer wiring and the live instance inventory are account state. What *is* checkable is whether this repository references the group and from what.
- **Whether an over-broad role is assumable by an untrusted principal today.** The trust policy is here; the set of principals that exist in the account is not.
- **Whether account-level Block Public Access is on.** With no `aws_s3_account_public_access_block` (or the CloudFormation, Azure or GCP equivalent) in the repository, the account setting is not visible. Report the bucket-level facts you can see and record the account setting as an open question with the console path to check. Do not assume either direction.
- **Whether the deployed resource matches the committed configuration.** Console edits, drift, and a module version bumped outside this repository all break the inference. Every finding here is about the configuration as written.
- **Whether etcd encryption is enabled.** `EncryptionConfiguration` is an API-server flag on the control plane, absent from application repositories and invisible in managed-cluster configuration.
- **Whether an admission controller is installed and enforcing.** A `ClusterPolicy` manifest proves the policy was authored, not that the engine runs, that the webhook `failurePolicy` is `Fail`, or that the policy is out of audit-only mode.
- **Whether IMDSv2 is enforced on running instances.** `http_tokens = "required"` in a launch template governs instances launched from it afterwards; pre-existing instances keep their own metadata options.
- **Whether an egress `NetworkPolicy` on `169.254.169.254/32` is actually enforced.** The manifest proves the policy was authored. Enforcement depends on the CNI — Calico and Cilium enforce egress, Flannel enforces nothing — so establish the CNI from the repository if you can and record it as an open question if you cannot.
- **Whether a snapshot or AMI is publicly shared today.** An `aws_ami_launch_permission` shows what Terraform manages. A `ModifySnapshotAttribute --group-names all` run from a console or a one-off script leaves no trace in the configuration, and the live snapshot-attribute state is account state. Report the console/CLI path to check.
- **Whether a scanner or policy engine named in the repository gates anything.** A `.checkov.yaml` is a configuration file, not a gate. The gate is cicd's finding, and even they cannot see the provider's enforcement.
- **The CIS benchmark and version an auditor assessed.** Nothing in the repository establishes it; the auditor states it.

## Activation coverage

The activation map is wider than the parsers in item 0. A syntax named here as
`NOT ASSESSED` is still a reason to run the lens, but an empty sweep over it is
not evidence of safety.

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| Terraform HCL | COVERED | `encryption-at-rest-configuration` | fixture:V-010 |
| Terraform values, state and lock metadata | PARTIAL | `terraform-state-protection` | State and guard-rail checks exist; values and generated state require format-aware reading |
| Azure Bicep | PARTIAL | `network-exposure-and-segmentation` | V-016 covers formatted top-level resources; modules, nested children, loops and parameter resolution remain outside the helper |
| Kubernetes, Helm, Kustomize and policy YAML | PARTIAL | `kubernetes-workload-hardening` | Per-document checks and policy recipes exist; rendered and live admission behavior is not fully established |
| Dockerfiles, dockerignore and images | PARTIAL | `dockerfile-and-image-content` | Final-stage, ignored-content and image-content checks exist; Compose semantics are not covered by them |
| Rego policy | PARTIAL | `kubernetes-rbac-and-admission` | A detector pair covers default-allow; configured decision entrypoints still require tracing |
| Firebase and BaaS rules | PARTIAL | `baas-security-rules` | Rule checks exist without a committed fixture pair |
| Checkov and cloud scanner configuration | PARTIAL | `image-cve-exposure` | Checkov, image-scanner and policy-engine inventory exists; pipeline gating belongs to the CI lens |
| TFLint configuration | NOT ASSESSED | — | The path activates inventory only; this lens has no TFLint-specific actionable review path |
| Cloud SDK and resource-positive signals | PARTIAL | `iam-policy-and-privilege-scope` | Positive call and policy checks exist; SDK control-flow coverage is generic |
| CloudFormation, SAM, ARM JSON, CDKTF, Terraform JSON, Pulumi, Serverless Framework and AWS CDK | NOT ASSESSED | — | No syntax-aware absence sweep; report these stacks as not assessed |
| Terragrunt, Compose, Skaffold, eksctl, app.yaml, cloud-init and user-data | NOT ASSESSED | — | Activation or inventory only; no dedicated body semantics |

## Checklist

Twenty-one items, one per owned topic, in the order a reviewer should work them: identity first, because it is the number-one cloud breach vector and it decides the blast radius of everything else.

Each item states **which direction to grep**. Where an item names a literal, filename or API symbol, a detector block demonstrates it firing and not firing. Item 0 is an index into those literals, not a separate check.

### 0. Highest-yield sweeps

Run these first over the repository. Every hit is a candidate to read, not a finding.

**Every line below ends with an explicit `.` path argument, and that is load-bearing, not decoration.** `rg` searches **stdin** whenever no path is given and stdin is not a terminal — which is exactly how this block runs when it is pasted into a script, a pipeline or an agent's shell. Measured on the vulnerable fixture tree for this item, thirty-four of the thirty-six lines run under an empty pipe: with the path argument omitted, **0 stdout lines and 0 stderr lines**; with it present, **41 stdout lines and 0 stderr lines**. There is no error, no warning and no diagnostic to tell the two apart — and the first command drains stdin, so every later one reads EOF regardless. **A sweep that could not have matched must never be reported as a sweep that found nothing**, so if you retype one of these, retype the path too. The two Azure lines were added after that measurement and were measured the same way on the Bicep fixture pair: under a real empty pipe with the path argument omitted both return **0 stdout lines and exit 1**, and with it present both return hits on the vulnerable fixture. Note the platform wrinkle the measurement turned up — a `< /dev/null` redirect on Windows is a character device rather than a pipe, so `rg` falls back to searching `./` and the omission *appears* harmless; only a real pipe reproduces the silent-clearance failure, which is the shape a script or an agent shell actually produces.

**`--hidden` is just as load-bearing on every repository traversal below.** A glob naming `.terraform/`, `.github/` or any other hidden directory does not override ripgrep's traversal pruning, so a path-bearing command without `--hidden` can still return a silent exit 1 after searching zero relevant files. `--hidden` is for tree traversal: do not mechanically add it to a second-stage `rg` that intentionally reads stdin, or to a command whose only operand is one explicit file. Neither traverses a directory.

```bash
# --- identity and resource policies (items 1, 2, 7) ---
rg -n --hidden '"Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"|"Resource"\s*:\s*"\*"|resources\s*=\s*\[\s*"\*"' .
rg -n --hidden 'iam:PassRole|iam:CreateAccessKey|iam:AttachRolePolicy|iam:PutRolePolicy|iam:UpdateAssumeRolePolicy|sts:AssumeRole' .
rg -n --hidden 'aws_s3_bucket_policy|aws_kms_key_policy|aws_sqs_queue_policy|aws_sns_topic_policy|aws_lambda_permission|aws_ecr_repository_policy|aws_cloudwatch_event_bus_policy|aws_secretsmanager_secret_policy' .
rg -n --hidden 'roles/owner|roles/editor|roles/viewer|google_service_account_key|serviceAccountTokenCreator' .
rg -n --hidden 'token\.actions\.githubusercontent\.com|:sub|attributeMapping|federatedIdentityCredentials' .

# --- object storage (item 4) ---
rg -n --hidden 'allUsers|allAuthenticatedUsers|acl\s*=\s*"public-read|"AWS"\s*:\s*"\*"|object_ownership' .
rg -n --hidden 'aws_s3_account_public_access_block|aws_s3_bucket_public_access_block|PublicAccessBlockConfiguration' .

# --- network (item 3) ---
# Terraform snake_case AND the CloudFormation/Bicep camelCase sibling of the same
# property, because Scope claims both stacks: `PubliclyAccessible`,
# `publicNetworkAccess` and `sourceAddressPrefix` are the same defects a
# snake_case-only sweep reports clean. The `.` before the alternation on the
# camelCase NSG arm matches either quote character, which is what lets one pattern
# read Bicep (`sourceAddressPrefix: 'Internet'`) and ARM JSON
# (`"sourceAddressPrefix": "Internet"`) at once.
rg -n --hidden '0\.0\.0\.0/0|::/0|source_address_prefix\s*=\s*"(\*|Internet)"|sourceAddressPrefix"?:\s*.(\*|Internet)|publicly_accessible\s*=\s*true|map_public_ip_on_launch|PubliclyAccessible|MapPublicIpOnLaunch' .
rg -n --hidden 'public_network_access_enabled\s*=\s*true|ipv4_enabled\s*=\s*true|authorized_networks|publicNetworkAccess' .
rg -n --hidden 'type:\s*LoadBalancer' .

# --- Azure resource firewalls and the 0.0.0.0-0.0.0.0 sentinel (items 3, 4, 16) ---
# THE AZURE GOTCHA. A Postgres/MySQL/SQL firewall rule of `startIpAddress:
# '0.0.0.0'` with `endIpAddress: '0.0.0.0'` is not a CIDR, not a range, and shares
# no substring with `0.0.0.0/0` — Azure reads the pair as the sentinel meaning
# "accept connections from any IP inside Azure", i.e. every other tenant's compute.
# Every sweep above reports it clean. `0.0.0.0`-`255.255.255.255` is the genuinely
# internet-wide rule and is a separate, higher finding; both are matched here.
# The pair spans two lines, so this line needs -U. It assumes source order
# (start before end); the candidate line under it is the order-independent
# backstop and is the one to trust when the -U line is silent.
rg -n --hidden -U "startIpAddress'?:?\s*'?0\.0\.0\.0'?[^}]{0,160}?endIpAddress'?:?\s*'?(0\.0\.0\.0|255\.255\.255\.255)'?" -g '*.bicep' -g '**/azuredeploy*.json' -g '**/arm/**/*.json' .
rg -n --hidden "allowBlobPublicAccess:\s*true|publicAccess:\s*'(Blob|Container)'|defaultAction:\s*'Allow'|(start|end)IpAddress" -g '*.bicep' -g '*.bicepparam' -g '**/azuredeploy*.json' -g '**/arm/**/*.json' .

# --- instance metadata (item 5) ---
rg -n --hidden 'metadata_options|http_tokens|MetadataOptions|169\.254\.169\.254|metadata\.google\.internal' .
rg -n --hidden 'http_put_response_hop_limit\s*=\s*([2-9]|[1-9][0-9]+)' .   # the VALUE, not the key

# --- encryption at rest (item 6) ---
# `server_side_encryption.*enabled = false` was here and is deliberately gone: rg is
# line-based, so the multi-line HCL form everybody writes could never match it, and
# the only store it pointed at was DynamoDB, whose SSE cannot be disabled at all —
# item 6 repudiates that claim in as many words. `StorageEncrypted` is the
# CloudFormation spelling of the same defect.
rg -n --hidden 'storage_encrypted\s*=\s*false|\bencrypted\s*=\s*false|at_rest_encryption_enabled\s*=\s*false|transit_encryption_enabled\s*=\s*false|StorageEncrypted:\s*false' .
# three spellings of the same out-of-band call: SDK, CLI (hyphens), Terraform.
# `--group-names all`, not bare `--group-names`: `describe-security-groups
# --group-names default` is a benign hit and `all` is the only value that shares.
# Nothing is lost by narrowing it — the two `ModifySnapshotAttribute` spellings
# still catch the call however the group is passed.
rg -n --hidden 'aws_ami_launch_permission|aws_snapshot_create_volume_permission|ModifySnapshotAttribute|modify.snapshot.attribute|--group-names[ =]+all|aws_db_snapshot|aws_ebs_snapshot_copy|disk_encryption_set_id' .

# --- transport security flags (item 8) ---
# `minimumTlsVersion` / `supportsHttpsTrafficOnly` are the ARM and Bicep spellings of
# `min_tls_version` and the https-only flag. Both stacks are in Scope, and neither
# camelCase name shares a substring with its snake_case sibling.
rg -n --hidden 'min_tls_version|rds\.force_ssl|require_secure_transport|require_ssl|ssl_mode|ssl_policy|minimum_protocol_version|enable_https_traffic_only|https_traffic_only_enabled|minimumTlsVersion|supportsHttpsTrafficOnly' .

# --- Kubernetes workload and RBAC (items 9, 10) ---
rg -n --hidden 'privileged:\s*true|hostNetwork:\s*true|hostPID:\s*true|hostIPC:\s*true|hostPath:' .
rg -n --hidden 'containerd\.sock|crio\.sock|docker\.sock' .
rg -n --hidden 'pod-security\.kubernetes\.io/(enforce|audit|warn)' .
rg -n --hidden 'serviceaccounts/token|pods/exec|pods/attach|nodes/proxy|certificatesigningrequests|escalate|impersonate|bind' .
rg -n --hidden 'system:authenticated|system:unauthenticated|cluster-admin' .
rg -n --hidden 'type:\s*kubernetes\.io/service-account-token' .

# --- images and Dockerfiles (items 11, 12, 13) ---
# -i deliberately: Dockerfile instructions are case-insensitive to the builder, so
# `from node:latest` and `user root` are valid and a case-sensitive sweep reads a
# lowercase Dockerfile as clean. `dockerfile_root` below already folds case.
rg -ni --hidden '^FROM .*:latest|^FROM [^@]*$|^USER root|^COPY \.env|--mount=type=secret' -g 'Dockerfile*' -g '*.dockerfile' .
rg -n --hidden 'image:\s*[^@]*:(latest|main|master|dev)|imagePullPolicy' .
rg -n --hidden 'cosign verify|notation verify|verifyImages|attestations|BinaryAuthorization' .

# --- serverless (item 14) ---
# AuthType (AWS::Lambda::Url) and AuthorizationType (API Gateway) are DIFFERENT
# keys — the old sweep had only the first, so every open API Gateway route passed.
rg -n --hidden 'authorization_type\s*=\s*"NONE"|AuthType:\s*NONE|AuthorizationType:\s*NONE|DefaultAuthorizer:\s*NONE|authLevel:\s*anonymous|AuthorizationLevel\.Anonymous|--allow-unauthenticated|function_url' .

# --- state and secrets (items 15, 16) ---
rg -n --hidden 'backend\s+"(s3|azurerm|gcs|local)"|encrypt\s*=|use_lockfile|dynamodb_table' .
rg -n --hidden 'NoEcho|\{\{resolve:secretsmanager:|secretKeyRef|azurerm_key_vault_secret|google_secret_manager' .
rg --files --hidden -g '*.tfstate' -g '*.tfstate.backup' .

# --- logging, backup, region (items 17, 18, 19) ---
rg -n --hidden 'aws_cloudtrail|enable_log_file_validation|is_multi_region_trail|azurerm_monitor_diagnostic_setting|google_logging_project_sink' .
rg -n --hidden 'backup_retention_period|deletion_protection|skip_final_snapshot|point_in_time_recovery' .
rg -n --hidden 'region\s*=|location\s*=|replication_configuration|geo_replication' .

# --- BaaS rules and chart provenance (items 20, 21) ---
rg -n --hidden 'allow read, write: if true|allow .*: if true|"\.read":\s*true|"\.write":\s*true' .
# `kubectl apply -f https://` lives in Makefiles, CI workflows and install docs and
# never in a Chart.yaml, so glob-restricting it to chart files was a sweep that could
# not fire. It gets its own unrestricted line.
rg -n --hidden 'kubectl apply -f https?://|kubectl (apply|create) -k https?://|kustomize build https?://' .
# The old character class began with `"`, so a correctly pinned `version: "1.2.3"` was
# a hit. The finding is a range operator, quoted or bare — not the quote.
rg -n --hidden 'repository:\s*https?://|^\s*version:\s*["]?[\^~><*]' -g 'Chart.yaml' -g 'Chart.lock' -g 'kustomization.y*ml' .
```

**Nine of the checks below are absence sweeps, and no positive grep replaces them.** The dangerous state is the default in each case. But the obvious implementation of an absence sweep is the wrong tool, and it fails silently, so read the next paragraph before running anything.

**`rg --files-without-match` is FILE-granular, and multi-resource files are the normal case.** A `.tf` file with five buckets where one carries `aws_s3_bucket_public_access_block`, a multi-document manifest where one workload has a `securityContext`, a multi-stage `Dockerfile` with `USER node` in the builder stage and nothing in the final stage — every one of those contains the setting *somewhere*, so `--files-without-match` drops the file and the sweep reports clean over the defect. Measured on a fixture tree with two dozen planted defects — `.tf` files holding several resources each, a five-document manifest, a two-stage `Dockerfile` — the file-granular form of the six sweeps this block used to contain returned **five empty results out of six**, and the one that fired named the wrong file. **A per-file absence sweep is structurally incapable of answering "does every resource carry this setting", and it fails in the clearing direction.** It has been replaced with per-resource and per-document extraction plus a count comparison.

Six helpers do the extraction. Source them once, then every sweep is one line. They need only `find`, `xargs` and `awk`:

**`tf_absent` and `tf_count` read HCL only — never `*.tf.json`.** The awk logic keys on a column-0 block header ending in `{` and a column-0 `}`, and Terraform JSON has neither, so including `*.tf.json` in the glob asserted coverage the parser cannot deliver. Verified: on a `cdk.tf.json` carrying three unprotected buckets and an instance with no `metadata_options`, every sweep returned nothing and the count line printed a *balanced* `buckets: 0  bpa: 0` — a broken pattern wearing a clean result. That is why the count line now prints `tf-files:` beside the counts: on that same tree it reads `tf-files: 0`, which says out loud that nothing was parsed. **On a CDKTF, Terraform-JSON, Pulumi, CloudFormation or ARM-JSON repository these helpers are not a check at all**; use P1's `terraform show -json` form, which has no syntax assumption, and say in the report which one you ran. **Bicep is no longer on that list** — it has its own pair, `bicep_absent` and `bicep_count`, immediately below, because widening the `*.tf` glob would have changed what every Terraform sweep in this block parses.

**`bicep_absent` and `bicep_count` read `*.bicep` only, and four properties of Bicep decide what they can and cannot see.** The layout assumption is the same one `tf_absent` makes — a `resource` declaration at column 0 whose header ends in `{`, closed by a `}` at column 0 — which `bicep format` produces and which the deployment-per-file convention makes near-universal.

- **An `existing` reference is excluded by the header test, and must be.** `resource kv 'Microsoft.KeyVault/vaults@2023-07-01' existing = { name: … }` deploys nothing; it resolves an id. It therefore carries no properties, so a sweep that does not exclude it reports every referenced resource in the repository as missing every setting. Verified in both directions on the fixture pair.
- **The type string is `@`-terminated on purpose, and this is the Bicep analogue of the quote-termination rule below.** `Microsoft[.]DBforPostgreSQL/flexibleServers@` does not also match `Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@`, and `Microsoft[.]Storage/storageAccounts@` does not match `…/blobServices@`. Drop the `@` and a parent's absence sweep is silently cleared by its own child resource.
- **`module` declarations and nested child resources are invisible to it.** A `module` points at another `.bicep` file, so the settings live there and the parent shows nothing; a child resource written *inside* its parent's braces is part of the parent's body rather than a block of its own. Both cost coverage rather than clearing a finding — but a repository that declares its data stores through modules has **no** per-resource absence sweep here, exactly as a CDKTF one does not, and the report says so.
- **A loop header is one block for N instances**: `resource x 'type@ver' = [for name in names: {` counts once, which is the `for_each` trap `tf_meta` exists to surface, with no equivalent helper on this side. Grep `= \[for` beside any Bicep count you report, and if it hits, the number is not an instance count.

**The authoritative Bicep form is the rendered one, and unlike Terraform it needs no credentials**: `bicep build --stdout file.bicep` (or `az bicep build`) emits the ARM JSON the deployment actually submits, offline, so P1 can iterate `resources[]` with no formatting assumption at all. It is not free of caveats — it needs the `bicep` CLI, a `br:` registry module reference needs a restore that does reach the network, and `.bicepparam` values are resolved at deployment rather than at build — so say which form you ran.

**All six helpers are awk pipelines, so they exit `0` whether or not they printed anything.** The exit-status rule in this block's opening paragraph governs the `rg` lines; for these, the verdict is the stdout lines and the exit status means nothing. Measured: `bicep_absent` over the clean fixture printed 0 lines and exited 0, and over the vulnerable fixture printed 2 lines and exited 0.

```bash
# tf_absent <construct-regex> <setting-regex> [paths...]
# Every top-level HCL block whose header matches <construct-regex> and whose body
# does NOT contain <setting-regex>, as file:line plus the resource address.
# HCL only: `*.tf.json` is deliberately NOT in this glob — see the paragraph above.
tf_absent() {
  local c="$1" s="$2"; shift 2
  find "${@:-.}" -type f -name '*.tf' -print0 \
  | xargs -0 -r awk -v c="$c" -v s="$s" '
      /^[A-Za-z]/ && /\{[ \t]*$/ { inb=1; hdr=$0; ln=FNR; body=""; next }
      inb { body = body "\n" $0 }
      inb && /^\}/ { if (hdr ~ c && body !~ s) printf "%s:%d: %s\n", FILENAME, ln, hdr; inb=0 }
    '
}

# tf_count <construct-regex> [paths...] — how many top-level blocks match.
# BLOCKS, not instances: a `for_each` or `count` block is one block and N instances.
tf_count() {
  local c="$1"; shift
  find "${@:-.}" -type f -name '*.tf' -print0 \
  | xargs -0 -r awk -v c="$c" '/^[A-Za-z]/ && /\{[ \t]*$/ && $0 ~ c { n++ } END { print n+0 }' \
  | awk '{ t += $1 } END { print t+0 }'
}

# tf_meta <construct-regex> [paths...] — of those blocks, how many carry a
# `for_each` or `count`. Any non-zero result means the block count above is NOT an
# instance count and no count identity over it means anything.
tf_meta() {
  local c="$1"; shift
  find "${@:-.}" -type f -name '*.tf' -print0 \
  | xargs -0 -r awk -v c="$c" '
      /^[A-Za-z]/ && /\{[ \t]*$/ { inb=1; hdr=$0; body=""; next }
      inb { body = body "\n" $0 }
      inb && /^\}/ { if (hdr ~ c && body ~ /\n[ \t]*(for_each|count)[ \t]*=/) n++; inb=0 }
      END { print n+0 }
    ' \
  | awk '{ t += $1 } END { print t+0 }'
}

# doc_absent <kind-regex> <setting-regex> [paths...]
# Splits multi-document YAML on `---` and reports each DOCUMENT that matches
# <kind-regex> and does not contain <setting-regex>.
# The separator pattern allows a trailing comment: `--- # Source: chart/...` is what
# hand-written and some templated files carry, and a bare-`---`-only pattern merges
# every such file into ONE document, so its first compliant document clears the rest.
doc_absent() {
  local k="$1" s="$2"; shift 2
  find "${@:-.}" -type f \( -name '*.yaml' -o -name '*.yml' \) -print0 \
  | xargs -0 -r awk -v k="$k" -v s="$s" '
      function emit() { if (doc ~ k && doc !~ s) printf "%s:%d: %s\n", fn, ln, nm }
      FNR==1 { if (NR>1) emit(); fn=FILENAME; doc=""; ln=1; nm="(unnamed)" }
      /^---([ \t]+#.*)?[ \t]*$/ { emit(); doc=""; ln=FNR+1; nm="(unnamed)"; next }
      { doc = doc "\n" $0 }
      /^[ \t]*name:[ \t]*[^ \t]/ { if (nm=="(unnamed)") { nm=$0; sub(/^[ \t]*/,"",nm) } }
      END { emit() }
    '
}

# bicep_absent <type-regex> <setting-regex> [paths...]
# Every top-level `resource` declaration whose header matches <type-regex> and
# whose body does NOT contain <setting-regex>, as file:line plus the header.
# `existing` headers are excluded: they are references, not deployments, and have
# no properties to carry the setting. Bicep only — ARM JSON has no column-0 block.
bicep_absent() {
  local c="$1" s="$2"; shift 2
  find "${@:-.}" -type f \( -name '*.bicep' -o -name '*.bicepparam' \) -print0 \
  | xargs -0 -r awk -v c="$c" -v s="$s" '
      /^resource[ \t]/ && /\{[ \t]*$/ { inb=1; hdr=$0; ln=FNR; body=""; next }
      inb { body = body "\n" $0 }
      inb && /^\}/ {
        if (hdr ~ c && hdr !~ /[ \t]existing[ \t]*=/ && body !~ s)
          printf "%s:%d: %s\n", FILENAME, ln, hdr
        inb=0
      }
    '
}

# bicep_count <type-regex> [paths...] — how many top-level `resource` blocks match,
# `existing` references excluded. BLOCKS, not instances: `= [for x in y: {` is one
# block and N instances, and there is no `tf_meta` equivalent on this side.
bicep_count() {
  local c="$1"; shift
  find "${@:-.}" -type f -name '*.bicep' -print0 \
  | xargs -0 -r awk -v c="$c" '
      /^resource[ \t]/ && /\{[ \t]*$/ && $0 ~ c && $0 !~ /[ \t]existing[ \t]*=/ { n++ }
      END { print n+0 }
    ' \
  | awk '{ t += $1 } END { print t+0 }'
}

# dockerfile_root [paths...] — Dockerfiles whose FINAL stage has no USER.
# A `USER` in an earlier build stage does not apply to the shipped image, which is
# why `--files-without-match '^USER '` clears every multi-stage Dockerfile.
dockerfile_root() {
  find "${@:-.}" -type f \( -name 'Dockerfile' -o -name 'Dockerfile.*' -o -name '*.dockerfile' \) -print0 \
  | xargs -0 -r awk '
      function emit() { if (fn != "" && stage != "" && !u) printf "%s:%d: final stage never drops root: %s\n", fn, sl, stage }
      FNR==1 { if (NR>1) emit(); fn=FILENAME; stage=""; u=0 }
      /^[Ff][Rr][Oo][Mm][ \t]/ { stage=$0; sl=FNR; u=0 }
      /^[Uu][Ss][Ee][Rr][ \t]/ { u=1 }
      END { emit() }
    '
}
```

The nine sweeps:

```bash
# EC2 / launch constructs with no metadata_options block (item 5)
tf_absent 'resource +"aws_(instance|launch_template|launch_configuration)"' 'metadata_options'

# namespaces with no Pod Security Admission enforce label (item 10)
# NOTE the [.] instead of \. — awk -v eats a backslash escape and warns.
doc_absent 'kind:[ \t]*Namespace' 'pod-security[.]kubernetes[.]io/enforce'

# workload documents with no securityContext (item 9). DOCUMENT-granular, which is
# one level coarser than the finding: a clean result here means *some* container in
# the document carries it, and a Deployment whose second container has none is
# silent. Verified. Count `- name:` entries under `containers:` against
# `securityContext` blocks before you report this one clean, and remember that
# `privileged` and `capabilities` are container-only fields a pod-level
# securityContext cannot express at all.
doc_absent 'kind:[ \t]*(Deployment|StatefulSet|DaemonSet|Job|CronJob|Pod)' 'securityContext'

# stateful resources with no prevent_destroy guard (item 15)
tf_absent 'resource +"(aws_db_instance|aws_rds_cluster|aws_s3_bucket|aws_kms_key|aws_dynamodb_table|azurerm_mssql_database|google_sql_database_instance)"' 'prevent_destroy'

# S3-granting policies with no TLS-only deny (item 8). The left side now covers
# `data "aws_iam_policy_document"` too: the old left side only understood JSON
# colon form ("Effect": "Allow"), so an HCL jsonencode({ Effect = "Allow" ... })
# policy or a policy_document in its own file was never examined at all.
tf_absent 'resource +"aws_s3_bucket_policy"|data +"aws_iam_policy_document"' 'aws:SecureTransport'

# Dockerfiles whose FINAL stage never drops root (item 11)
dockerfile_root

# Block Public Access coverage (item 4) — a count comparison, because the
# bucket-to-BPA pairing is a cross-resource reference a grep cannot resolve.
#
# READ THE THREE NUMBERS TOGETHER. Equal counts do NOT prove pairing, and unequal
# counts do NOT prove a gap:
#   * two BPA resources naming the same bucket balance the identity over a third
#     bucket that has none. Verified at buckets: 3  bpa: 3 with one bucket bare.
#     Resolve the pairing by reading the `bucket =` reference on every BPA resource
#     and diffing the referenced set against the bucket set — the identity is a
#     tripwire, never the answer.
#   * `for_each`/`count` is a block, not an instance. Five bucket blocks plus one
#     `for_each` BPA prints 5 / 1 and manufactures a Critical shortfall of four;
#     one `for_each` bucket block over five names prints 1 and understates a real
#     finding fivefold. Both verified. `meta:` non-zero means stop and use P1's
#     `terraform show -json`, which counts instances.
#   * `buckets: 0` means either no buckets or a parser that cannot read this
#     repository — Terraform JSON, CDKTF, one-line blocks. A balanced zero is not
#     a clean result. The count is printed so the zero is visible as a zero.
echo "buckets: $(tf_count 'resource +"aws_s3_bucket"')" \
     "bpa: $(tf_count 'resource +"aws_s3_bucket_public_access_block"')" \
     "meta: $(tf_meta 'resource +"aws_s3_bucket(_public_access_block)?"')" \
     "tf-files: $(find . -type f -name '*.tf' | wc -l)"

# Azure data stores with no explicit private data plane (items 3, 4, 16).
# `publicNetworkAccess` DEFAULTS TO ENABLED on Key Vault, Storage, Cognitive
# Services, Search and Cosmos, so the absence of the property is the same defect as
# `'Enabled'` written out — which is why this is an absence sweep and why the
# positive `publicNetworkAccess` line above cannot replace it. The setting sits
# under `properties.network` on PostgreSQL/MySQL flexible servers and directly
# under `properties` on everything else, so the pattern is body-scoped and not
# path-scoped. Read each hit for the sibling control before filing: a
# `delegatedSubnetResourceId`, or a `Microsoft.Network/privateEndpoints` naming
# this resource, is the fix and the count line below is how you find out whether
# one exists.
bicep_absent 'Microsoft[.](KeyVault/vaults|Storage/storageAccounts|DBforPostgreSQL/flexibleServers|DBforMySQL/flexibleServers|Sql/servers|DocumentDB/databaseAccounts|Search/searchServices|CognitiveServices/accounts|Cache/[Rr]edis)@' "publicNetworkAccess:[ \t]*'Disabled'"

# Diagnostic-settings coverage (item 17) — a count comparison, for the same reason
# BPA is one: a `Microsoft.Insights/diagnosticSettings` resource names its target
# in `scope:`, which is a cross-resource reference a grep cannot resolve. READ THE
# NUMBERS TOGETHER, and read `scope:` on every diagnostic setting before you call
# it paired — two settings on one store balance the identity over a store that has
# none, exactly as two BPA resources do. **`diag: 0` with a non-zero `stores:` is
# the finding**, and it is the shape a real Bicep estate produces: no diagnostic
# setting anywhere means no Azure resource log for any of these stores exists at
# all. `bicep-files: 0` means nothing was parsed — a balanced zero is not clean.
echo "stores: $(bicep_count 'Microsoft[.](KeyVault/vaults|Storage/storageAccounts|DBforPostgreSQL/flexibleServers|DBforMySQL/flexibleServers|Sql/servers|DocumentDB/databaseAccounts)@')" \
     "diag: $(bicep_count 'Microsoft[.]Insights/diagnosticSettings@')" \
     "pe: $(bicep_count 'Microsoft[.]Network/privateEndpoints@')" \
     "bicep-files: $(find . -type f -name '*.bicep' | wc -l)"
```

Five things to keep true about these:

- **A count identity generalises, and both of its halves have to be interrogated every time.** For any absence-shaped row, `count(construct) == count(construct carrying the setting)` is a cheap tripwire where the pairing lives in a separate resource (BPA, `aws_s3_bucket_ownership_controls`, `aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_versioning`). It is only a tripwire, because **the totals can match while a specific item is unprotected, and they can diverge while everything is fine.** Ask both questions of every identity you write: *can two of the right-hand resources name the same left-hand resource?* (they can — resolve the pairing by reading the reference argument, `bucket =` for BPA) and *can one block stand for many instances?* (it can — `for_each` and `count`, which `tf_meta` exists to surface). An identity reported without those two answers is an arithmetic coincidence presented as coverage.
- **The construct regexes are quote-terminated on purpose.** `resource +"aws_s3_bucket"` does not also match `aws_s3_bucket_public_access_block`, `aws_s3_bucket_policy` or `aws_s3_bucket_ownership_controls`. Drop the closing quote and the count comparison silently balances and clears every bucket in the repository.
- **`tf_absent` assumes `terraform fmt` layout** — block opens at column 0, closes with `}` at column 0 — and a one-line `resource "x" "y" {}` is invisible to it. The authoritative form is P1's: `terraform show -json` and iterate resource addresses, which has no formatting assumption at all. Do the same on the Kubernetes side: run `kustomize build` or `helm template` first and split the *rendered* output, because a sweep over `base/` audits text the cluster never sees.
- **Two shapes make `tf_absent` over-report, and both are common enough to expect.** A heredoc whose closing `}` sits at column 0 — a `<<EOT` JSON policy body in `tags` or `policy` — ends the block early, so anything after it, including the `lifecycle` block, is read as absent. And a `aws_s3_bucket_policy` that delegates to `data.aws_iam_policy_document...json` is reported even when the *document* carries the `aws:SecureTransport` deny, because the helper cannot follow a reference. Both verified. Both cost reading time rather than clearing a finding, and both are visible on the face of the output as an address you open — which is the direction to fail in.
- **Read the granularity of each helper against the granularity of the finding.** `tf_absent` and `bicep_absent` are per-resource, `doc_absent` is per-*document* (not per-container), `dockerfile_root` is per-final-stage, `tf_count` and `bicep_count` are per-*block* (not per-instance). Where the helper is coarser than the finding — `doc_absent` for `securityContext`, `tf_count` for anything with `for_each`, `bicep_count` for a `= [for` loop or a store declared through a `module` — a clean result is a weaker fact than the row needs, and the report must say which granularity it ran at.

An absence sweep is also only as good as the construction list feeding it. When a stack in the repository is missing from the left-hand pattern, the sweep reports that whole stack clean — so before trusting a clean result, confirm the left-hand pattern matched the constructs you expected: `tf_count` or `bicep_count` with the construct regex alone, or `doc_absent <kind> 'ZZZ_NEVER_MATCHES'`, tells you the denominator. On the Azure side the denominator is also the list of resource *types* you thought to name: a Data Factory, an Event Hub namespace, an App Configuration store and a Container Registry all carry `publicNetworkAccess` too, and none of them is in the pattern above. **A denominator in blocks is not a denominator in instances** — run `tf_meta` beside it, and if it is non-zero the number you have is not the number you need.

**Four tokens whose presence reads as safety and is not.** Each is the shape that has silently cleared vulnerable configuration here before:

- `aws_s3_bucket_public_access_block` **present with flags `false`.** The resource name is what a "is BPA configured?" grep finds. Read all four booleans.
- `pod-security.kubernetes.io/enforce` **present with value `privileged`.** The label name is what a "do they use PSA?" grep finds. Read the value, and read the `-version` label beside it.
- An Azure `networkAcls` block **present with `defaultAction: 'Allow'`**, and `publicNetworkAccess` **present with `'Enabled'`.** A `networkAcls` block is what a "does this resource restrict its network?" grep finds, and with `defaultAction: 'Allow'` it restricts nothing — the `ipRules` and `virtualNetworkRules` under it are then decorative, because everything not named is allowed too. The safe shape is `defaultAction: 'Deny'`; `bypass: 'AzureServices'` beside a `Deny` is a scoped first-party exemption and not the same finding.
- A scanner suppression next to the defect: `#checkov:skip=`, `# tfsec:ignore:`, `# nosemgrep`, `@kics-scan ignore-line`, `--soft-fail`. A suppression comment is evidence a scanner *did* fire and someone silenced it. Read the justification, or note its absence.

### 1. Identity and resource policy scope (`iam-policy-and-privilege-scope`)

**Audit both halves of the grant graph.** Inside one account, access is allowed if *either* an identity policy or the resource's own policy allows it, and there is no requirement that the two agree. Reading only `aws_iam_policy`, `aws_iam_role_policy` and `aws_iam_policy_document` and reporting "least privilege looks reasonable" leaves every resource-side grant unaudited. Enumerate the resource-policy resources explicitly: `aws_s3_bucket_policy`, `aws_kms_key_policy` (and inline `policy` on `aws_kms_key`), `aws_sqs_queue_policy`, `aws_sns_topic_policy`, `aws_lambda_permission`, `aws_ecr_repository_policy`, `aws_cloudwatch_event_bus_policy`, `aws_secretsmanager_secret_policy`, `aws_api_gateway_rest_api` policy, `aws_efs_file_system_policy`, `aws_glacier_vault` access policy.

**An explicit `Deny` always wins, so never report that something "overrides" a deny.** If you find a `Deny` in an SCP, a permissions boundary, a resource policy or an identity policy that covers the action, the access is denied — full stop. Where you can see a `Deny` that covers the finding, say so and drop the finding. Where the `Deny` would live outside the repository (an SCP in the management account), say that you cannot see it and keep the finding at the lower severity with the assumption written out.

The escalation actions to grep for by name, because each one converts any principal holding it into an administrator: `iam:PassRole`, `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:AttachRolePolicy`, `iam:AttachUserPolicy`, `iam:PutRolePolicy`, `iam:PutUserPolicy`, `iam:UpdateAssumeRolePolicy`, `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `sts:AssumeRole`, `lambda:UpdateFunctionCode`, `glue:UpdateDevEndpoint`, `cloudformation:CreateStack` with a passed role, `ssm:SendCommand`, `ec2:RunInstances` paired with `iam:PassRole`.

**`iam:PassRole` with `Resource: "*"` is the single highest-value grep in this item** and stays Critical: it lets the holder hand any role in the account to a service they control. The scoping that fixes it is a role-ARN resource plus an `iam:PassedToService` condition.

**Judge a condition block before you credit it.** A `Condition` only narrows a statement if the key it tests is *identity-bearing*. `aws:PrincipalOrgID`, `aws:SourceAccount`, `aws:SourceArn`, `sts:ExternalId`, `aws:PrincipalArn`, an OIDC `sub` with `StringEquals` — those narrow. `aws:SecureTransport`, `aws:RequestedRegion` alone, `aws:UserAgent`, `aws:Referer` do not: a `Principal: "*"` statement whose only condition is `Bool: {"aws:SecureTransport": "true"}` is open to the internet over HTTPS. This is the most common way a wildcard principal survives review.

**Confused deputy.** A resource policy whose principal is a **service** (`{"Service": "events.amazonaws.com"}`, `s3.amazonaws.com`, `cloudfront.amazonaws.com`, `logs.amazonaws.com`, `sns.amazonaws.com`) and which carries no `aws:SourceAccount` or `aws:SourceArn` condition lets that service, acting for *any* customer, invoke or read the resource. In Terraform the fix is `source_account` and `source_arn` arguments on `aws_lambda_permission`, or the corresponding condition keys in a policy document. Grep for the service principal and then for the **absence** of the condition — the vulnerable form is the one with nothing there.

**Long-lived credentials where a role would do.** An `aws_iam_access_key` resource, or an IAM user with an attached policy, in a repository that also has OIDC or instance-profile machinery is a credential that must be rotated by hand and that appears in state. The console-side facts — whether a human user has MFA, whether the root account is used — are account state this audit cannot read; the *checkable* proxy is whether privileged policies carry a `Bool: {"aws:MultiFactorAuthPresent": "true"}` condition and whether root-usage alerting exists (item 17). Report the checkable half and record the rest as an open question.

**Azure.** Owner or Contributor at subscription or management-group scope; a service principal with a client secret where a managed identity or a workload-identity federated credential would do; a managed identity whose role assignment scope is the subscription rather than the resource group or resource. The directory is **Entra ID**; searching for "Azure AD" or "AAD" finds prose, not configuration.

**GCP.** **Basic roles** (`roles/owner`, `roles/editor`, `roles/viewer`) on a project; `google_service_account_key` resources, which materialize a downloadable long-lived key where Workload Identity Federation would not; `roles/iam.serviceAccountUser` or `roles/iam.serviceAccountTokenCreator` granted broadly, which is impersonation and therefore escalation; the default Compute Engine service account attached to GKE nodes or instances, which carries Editor on the project unless someone changed it.

**Unused-permission detection is a real gap, and the control must be named correctly.** IAM Access Analyzer **unused access findings** for AWS; **Entra Permissions Management** (CIEM) plus Entra ID access reviews for Azure, with **PIM only for just-in-time elevation — PIM does not detect unused permissions**; IAM Recommender / Policy Analyzer for GCP. Recommend Access Analyzer as a manual follow-up for the operator; do not call it from inside an audit, because that is a credentialed network call to the provider.

```detector
match: |
  data "aws_iam_policy_document" "deployer" {
    statement {
      effect    = "Allow"
      actions   = ["iam:PassRole", "ec2:RunInstances"]
      resources = ["*"]
    }
  }
nomatch: |
  data "aws_iam_policy_document" "deployer" {
    statement {
      effect    = "Allow"
      actions   = ["iam:PassRole"]
      resources = [aws_iam_role.ec2_app.arn]
      condition {
        test     = "StringEquals"
        variable = "iam:PassedToService"
        values   = ["ec2.amazonaws.com"]
      }
    }
    statement {
      effect    = "Allow"
      actions   = ["ec2:RunInstances"]
      resources = ["arn:aws:ec2:us-east-1:111122223333:instance/*"]
    }
  }
```

```detector
match: |
  resource "aws_sqs_queue_policy" "ingest" {
    queue_url = aws_sqs_queue.ingest.id
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect    = "Allow"
        Principal = "*"
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.ingest.arn
        Condition = { Bool = { "aws:SecureTransport" = "true" } }
      }]
    })
  }
nomatch: |
  resource "aws_sqs_queue_policy" "ingest" {
    queue_url = aws_sqs_queue.ingest.id
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.ingest.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
          ArnLike      = { "aws:SourceArn" = aws_s3_bucket.uploads.arn }
        }
      }]
    })
  }
```

```detector
match: |
  resource "aws_lambda_permission" "from_eventbridge" {
    statement_id  = "AllowExecutionFromEventBridge"
    action        = "lambda:InvokeFunction"
    function_name = aws_lambda_function.processor.function_name
    principal     = "events.amazonaws.com"
  }
nomatch: |
  resource "aws_lambda_permission" "from_eventbridge" {
    statement_id   = "AllowExecutionFromEventBridge"
    action         = "lambda:InvokeFunction"
    function_name  = aws_lambda_function.processor.function_name
    principal      = "events.amazonaws.com"
    source_account = data.aws_caller_identity.current.account_id
    source_arn     = aws_cloudwatch_event_rule.nightly.arn
  }
```

```detector
match: |
  resource "google_project_iam_member" "ci" {
    project = var.project_id
    role    = "roles/editor"
    member  = "serviceAccount:${google_service_account.ci.email}"
  }

  resource "google_service_account_key" "ci" {
    service_account_id = google_service_account.ci.name
  }
nomatch: |
  resource "google_project_iam_member" "ci" {
    project = var.project_id
    role    = "roles/artifactregistry.writer"
    member  = "serviceAccount:${google_service_account.ci.email}"
  }

  resource "google_iam_workload_identity_pool_provider" "github" {
    workload_identity_pool_id          = google_iam_workload_identity_pool.ci.workload_identity_pool_id
    workload_identity_pool_provider_id = "github"
    attribute_mapping = {
      "google.subject"       = "assertion.sub"
      "attribute.repository" = "assertion.repository"
    }
    attribute_condition = "assertion.repository == 'acme/api'"
    oidc { issuer_uri = "https://token.actions.githubusercontent.com" }
  }
```

### 2. Federated trust policies (`cloud-oidc-trust-policy`)

A trust policy is where a foreign identity provider becomes a principal in the account, and a wildcard in the wrong segment of one string gives an entire GitHub organization — or an entire cloud region's worth of tenants — the role.

Check, in order:

- **The `sub` condition exists and is not wildcarded in a load-bearing segment.** `token.actions.githubusercontent.com:sub` of `repo:acme/*:*` is satisfied by every repository in the org; `repo:acme/api:*` is satisfied by every branch, tag and pull request of that repository. **Name the trigger, because only some of them reach it:** a `pull_request` run from a fork cannot be granted `id-token: write`, so it cannot mint an OIDC token at all; the shapes that do produce a `repo:acme/api:pull_request` subject are **`pull_request_target`** and **`workflow_run`**, which run in the base repository's context with its permissions. Pin to a ref or an environment: `repo:acme/api:ref:refs/heads/main` or `repo:acme/api:environment:production`. Which workflows may request a token is cicd's `ci-oidc-workflow-configuration`; hand them the trigger and keep the trust-policy finding here.
- **The `aud` condition exists.** Without an audience check the role accepts a token minted for a different relying party.
- **`StringLike` versus `StringEquals`.** A `StringLike` with no `*` is a `StringEquals` written the long way and is fine. A `StringEquals` cannot be wildcarded. The finding is `StringLike` **with** a `*` in the repository, branch or subject segment.
- **The OIDC provider's thumbprint or issuer URL** points at the intended issuer, and `aws_iam_openid_connect_provider` `client_id_list` is not empty.
- **GCP** — `attribute_condition` present on `google_iam_workload_identity_pool_provider`, not just an `attribute_mapping`. A mapping without a condition maps every token in the issuer into the pool.
- **Azure** — a federated identity credential's `subject` and `issuer`, and whether a client **secret** exists alongside it, which defeats the point of federation.
- **In-cluster identity annotations** — `eks.amazonaws.com/role-arn`, `iam.gke.io/gcp-service-account`, `azure.workload.identity/use`. Read the trust policy on the other end: an IRSA role whose condition is on the OIDC provider but *not* on `sub` is assumable by every service account in the cluster. This is the pod-identity case; note that "Azure AD Pod Identity" is retired and the current mechanism is Entra Workload ID.

```detector
match: |
  data "aws_iam_policy_document" "gha_trust" {
    statement {
      effect  = "Allow"
      actions = ["sts:AssumeRoleWithWebIdentity"]
      principals {
        type        = "Federated"
        identifiers = [aws_iam_openid_connect_provider.github.arn]
      }
      condition {
        test     = "StringLike"
        variable = "token.actions.githubusercontent.com:sub"
        values   = ["repo:acme/*:*"]
      }
    }
  }
nomatch: |
  data "aws_iam_policy_document" "gha_trust" {
    statement {
      effect  = "Allow"
      actions = ["sts:AssumeRoleWithWebIdentity"]
      principals {
        type        = "Federated"
        identifiers = [aws_iam_openid_connect_provider.github.arn]
      }
      condition {
        test     = "StringEquals"
        variable = "token.actions.githubusercontent.com:aud"
        values   = ["sts.amazonaws.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "token.actions.githubusercontent.com:sub"
        values   = ["repo:acme/api:environment:production"]
      }
    }
  }
```

```detector
match: |
  data "aws_iam_policy_document" "irsa_trust" {
    statement {
      effect  = "Allow"
      actions = ["sts:AssumeRoleWithWebIdentity"]
      principals {
        type        = "Federated"
        identifiers = [aws_iam_openid_connect_provider.eks.arn]
      }
      condition {
        test     = "StringEquals"
        variable = "${local.oidc_host}:aud"
        values   = ["sts.amazonaws.com"]
      }
    }
  }
nomatch: |
  data "aws_iam_policy_document" "irsa_trust" {
    statement {
      effect  = "Allow"
      actions = ["sts:AssumeRoleWithWebIdentity"]
      principals {
        type        = "Federated"
        identifiers = [aws_iam_openid_connect_provider.eks.arn]
      }
      condition {
        test     = "StringEquals"
        variable = "${local.oidc_host}:aud"
        values   = ["sts.amazonaws.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "${local.oidc_host}:sub"
        values   = ["system:serviceaccount:prod:api"]
      }
    }
  }
```

### 3. Network exposure and segmentation (`network-exposure-and-segmentation`)

**Hold to the sensitive-port list, and check attachment before you claim exposure.** `0.0.0.0/0` on 80 or 443 attached to a public load balancer is the intended design, and egress `0.0.0.0/0` is the default almost everywhere. The ports that carry a finding: **22** (SSH), **3389** (RDP), **3306** (MySQL), **5432** (Postgres), **27017** (MongoDB), **6379** (Redis), **1433** (MSSQL), **9200**/**9300** (Elasticsearch/OpenSearch), **2375**/**2376** (Docker API), **5984** (CouchDB), **11211** (memcached), **9000** (various admin consoles), and **`from_port = 0, to_port = 65535`** or `protocol = "-1"`, which is every port including all of the above.

Also check `::/0` — an IPv6 any-source rule is the same finding and is routinely omitted from both configurations and reviews.

**A managed database is the highest-severity form.** `publicly_accessible = true` on `aws_db_instance` or `aws_rds_cluster_instance`, `public_network_access_enabled = true` on Azure SQL or PostgreSQL Flexible Server, `ipv4_enabled = true` with an `authorized_networks` CIDR of `0.0.0.0/0` on Cloud SQL. Paired with an open engine port, that is Critical.

**Subnet and IP placement:** `map_public_ip_on_launch = true` on a subnet, or an instance in a public subnet with `associate_public_ip_address = true` that does not serve public traffic. This — not the existence of a default VPC — is the real defect behind "default VPC used for production": the default VPC's subnets have `map_public_ip_on_launch` on.

**Azure NSGs:** `source_address_prefix = "*"` or `"Internet"` with a `destination_port_range` covering a sensitive port, and rules whose `priority` places them ahead of the deny. In Bicep and ARM the same rule reads `sourceAddressPrefix: 'Internet'` with `destinationPortRange` under `properties.securityRules[].properties`, and `access: 'Allow'` with a lower `priority` number than the deny that follows it. **GCP:** `google_compute_firewall` with `source_ranges = ["0.0.0.0/0"]`, and an auto-mode default network, whose pre-populated rules allow SSH and RDP from anywhere.

**Azure PaaS resource firewalls are a different artifact from an NSG, and on a Bicep repository they are where this item's findings actually are.** An NSG governs traffic to a subnet or a NIC; a managed store's own data plane is reached over the internet regardless of any NSG, and two properties decide it. Name them by their exact paths, because none of them shares a substring with its Terraform sibling:

- **`publicNetworkAccess`.** `properties.network.publicNetworkAccess: 'Enabled'` on `Microsoft.DBforPostgreSQL/flexibleServers` and `Microsoft.DBforMySQL/flexibleServers`; `properties.publicNetworkAccess: 'Enabled'` on `Microsoft.Sql/servers`, `Microsoft.KeyVault/vaults`, `Microsoft.Storage/storageAccounts`, `Microsoft.DocumentDB/databaseAccounts`, `Microsoft.Search/searchServices`, `Microsoft.CognitiveServices/accounts`. **The default is `Enabled` on the vault, storage, search and Cognitive Services types, so its absence is the same finding as the value written out** — grep the absence with `bicep_absent`, per item 0. The fix is `'Disabled'` plus a `Microsoft.Network/privateEndpoints` resource naming the store in `privateLinkServiceConnections[].properties.privateLinkServiceId`, or — for a flexible server — VNet injection via `properties.network.delegatedSubnetResourceId`, which makes `publicNetworkAccess` moot and forbids firewall rules outright.
- **`properties.networkAcls.defaultAction`.** `'Allow'` means the `ipRules` and `virtualNetworkRules` beside it narrow nothing. `'Deny'` is the enforcing value; `bypass: 'AzureServices'` beside a `Deny` exempts named first-party services (this is what lets a diagnostic setting write) and is not an open door.

**The `0.0.0.0`–`0.0.0.0` firewall rule is the Azure gotcha most likely to be missed, and it is missed because it does not look like `0.0.0.0/0`.** On `Microsoft.DBforPostgreSQL/flexibleServers/firewallRules`, `Microsoft.DBforMySQL/flexibleServers/firewallRules` and `Microsoft.Sql/servers/firewallRules`, a rule whose `properties.startIpAddress` **and** `properties.endIpAddress` are both `'0.0.0.0'` is not a range and not a CIDR: it is Azure's sentinel for **"allow all Azure services and resources within Azure IPs"**, and the portal writes it under exactly that name. Read what it grants precisely, because both the over- and the under-statement discredit the finding:

- It admits traffic from Azure IP space **across every tenant**, not just this subscription — so any attacker with a trial Azure subscription is inside the network boundary and the administrator password or Entra token is the only remaining control. That is the finding, and it is why the pair is graded with `publicNetworkAccess` rather than on its own.
- It is **not** the whole internet. The rule that is spelled `'0.0.0.0'` to `'255.255.255.255'`, and that one is a separate and worse finding — file it as the internet-wide rule it is.
- It is **inert when the public data plane is off.** A flexible server with `delegatedSubnetResourceId` cannot carry firewall rules at all, and a store with `publicNetworkAccess: 'Disabled'` does not consult them. Establish which state the store is in before grading the rule, and say which.
- The two properties are on **separate lines**, so a line-based grep sees each half alone and can decide nothing from either. Item 0 carries a `-U` line for the pair and an order-independent candidate line beside it.

**Kubernetes.** `Service` of `type: LoadBalancer` for a workload that should be cluster-internal — check for the internal-LB annotation (`service.beta.kubernetes.io/aws-load-balancer-internal`, `service.beta.kubernetes.io/azure-load-balancer-internal`, `networking.gke.io/load-balancer-type: "Internal"`) before filing. And **NetworkPolicy absence is a real finding phrased as an absence**: with no policy selecting a pod, all ingress and egress are allowed, so the question is whether *any* `kind: NetworkPolicy` selects the namespace's workloads, plus whether the CNI in use enforces them at all (Flannel does not).

```detector
match: |
  resource "aws_security_group" "db" {
    name   = "db"
    vpc_id = aws_vpc.main.id

    ingress {
      from_port   = 5432
      to_port     = 5432
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
nomatch: |
  resource "aws_security_group" "db" {
    name   = "db"
    vpc_id = aws_vpc.main.id

    ingress {
      from_port       = 5432
      to_port         = 5432
      protocol        = "tcp"
      security_groups = [aws_security_group.app.id]
    }
  }
```

```detector
match: |
  resource "aws_db_instance" "app" {
    identifier          = "app"
    engine              = "postgres"
    publicly_accessible = true
    db_subnet_group_name = aws_db_subnet_group.public.name
  }
nomatch: |
  resource "aws_db_instance" "app" {
    identifier           = "app"
    engine               = "postgres"
    publicly_accessible  = false
    db_subnet_group_name = aws_db_subnet_group.private.name
    vpc_security_group_ids = [aws_security_group.db.id]
  }
```

The same defect in Bicep. The `match` side contains no `0.0.0.0/0`, no `::/0` and no `publicly_accessible`, which is why the Terraform-shaped sweeps read it as clean:

```detector
match: |
  resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-06-01-preview' = {
    name: serverName
    location: location
    properties: {
      version: '16'
      administratorLogin: administratorLogin
      administratorLoginPassword: administratorLoginPassword
      network: {
        publicNetworkAccess: 'Enabled'
      }
    }
  }

  resource allowAzureServices 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2023-06-01-preview' = {
    parent: postgres
    name: 'AllowAllAzureServicesAndResourcesWithinAzureIps'
    properties: {
      startIpAddress: '0.0.0.0'
      endIpAddress: '0.0.0.0'
    }
  }
nomatch: |
  resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-06-01-preview' = {
    name: serverName
    location: location
    properties: {
      version: '16'
      administratorLogin: administratorLogin
      administratorLoginPassword: administratorLoginPassword
      network: {
        publicNetworkAccess: 'Disabled'
        delegatedSubnetResourceId: databaseSubnetId
        privateDnsZoneArmResourceId: databasePrivateDnsZoneId
      }
    }
  }
```

```detector
match: |
  apiVersion: v1
  kind: Service
  metadata:
    name: internal-admin
    namespace: prod
  spec:
    type: LoadBalancer
    ports:
      - port: 8080
        targetPort: 8080
    selector:
      app: admin
nomatch: |
  apiVersion: v1
  kind: Service
  metadata:
    name: internal-admin
    namespace: prod
    annotations:
      service.beta.kubernetes.io/aws-load-balancer-internal: "true"
      service.beta.kubernetes.io/aws-load-balancer-scheme: internal
  spec:
    type: ClusterIP
    ports:
      - port: 8080
        targetPort: 8080
    selector:
      app: admin
```

### 4. Object storage exposure (`object-storage-exposure`)

**Block Public Access is the backstop. Check whether it is enforcing; do not look for a policy that beat it.** Nothing in a bucket policy or an ACL can defeat BPA, so the finding is BPA off or absent:

- **Account level:** `aws_s3_account_public_access_block` absent from the repository, or present with any of `block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets` set to `false`. Account-level BPA overrides every bucket, which is why its absence is the highest-leverage fact in this item — and why, when the repository does not manage it, you record it as an unknown rather than assuming either way.
- **Bucket level:** `aws_s3_bucket_public_access_block` absent, or any of the same four flags `false`. In CloudFormation the equivalent is `PublicAccessBlockConfiguration` with `BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, `RestrictPublicBuckets`.
- **ACLs re-enabled on purpose:** `aws_s3_bucket_ownership_controls` with `object_ownership = "ObjectWriter"` or `"BucketOwnerPreferred"`. Since April 2023 a new bucket ships with ACLs disabled (`BucketOwnerEnforced`), so an explicit ownership-controls resource that turns them back on is a deliberate act and worth a finding of its own — it is also the only way `acl = "public-read"` still applies at all.

**Since April 2023 new buckets ship with BPA enabled and ACLs disabled.** That narrows this item and raises its confidence in both directions: a bucket that *is* public in a modern account was almost certainly made public deliberately, and a config that turns BPA off is a deliberate act rather than an omission. Say which you established, and note the bucket's creation era if the repository shows it — a long-lived bucket predating the default change can be public by accident.

**Then read the grants,** because BPA on does not make the bucket private to *authenticated* strangers:

- `Principal: "*"` or `{"AWS": "*"}` in a bucket policy with no identity-bearing condition.
- GCS `allUsers` and `allAuthenticatedUsers` in `google_storage_bucket_iam_member` / `_binding`. **`allAuthenticatedUsers` means every Google account on earth, not every account in your org** — it is not a lesser finding than `allUsers`. **The two tokens share no substring, so grep both.** `allAuthenticatedUsers` does not contain `allUsers` — the characters are not contiguous — so a rule implemented as a single `allUsers` match reports clean on a bucket granted to every Google account alive. Grep `allUsers|allAuthenticatedUsers` and read the whole value.
- Azure `allow_blob_public_access` / `allow_nested_items_to_be_public` on the storage account, and a container with `container_access_type = "blob"` or `"container"`. **Both are anonymous read**; `"container"` additionally allows listing, which is the aggravator, not the threshold. **In Bicep and ARM the two properties are `properties.allowBlobPublicAccess: true` on `Microsoft.Storage/storageAccounts` and `properties.publicAccess: 'Blob'` or `'Container'` on `Microsoft.Storage/storageAccounts/blobServices/containers`** — and since 2023 the account-level flag defaults to `false` on new accounts, so `true` written out is a deliberate act and the container-level value only applies when it is. Read the account's `publicNetworkAccess` and `networkAcls.defaultAction` beside them, per item 3: an account whose data plane is private is not anonymously readable whatever the container says, and an account with `defaultAction: 'Allow'` is reachable by anyone with the URL and a key.
- **Public listing versus public get.** `s3:ListBucket` to an anonymous principal turns the bucket into an index of every key, which is what converts "one public asset" into a full enumeration.
- **Cross-account grants** in a bucket policy: read the account id in the principal and say whose it is.

**CloudFront in front of S3 does not make the bucket private.** Check for an origin access control (`aws_cloudfront_origin_access_control`) or the legacy OAI, plus a bucket policy that grants only the CloudFront service principal with an `AWS:SourceArn` on the distribution. Without it the bucket is reachable directly at its own endpoint, bypassing whatever the distribution enforces.

```detector
match: |
  resource "aws_s3_bucket" "exports" {
    bucket = "acme-exports"
  }

  resource "aws_s3_bucket_public_access_block" "exports" {
    bucket                  = aws_s3_bucket.exports.id
    block_public_acls       = false
    block_public_policy     = false
    ignore_public_acls      = false
    restrict_public_buckets = false
  }
nomatch: |
  resource "aws_s3_bucket" "exports" {
    bucket = "acme-exports"
  }

  resource "aws_s3_bucket_public_access_block" "exports" {
    bucket                  = aws_s3_bucket.exports.id
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }

  resource "aws_s3_account_public_access_block" "account" {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
```

```detector
match: |
  resource "google_storage_bucket_iam_member" "public_read" {
    bucket = google_storage_bucket.reports.name
    role   = "roles/storage.objectViewer"
    member = "allAuthenticatedUsers"
  }
nomatch: |
  resource "google_storage_bucket_iam_member" "app_read" {
    bucket = google_storage_bucket.reports.name
    role   = "roles/storage.objectViewer"
    member = "serviceAccount:${google_service_account.api.email}"
  }
```

```detector
match: |
  resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
    name: storageAccountName
    location: location
    kind: 'StorageV2'
    sku: {
      name: 'Standard_LRS'
    }
    properties: {
      allowBlobPublicAccess: true
      networkAcls: {
        defaultAction: 'Allow'
        ipRules: [
          {
            value: '203.0.113.0/24'
          }
        ]
      }
    }
  }

  resource exports 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
    name: '${storageAccountName}/default/exports'
    properties: {
      publicAccess: 'Container'
    }
  }
nomatch: |
  resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
    name: storageAccountName
    location: location
    kind: 'StorageV2'
    sku: {
      name: 'Standard_ZRS'
    }
    properties: {
      publicNetworkAccess: 'Disabled'
      allowBlobPublicAccess: false
      allowSharedKeyAccess: false
      minimumTlsVersion: 'TLS1_2'
      supportsHttpsTrafficOnly: true
      networkAcls: {
        defaultAction: 'Deny'
        bypass: 'AzureServices'
      }
    }
  }

  resource exports 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
    name: '${storageAccountName}/default/exports'
    properties: {
      publicAccess: 'None'
    }
  }
```

The `ipRules` entry on the `match` side is the point of that detector: it reads as an allow-list and narrows nothing, because `defaultAction: 'Allow'` already admitted every address that is not in it.

```detector
match: |
  resource "aws_s3_bucket_ownership_controls" "assets" {
    bucket = aws_s3_bucket.assets.id
    rule {
      object_ownership = "ObjectWriter"
    }
  }

  resource "aws_s3_bucket_acl" "assets" {
    bucket = aws_s3_bucket.assets.id
    acl    = "public-read"
  }
nomatch: |
  resource "aws_s3_bucket_ownership_controls" "assets" {
    bucket = aws_s3_bucket.assets.id
    rule {
      object_ownership = "BucketOwnerEnforced"
    }
  }
```

### 5. Instance metadata service (`imds-hardening`)

The metadata service hands out the instance's role credentials to anything that can make an HTTP request from the instance, which is why it is the payoff half of every server-side request forgery chain in this domain.

**Grep for the absence.** `http_tokens = "required"` is the safe value and nobody types the unsafe one: with no `metadata_options` block at all, IMDSv1 is permitted. So:

- `aws_instance`, `aws_launch_template`, `aws_launch_configuration`, `aws_eks_node_group` (via its launch template), and the CDK/CloudFormation `MetadataOptions` — check for a `metadata_options` block, then for `http_tokens = "required"` inside it. `"optional"` is the explicit vulnerable value; a missing block is the implicit one.
- **`http_put_response_hop_limit` is the IP TTL of the IMDS PUT (token) response, so it bounds how many hops away the *requester* may be — and `>= 2` is the finding for ordinary, CNI/bridge-networked pods.** Those pods live in their own network namespace, so reaching the node's IMDS costs them one extra hop; a hop limit of 2 is what lets every one of them retrieve the node instance-profile credentials. This is the **default on EKS managed node groups**, so on an EKS repository expect to find it, and file it — "pods can steal the worker node's AWS credentials" is the catalogued outcome. Grep the value, not just the key: `http_put_response_hop_limit\s*=\s*([2-9]|[1-9][0-9]+)`.
- **The other direction, because getting it backwards closes a live item: a `hostNetwork: true` pod shares the node's network namespace, so it reaches IMDS at hop limit 1 and the hop limit is irrelevant to it.** Never record `http_put_response_hop_limit = 1` as the mitigating control for a `hostNetwork` workload. For those the only controls are `http_tokens = "required"` (which forces the PUT, so an SSRF that can only issue GETs fails) plus a node-level block, and IRSA / EKS Pod Identity so nothing needs the node role at all.
- `http_endpoint = "disabled"` where nothing needs metadata at all is the strongest form.
- **Kubernetes and ECS:** whether the pod or task can reach `169.254.169.254` **at all**. Three artifacts decide it, and only these three: an **egress `NetworkPolicy` denying `169.254.169.254/32`** — and only on a CNI that enforces egress, so establish the CNI, because Flannel enforces nothing; **IMDS blocked at the node** (iptables/nftables, or `http_put_response_hop_limit = 1`, which stops a pod in its own netns but not a `hostNetwork` pod); and **IRSA or EKS Pod Identity** so no workload needs the node role. On GKE, Workload Identity with metadata concealment; `metadata.google.internal` reachable from a pod that uses the node's default service account is the same defect with a different endpoint.
- **`AWS_EC2_METADATA_DISABLED=true` is not a reachability control and must not close this item.** It is an **AWS SDK environment variable**: it stops the SDK *in that one process* from consulting IMDS. The endpoint still answers `curl`, it still answers a shell-out, and it still answers an SSRF payload — and an SSRF payload is not written with an SDK. Finding it in a pod spec or task definition changes nothing about reachability; record it as a hardening nicety and keep the finding open. This is the same reasoning as rejected candidate 2, and per Scope, naming the wrong mitigating control is worse than a dead check.
- **Azure** — the IMDS endpoint is the same address, and a container workload that can reach it can request a token for the host's managed identity.

The application-side half of this — code that fetches a user-supplied URL — is web-and-api's `ssrf-application-path`. File both and note the pairing in `impact`.

```detector
match: |
  resource "aws_launch_template" "workers" {
    name_prefix   = "workers"
    image_id      = data.aws_ami.al2023.id
    instance_type = "m6i.large"

    iam_instance_profile {
      name = aws_iam_instance_profile.workers.name
    }
  }
nomatch: |
  resource "aws_launch_template" "workers" {
    name_prefix   = "workers"
    image_id      = data.aws_ami.al2023.id
    instance_type = "m6i.large"

    metadata_options {
      http_endpoint               = "enabled"
      http_tokens                 = "required"
      http_put_response_hop_limit = 1
      instance_metadata_tags      = "disabled"
    }

    iam_instance_profile {
      name = aws_iam_instance_profile.workers.name
    }
  }
```

### 6. Encryption at rest (`encryption-at-rest-configuration`)

**Do not report "no encryption" from the absence of an encryption block.** Since January 2023 S3 applies SSE-S3 (AES-256) to **every new object upload in every bucket** — not only new buckets — and it cannot be switched off; Azure Storage and GCS have always encrypted at rest with platform-managed keys and offer no off switch. A missing `aws_s3_bucket_server_side_encryption_configuration` therefore does not mean unencrypted, in an old bucket any more than a new one, and reporting it that way is the fastest route to losing the reader.

What *is* a finding:

- **An explicit disable, where one is possible — and the argument name differs per resource, so name the right one.** `aws_ebs_volume` with `encrypted = false`; `aws_ebs_encryption_by_default` with **`enabled = false`** (that resource has no `encrypted` argument, and it is account-level, so its absence means the account default is whatever somebody set in the console); `aws_db_instance` / `aws_rds_cluster` with `storage_encrypted = false`; `azurerm_managed_disk` with no `disk_encryption_set_id` where a CMK is required; an ElastiCache or OpenSearch cluster with `at_rest_encryption_enabled = false`; a Kubernetes `EncryptionConfiguration` you can actually see with `identity` first in the provider list.
- **DynamoDB is not on that list, and putting it there repeats this item's own mistake.** DynamoDB encrypts at rest unconditionally; `server_side_encryption { enabled = false }` on `aws_dynamodb_table` selects the **AWS-owned key** instead of a customer-managed one — it does not turn encryption off. So it belongs under the key-ownership claim below, not here, and "DynamoDB table not encrypted" is as stale as "bucket has no SSE block."
- **A key-ownership requirement that is not met** — and this must be framed as the narrower claim it is: *"no customer-managed key (SSE-KMS, CMEK, or a disk encryption set) where the data classification or the contract requires key ownership and revocability."* Say which classification or contract clause makes it required. If you cannot name one, the claim is "platform-managed keys in use", which is a fact, not a finding.
- **Snapshots and backups**, which are a separate resource with their own setting: `aws_db_snapshot`, `aws_ebs_snapshot` (and `aws_ebs_snapshot_copy` with `encrypted`/`kms_key_id`), Azure snapshot encryption, and any manual export to a bucket. An encrypted primary with an unencrypted export is the finding this item most often turns up.
- **A publicly shared image or snapshot**, which is an exposure rather than an encryption finding. Get the literals right, because two plausible-looking ones do not exist:
  - **The real one is `aws_ami_launch_permission` with `group = "all"`** — `group` takes exactly one valid value, `"all"`, and that makes the AMI public to every AWS account. Grep for it by name.
  - **`aws_ami` has no settable `public` argument.** `public` is a read-only *exported attribute*, so "an AMI with `public = true`" can never appear in valid Terraform and a check keyed to it is unfireable.
  - **Terraform cannot express a public EBS snapshot at all.** `aws_snapshot_create_volume_permission` accepts `snapshot_id` and `account_id` (and `region`) — there is no `group` argument and no public option, and `account_id = "all"` is not a valid account id. What that resource *does* express is a share to a **named foreign account**: read the twelve digits and say whose they are. A genuinely public EBS snapshot is made out of band, so the artifact to look for is a `ModifySnapshotAttribute --group-names all` in a script, a Makefile or an SDK call; the live snapshot-attribute state is account state this audit cannot read, and it is recorded as an open question with the console path.

The data class that decides how much any of this matters is hipaa's or privacy's. Supply the storage-layer facts; do not grade them.

```detector
match: |
  resource "aws_db_instance" "app" {
    identifier        = "app"
    engine            = "postgres"
    storage_encrypted = false
  }

  resource "aws_ebs_volume" "data" {
    availability_zone = "us-east-1a"
    size              = 500
    encrypted         = false
  }
nomatch: |
  resource "aws_db_instance" "app" {
    identifier        = "app"
    engine            = "postgres"
    storage_encrypted = true
    kms_key_id        = aws_kms_key.rds.arn
  }

  resource "aws_ebs_volume" "data" {
    availability_zone = "us-east-1a"
    size              = 500
    encrypted         = true
    kms_key_id        = aws_kms_key.ebs.arn
  }
```

```detector
match: |
  resource "aws_ami_launch_permission" "share" {
    image_id = aws_ami_from_instance.golden.id
    group    = "all"
  }
nomatch: |
  resource "aws_ami_launch_permission" "share" {
    image_id   = aws_ami_from_instance.golden.id
    account_id = "444455556666"
  }
```

### 7. KMS key policy and lifecycle (`kms-key-lifecycle-and-policy`)

**The default key policy is not a finding.** `{"Principal": {"AWS": "arn:aws:iam::<this-account>:root"}, "Action": "kms:*", "Resource": "*"}` is what the console, CloudFormation and Terraform all generate. The `root` ARN does not mean the root *user*; it delegates authorization to that account's IAM policies, and it is required for IAM-based access to the key to work at all. Removing it can render the key unmanageable. Do not file it.

The two real findings this splits into:

1. **`Principal: "*"`, or an organization-wide grant with no `aws:PrincipalOrgID`,** on a key policy statement. Also treat as this finding a wildcard principal whose only condition is non-identity-bearing.
2. **A `root` principal belonging to a *different* account.** That delegates the key to that entire foreign account's IAM, so anybody the other account's administrators trust can use your key. Read the twelve digits and say whose account it is.

Then the scoping conditions that make a broad grant tolerable, whose absence is the actual defect: `kms:ViaService` (the key can only be used through a named service), `kms:CallerAccount`, `kms:EncryptionContext:*`, and `kms:GrantIsForAWSResource`.

**Grants bypass a policy reading.** `aws_kms_grant` and runtime `CreateGrant` calls add permissions that never appear in the key policy. Grep for `aws_kms_grant` and for `CreateGrant` in SDK code, and list what you find as part of the key's effective permissions.

Lifecycle: `enable_key_rotation` (absent means no automatic rotation), `deletion_window_in_days` (7 is the floor; a short window on a key protecting backups means the backups die with it), and a key alias that is reused across environments, which is how a staging role ends up able to decrypt production data.

```detector
match: |
  resource "aws_kms_key" "data" {
    description = "data key"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid       = "Root"
          Effect    = "Allow"
          Principal = { AWS = "arn:aws:iam::111122223333:root" }
          Action    = "kms:*"
          Resource  = "*"
        },
        {
          Sid       = "PartnerAccount"
          Effect    = "Allow"
          Principal = { AWS = "arn:aws:iam::999988887777:root" }
          Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
          Resource  = "*"
        }
      ]
    })
  }
nomatch: |
  resource "aws_kms_key" "data" {
    description           = "data key"
    enable_key_rotation   = true
    deletion_window_in_days = 30
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid       = "Root"
          Effect    = "Allow"
          Principal = { AWS = "arn:aws:iam::111122223333:root" }
          Action    = "kms:*"
          Resource  = "*"
        },
        {
          Sid       = "ViaS3Only"
          Effect    = "Allow"
          Principal = { AWS = aws_iam_role.app.arn }
          Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
          Resource  = "*"
          Condition = {
            StringEquals = {
              "kms:ViaService"    = "s3.us-east-1.amazonaws.com"
              "kms:CallerAccount" = "111122223333"
            }
          }
        }
      ]
    })
  }
```

### 8. Transport-security enforcement flags (`resource-tls-enforcement-flags`)

This item is about the *configuration switch that forces* TLS, not about certificate-validation code — that is crypto's.

- **S3 and other resource policies:** the absence of a `Deny` statement conditioned on `Bool: {"aws:SecureTransport": "false"}`. With BPA on and no public grant a bucket is still reachable over plain HTTP by an authorized principal, and the deny statement is the only thing that stops it. This is an absence sweep — use the resource-granular form in item 0 (`tf_absent`), and note that the policy may be authored as `aws_s3_bucket_policy`, as an HCL `jsonencode({ Effect = "Allow" … })` body, or as a `data "aws_iam_policy_document"` in a separate file. A pattern written in JSON colon form (`"Effect": "Allow"`) matches none of the HCL shapes and will report clean over all of them.
- **Managed databases:** `rds.force_ssl` (Postgres) or `require_secure_transport` (MySQL) in the parameter group; Cloud SQL `settings.ip_configuration.require_ssl` / `ssl_mode`; Azure `require_secure_transport`; and Redis `transit_encryption_enabled`.
- **Load balancers and API gateways:** `ssl_policy` on `aws_lb_listener` naming a modern policy rather than a legacy one; a listener on port 80 with no redirect action to 443; `minimum_protocol_version` on a CloudFront distribution and on `aws_api_gateway_domain_name`; Azure Application Gateway `ssl_policy`; GCP `google_compute_target_https_proxy` with an `ssl_policy` rather than the default.
- **Storage accounts:** `min_tls_version` on `azurerm_storage_account` — `"TLS1_0"` and `"TLS1_1"` are findings — and the HTTPS-only flag, which is spelled `enable_https_traffic_only` in AzureRM 3.x and `https_traffic_only_enabled` in 4.x. **Check the provider version constraint in the configuration before deciding which spelling should be there**; grepping only one of the two silently clears every repository on the other major version. **In Bicep and ARM there is only one spelling of each, and neither shares a substring with any of the three above:** `properties.minimumTlsVersion: 'TLS1_0'` and `properties.supportsHttpsTrafficOnly: false` on `Microsoft.Storage/storageAccounts`. Both have safe defaults on current API versions (`TLS1_2` and `true`), so here the finding is the value written out rather than the absence — which is the opposite direction from `publicNetworkAccess` on the same resource, and getting the two backwards produces a false positive on every correctly written storage account. The managed-database sibling is `properties.requireSecureTransport: 'OFF'` on `Microsoft.DBforMySQL/flexibleServers` configurations, and `properties.minimalTlsVersion` on `Microsoft.Sql/servers`.

```detector
match: |
  resource "aws_s3_bucket_policy" "reports" {
    bucket = aws_s3_bucket.reports.id
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.app.arn }
        Action    = ["s3:GetObject"]
        Resource  = "${aws_s3_bucket.reports.arn}/*"
      }]
    })
  }
nomatch: |
  resource "aws_s3_bucket_policy" "reports" {
    bucket = aws_s3_bucket.reports.id
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect    = "Allow"
          Principal = { AWS = aws_iam_role.app.arn }
          Action    = ["s3:GetObject"]
          Resource  = "${aws_s3_bucket.reports.arn}/*"
        },
        {
          Sid       = "DenyInsecureTransport"
          Effect    = "Deny"
          Principal = "*"
          Action    = "s3:*"
          Resource  = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]
          Condition = { Bool = { "aws:SecureTransport" = "false" } }
        }
      ]
    })
  }
```

```detector
match: |
  resource "azurerm_storage_account" "docs" {
    name                     = "acmedocs"
    resource_group_name      = azurerm_resource_group.main.name
    location                 = "eastus"
    account_tier             = "Standard"
    account_replication_type = "LRS"
    min_tls_version          = "TLS1_0"
  }
nomatch: |
  resource "azurerm_storage_account" "docs" {
    name                          = "acmedocs"
    resource_group_name           = azurerm_resource_group.main.name
    location                      = "eastus"
    account_tier                  = "Standard"
    account_replication_type      = "LRS"
    min_tls_version               = "TLS1_2"
    public_network_access_enabled = false
  }
```

### 9. Kubernetes workload hardening (`kubernetes-workload-hardening`)

Read the pod spec, then read what enforces it — the two are separate findings and item 10 owns the enforcement half.

**`privileged: true`** is the whole of container isolation switched off and is a finding wherever it appears in a workload. **`hostNetwork: true`** puts the pod on the node's network namespace, which is also how it reaches the metadata service and the kubelet's port. **`hostPID: true`** exposes every process on the node, including their `/proc/<pid>/environ`. **`hostIPC: true`** shares memory with the node.

**`hostPath` is ranked by what the path gives you, and the ranking in the source material was stale.** A container runtime socket is a full node takeover — a mount of the socket lets the container start a privileged sibling container with the host root filesystem attached. The current sockets, in the order to check them:

- `/run/containerd/containerd.sock` (and `/var/run/containerd/containerd.sock`) — containerd is the default runtime on managed Kubernetes.
- `/run/crio/crio.sock` (and `/var/run/crio/crio.sock`) — CRI-O on OpenShift and some distributions.
- `/var/run/docker.sock` — **dockershim was removed in Kubernetes 1.24**, so this is no longer a Kubernetes node path. It is still real on Docker Compose hosts, in Docker-in-Docker build pods, and in CI runners, so keep it — just do not rank it first, because ranking it first is what walked reviewers past the two sockets that are actually mounted.

The other paths that matter: `/` (the whole node), `/etc` and `/etc/kubernetes` (including `admin.conf`), `/var/lib/kubelet` (including the kubelet's client certificate and every pod's projected token), `/var/log` (symlink traversal into the node filesystem via the kubelet log endpoint), `/dev` and `/sys`, and any writable mount of a directory the node's own components read. Read the `readOnly` flag on the volume mount: a read-only mount of `/etc/ssl/certs` is ordinary, a writable mount of `/etc` is not.

**The `securityContext` fields whose absence is the finding**, since every default is the unsafe one: `allowPrivilegeEscalation` (defaults to true), `runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities.drop: ["ALL"]`, `seccompProfile.type: RuntimeDefault`. Do not report `allowPrivilegeEscalation: true` as merely "the default" and therefore not a finding — the Pod Security Standards `restricted` profile requires it false, and defaulting is the reason it is missing, not a reason it is acceptable.

**`automountServiceAccountToken`** defaults to true, so an unset field means the pod holds an API credential. Check it on both the ServiceAccount and the pod spec, and check whether the token is needed at all.

**Resource limits** are an availability control here: no `limits.memory` on a workload means one pod can evict its neighbours, and no `limits.cpu` on a multi-tenant node is a noisy-neighbour path. Low unless the cluster is genuinely multi-tenant.

**Azure workload identity:** `azure.workload.identity/use: "true"` on the pod and a federated credential on the other end. "Azure AD Pod Identity" is retired; if a manifest still references `aadpodidbinding`, that is a migration finding rather than a live control.

```detector
match: |
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: build-agent
    namespace: ci
  spec:
    template:
      spec:
        hostPID: true
        containers:
          - name: agent
            image: acme/agent:1.4.2
            securityContext:
              privileged: true
            volumeMounts:
              - name: runtime
                mountPath: /run/containerd/containerd.sock
        volumes:
          - name: runtime
            hostPath:
              path: /run/containerd/containerd.sock
              type: Socket
nomatch: |
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: build-agent
    namespace: ci
  spec:
    template:
      spec:
        automountServiceAccountToken: false
        securityContext:
          runAsNonRoot: true
          runAsUser: 10001
          seccompProfile:
            type: RuntimeDefault
        containers:
          - name: agent
            image: acme/agent@sha256:9b2c1f0a4e6d8c3b5a7f9e1d2c4b6a8f0e2d4c6b8a0f2e4d6c8b0a2f4e6d8c0b
            securityContext:
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: true
              capabilities:
                drop: ["ALL"]
            volumeMounts:
              - name: workspace
                mountPath: /workspace
        volumes:
          - name: workspace
            emptyDir: {}
```

### 10. Kubernetes RBAC and admission control (`kubernetes-rbac-and-admission`)

**Pod Security Admission replaced PodSecurityPolicy, which was removed in Kubernetes 1.25.** "PSP not enforced" cannot be a finding on any supported cluster. What to check instead:

- **The namespace label and its value.** `pod-security.kubernetes.io/enforce` on `kind: Namespace`. Absent means no enforcement. Present with `privileged` means enforcement is explicitly switched off — and the label name is exactly what a "do they use PSA?" grep matches, so read the value. `baseline` blocks the worst of item 9; `restricted` is the profile that requires `runAsNonRoot`, `allowPrivilegeEscalation: false`, dropped capabilities and a seccomp profile. Check the `-version` label too: pinning `enforce-version` to an old minor keeps old, looser checks.
- **Whether a policy engine exists and whether it enforces.** Kyverno `kind: ClusterPolicy` with `validationFailureAction`/`failureAction` set to `Audit` rather than `Enforce` is an audit-only policy that blocks nothing. Gatekeeper `kind: ConstraintTemplate` with no matching `Constraint`, or a constraint with `enforcementAction: dryrun`, is the same defect. `kind: ValidatingAdmissionPolicy` with a binding whose `validationActions` are `Audit`/`Warn` only. Report audit-only as a real finding: the artifact exists, so a reviewer counting artifacts marks it done.

**Rego has its own fail-open shape: an allow decision whose default is true.** Search both current (`:=`) and legacy (`=`) assignment syntax:

```bash
rg -n --hidden --glob '*.rego' '^\s*default\s+allow\s*(?::=|=)\s*true\b' .
```

A match is a candidate when the deployed decision actually queries that package's `allow` rule: inputs not matched by a later rule are permitted. Trace the bundle entrypoint or `data.<package>.allow` consumer before filing it; a repository that evaluates only `deny` may never read this rule. A non-match is not a repository-wide clearance—another package can expose `permit`, `authorized` or a generated entrypoint—so inventory the configured decisions and record any bundle or entrypoint you could not resolve.

```detector
match: |
  package admission

  default allow := true

  allow if {
    input.review.object.metadata.namespace == "prod"
  }
nomatch: |
  package admission

  default allow := false

  allow if {
    input.review.object.metadata.namespace == "prod"
    input.review.userInfo.groups[_] == "platform-admins"
  }
```

**RBAC escalation grants, with the resource strings spelled the way RBAC actually spells them.** `serviceaccounts/tokenrequest` is not an RBAC resource; the subresource is **`serviceaccounts/token`**. The grants that turn a subject into a cluster administrator, each with the verb that does it:

| Grant | Why it escalates |
|---|---|
| `create` on `serviceaccounts/token` | Mints a token for any ServiceAccount in scope, inheriting its permissions. |
| `create` on `pods` | Schedule a pod that mounts any ServiceAccount, any `hostPath`, or runs privileged. |
| `create` on `pods/exec`, `pods/attach`, `pods/portforward` | Enter a pod that already holds the credentials you want. `create` is the verb — `kubectl exec` POSTs to the subresource. |
| `get`, `list` or `watch` on `secrets` | Read every credential in scope. At cluster scope this is game over. |
| `update` or `patch` on `nodes` | Change node labels and taints to steer a privileged workload onto a node you control. |
| `get`, `create` or `patch` on `nodes/proxy` | Reach the kubelet API directly, which permits exec into any pod on that node and bypasses API-server RBAC and audit. **`get` and `create` are the verbs that reach the kubelet — `patch` alone on `nodes/proxy` is not the escalation path.** |
| `escalate` or `bind` on `roles`/`clusterroles` | Grant yourself permissions you do not have, or bind an existing powerful role. |
| `impersonate` on `users`, `groups` or `serviceaccounts` | Act as anyone, including `system:masters`. |
| `create` on `certificatesigningrequests` **plus `update` on `certificatesigningrequests/approval` plus `approve` on `signers`** | Mint a client certificate for an arbitrary identity, including a group like `system:masters`. **Approval is an UPDATE on the `approval` subresource, not a create** — see the note below. |
| `create` on `mutatingwebhookconfigurations` / `validatingwebhookconfigurations` | Intercept and rewrite every admission request in the cluster. |
| `*` on `*` in `*` apiGroups | The wildcard form of all of the above. |

**A note on the CSR row, because it diverges from the source punch list.** The punch list's replacement text says `create` on `certificatesigningrequests/approval`. That verb is wrong: Kubernetes approves a CSR by **updating** (or patching) the `approval` subresource, and the approver additionally needs the `approve` verb on the `signers` resource in `certificates.k8s.io` for the signer in question. A grep for `create` next to `certificatesigningrequests/approval` finds nothing in a real cluster's RBAC — the same unfireable-check failure the punch list exists to remove. The table above carries the correct verbs; the divergence is recorded in this lens's migration report rather than applied silently.

**Bindings are half the finding.** A powerful ClusterRole with no binding grants nothing; a mild Role bound to `system:authenticated` grants it to every authenticated identity in the cluster, including every ServiceAccount. Check the `subjects` of every `RoleBinding` and `ClusterRoleBinding` for `system:authenticated`, `system:unauthenticated`, `system:serviceaccounts` (the group covering every SA), and for `cluster-admin` on the `roleRef`.

**Legacy non-expiring tokens.** Projected, audience-bound, expiring tokens are the default since 1.22, and since 1.24 Kubernetes no longer auto-creates a token Secret per ServiceAccount. What survives as a real finding is a hand-written `kind: Secret` of `type: kubernetes.io/service-account-token` — that still yields a token with no expiry, and it is committed in the repository where you can see it.

```detector
match: |
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: ci-deployer
  rules:
    - apiGroups: [""]
      resources: ["serviceaccounts/token"]
      verbs: ["create"]
    - apiGroups: [""]
      resources: ["secrets"]
      verbs: ["get", "list"]
    - apiGroups: [""]
      resources: ["pods/exec"]
      verbs: ["create"]
nomatch: |
  apiVersion: rbac.authorization.k8s.io/v1
  kind: Role
  metadata:
    name: ci-deployer
    namespace: prod
  rules:
    - apiGroups: ["apps"]
      resources: ["deployments"]
      resourceNames: ["api", "worker"]
      verbs: ["get", "patch"]
```

```detector
match: |
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRoleBinding
  metadata:
    name: dashboard-access
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: cluster-admin
  subjects:
    - kind: Group
      name: system:authenticated
      apiGroup: rbac.authorization.k8s.io
nomatch: |
  apiVersion: rbac.authorization.k8s.io/v1
  kind: RoleBinding
  metadata:
    name: dashboard-access
    namespace: observability
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: Role
    name: dashboard-viewer
  subjects:
    - kind: ServiceAccount
      name: dashboard
      namespace: observability
```

```detector
match: |
  apiVersion: v1
  kind: Namespace
  metadata:
    name: prod
    labels:
      pod-security.kubernetes.io/enforce: privileged
      pod-security.kubernetes.io/warn: baseline
nomatch: |
  apiVersion: v1
  kind: Namespace
  metadata:
    name: prod
    labels:
      pod-security.kubernetes.io/enforce: restricted
      pod-security.kubernetes.io/enforce-version: latest
      pod-security.kubernetes.io/audit: restricted
      pod-security.kubernetes.io/warn: restricted
```

```detector
match: |
  apiVersion: kyverno.io/v1
  kind: ClusterPolicy
  metadata:
    name: disallow-privileged
  spec:
    validationFailureAction: Audit
    rules:
      - name: privileged-containers
        match:
          any:
            - resources:
                kinds: ["Pod"]
        validate:
          pattern:
            spec:
              containers:
                - securityContext:
                    privileged: "false"
nomatch: |
  apiVersion: kyverno.io/v1
  kind: ClusterPolicy
  metadata:
    name: disallow-privileged
  spec:
    validationFailureAction: Enforce
    rules:
      - name: privileged-containers
        match:
          any:
            - resources:
                kinds: ["Pod"]
        validate:
          pattern:
            spec:
              containers:
                - securityContext:
                    privileged: "false"
```

```detector
match: |
  apiVersion: v1
  kind: Secret
  metadata:
    name: ci-token
    namespace: prod
    annotations:
      kubernetes.io/service-account.name: ci
  type: kubernetes.io/service-account-token
nomatch: |
  apiVersion: v1
  kind: Pod
  metadata:
    name: ci-runner
    namespace: prod
  spec:
    serviceAccountName: ci
    containers:
      - name: runner
        image: acme/runner@sha256:5f8a3c1e7b9d0a2f4c6e8b0d2a4f6c8e0b2d4a6f8c0e2b4d6a8f0c2e4b6d8a0f
        volumeMounts:
          - name: api-token
            mountPath: /var/run/secrets/tokens
    volumes:
      - name: api-token
        projected:
          sources:
            - serviceAccountToken:
                path: api-token
                expirationSeconds: 3600
                audience: api.acme.internal
```

### 11. Dockerfile and image content (`dockerfile-and-image-content`)

- **The base-image reference form.** `FROM node:latest`, `FROM python:3` and any tag-only reference are mutable: the digest behind the tag changes under you, so what you audited is not what ships. A `FROM` with no tag at all is `:latest`. The fix is a digest: `FROM node:22.14.0@sha256:…`. Multi-stage builds need every stage pinned, not just the final one.
- **`USER`.** A Dockerfile whose final stage has no `USER` instruction ships an image that runs as root. **Grep for the absence per FINAL STAGE, never per file — use `dockerfile_root` from item 0.** `rg --files-without-match '^USER '` clears every multi-stage build that carries a `USER` anywhere, and `USER node` in a builder stage does not apply to the shipped image, so the per-file form reads a root-shipping image as clean; the final stage is the only one that governs what runs. `USER root` as the final user is the explicit form of the same defect. Instructions are case-insensitive to the builder, so a `user` in lower case counts and a case-sensitive `^USER ` pattern does not see it — `dockerfile_root` folds case for exactly that reason. A numeric UID is preferable to a name, because Kubernetes `runAsNonRoot` can only verify a numeric one.
- **Build secrets in layers.** `COPY .env`, `COPY id_rsa`, `ARG` used to pass a token (every `ARG` value is visible in `docker history`), `RUN git clone https://user:token@…`, `RUN curl -H "Authorization: …"`, and a `RUN` that fetches with credentials and deletes the file in a *later* layer — the earlier layer still has it. The correct mechanism is `RUN --mount=type=secret`, whose presence is what to grep for on the safe side.
- **`RUN curl … | sh`** is not automatically a finding; when the URL is version-pinned, checksum- or signature-verified, and the pipeline is not carrying credentials, it has the same trust structure as `apt-get install`. The discriminators are: the URL points at `latest`, `main` or an unversioned installer; no checksum or signature check; secrets present in the environment during the fetch; and no `set -o pipefail`, which means a failed download still succeeds into `sh`.
- **`.dockerignore` absence** means `COPY . .` sweeps in `.git` (with any persisted credential in `.git/config`), `.env`, `node_modules`, and local certificates. Check whether any `COPY`/`ADD` copies a broad path, then check for the file.
- **`ADD` with a remote URL or an archive** where `COPY` would do: `ADD` fetches without verification and auto-extracts archives.
- **Hygiene items that stay Low**, listed so they are not inflated: `HEALTHCHECK` absent — **Kubernetes ignores `HEALTHCHECK` entirely and uses probes instead**, so it is only meaningful for plain Docker or Compose; no multi-stage build; build tooling left in the final image; `apt-get` without `--no-install-recommends`.

```detector
match: |
  FROM node:latest

  WORKDIR /app
  COPY . .
  COPY .env .env
  ARG NPM_TOKEN
  RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc \
   && npm ci \
   && rm .npmrc
  CMD ["node", "server.js"]
nomatch: |
  FROM node:22.14.0-bookworm-slim@sha256:5f0b1c8f3e6a9d2b4c7e0a3f6d9b2c5e8a1f4d7b0c3e6a9f2d5b8c1e4a7f0d3b AS build

  WORKDIR /app
  COPY package.json package-lock.json ./
  RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
  COPY src ./src

  FROM node:22.14.0-bookworm-slim@sha256:5f0b1c8f3e6a9d2b4c7e0a3f6d9b2c5e8a1f4d7b0c3e6a9f2d5b8c1e4a7f0d3b
  WORKDIR /app
  COPY --from=build /app /app
  USER 10001
  CMD ["node", "src/server.js"]
```

### 12. Base-image CVE exposure (`image-cve-exposure`)

The OS and base-layer half of vulnerability exposure. Application dependency CVEs are cicd's `package-dependency-cves`; do not double-file.

- **Identify the base image and its era.** A distribution release that is out of support gets no security updates at all, which makes every CVE in it permanent. Name the image and tag from the `FROM` line or the `image:` field, and say what you established about its support status rather than guessing a CVE count.
- **Whether anything scans.** `trivy`, `grype`, `docker scout`, `snyk container`, ECR enhanced scanning (`aws_ecr_registry_scanning_configuration` with `scan_type = "ENHANCED"`), Azure Defender for Containers, GCP Artifact Analysis. Their presence in the repository is a fact about intent; whether the pipeline blocks on the result is cicd's `pipeline-scanner-gating`.
- **Whether the image is rebuilt.** A digest-pinned base image is reproducible and *frozen*: pinning without a rebuild cadence means CVEs accumulate behind the pin. Report the pair — pinned with no renovation path is a finding at Low/Medium, and it is the honest counterweight to item 11's pinning requirement.
- **Do not report a CVE list you did not produce.** If no scanner ran during the audit, the finding is "no scanning in the image build path", not "the base image contains N vulnerabilities."

```detector
match: |
  resource "aws_ecr_repository" "api" {
    name = "api"
    image_scanning_configuration {
      scan_on_push = false
    }
  }
nomatch: |
  resource "aws_ecr_repository" "api" {
    name                 = "api"
    image_tag_mutability = "IMMUTABLE"
    image_scanning_configuration {
      scan_on_push = true
    }
  }

  resource "aws_ecr_registry_scanning_configuration" "this" {
    scan_type = "ENHANCED"
    rule {
      scan_frequency = "CONTINUOUS_SCAN"
      repository_filter {
        filter      = "*"
        filter_type = "WILDCARD"
      }
    }
  }
```

### 13. Deploy-time signature enforcement (`deploy-time-signature-enforcement`)

**Name the mechanism correctly.** The current signing mechanisms are **Sigstore Cosign** and the Notary Project's **Notation** (Notary v2, using OCI 1.1 referrers). "Notary" without qualification means Notary v1 / Docker Content Trust, which is legacy and effectively unmaintained — citing it as the control to adopt sends a team to a dead end.

- **Keyless verification with no effective identity constraint is the subtle defect that matters most here — and it is version-dependent, so establish the version before you write the finding.** Cosign 2.0 made `--certificate-identity` (or `--certificate-identity-regexp`) and `--certificate-oidc-issuer` (or its regexp form) **required** for `cosign verify` and `cosign verify-attestation` of a keyless signature: on 2.x the command fails without them rather than accepting anything. On 1.x they were optional, and their absence accepted any certificate Fulcio ever issued, for anybody. So there are three findings here, not one, and which applies depends on the pinned version — read the installer step, the `cosign-installer` action's `cosign-release`, or the vendored binary, and **say which version you established**:
  - a pinned or vendored **cosign 1.x** with the flags absent;
  - **either flag absent on any version** — on 1.x that is the accept-anything case, and on 2.x the command cannot succeed, so a green pipeline means the verification step is not actually running the path you think it is;
  - **a constraint present but not constraining**: `--certificate-identity-regexp '.*'`, a regexp with no anchors, `--insecure-ignore-tlog`, or `--insecure-ignore-sct`. This is the live defect on a current cosign and the one a flag-presence grep clears.
- **Notation** needs a trust policy (`trustpolicy.json`) with a `trustedIdentities` entry that is not `*`, and a trust store containing the expected root.
- **Enforcement lives at admission, not in the build.** The artifact to find is an enforcing policy in the deploy path: Kyverno `verifyImages` with `mutateDigest` and `required: true`, a Gatekeeper constraint, GCP Binary Authorization with an attestor and an enforcement mode that is not `dryrun`, AWS Signer with an ECR pull-through policy. A `cosign sign` in CI with nothing verifying at admission is the "emits provenance nobody checks" asymmetry — report it as a static finding, which is honest, rather than as a failed verification you did not run.
- **Verify the digest, not the tag.** A policy that verifies `acme/api:v1` and then deploys `acme/api:v1` re-resolves the tag; the signature check and the pull must agree on a digest. Kyverno's `mutateDigest: true` exists for exactly this.

```detector
match: |
  - name: verify image
    run: |
      cosign verify \
        --certificate-identity-regexp '.*' \
        --certificate-oidc-issuer-regexp '.*' \
        --insecure-ignore-tlog \
        ghcr.io/acme/api:${{ github.sha }}
nomatch: |
  - name: verify image
    run: |
      cosign verify \
        --certificate-identity-regexp '^https://github\.com/acme/api/\.github/workflows/.+@refs/heads/main$' \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        ghcr.io/acme/api@${{ steps.build.outputs.digest }}
```

```detector
match: |
  apiVersion: kyverno.io/v1
  kind: ClusterPolicy
  metadata:
    name: check-image-signature
  spec:
    validationFailureAction: Audit
    rules:
      - name: verify
        match:
          any:
            - resources:
                kinds: ["Pod"]
        verifyImages:
          - imageReferences: ["ghcr.io/acme/*"]
            mutateDigest: false
            required: false
            attestors:
              - entries:
                  - keyless:
                      issuer: https://token.actions.githubusercontent.com
nomatch: |
  apiVersion: kyverno.io/v1
  kind: ClusterPolicy
  metadata:
    name: check-image-signature
  spec:
    validationFailureAction: Enforce
    rules:
      - name: verify
        match:
          any:
            - resources:
                kinds: ["Pod"]
        verifyImages:
          - imageReferences: ["ghcr.io/acme/*"]
            mutateDigest: true
            required: true
            attestors:
              - entries:
                  - keyless:
                      issuer: https://token.actions.githubusercontent.com
                      subject: https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main
```

### 14. Serverless function exposure (`serverless-function-exposure`)

- **An unauthenticated invocation path.** `aws_lambda_function_url` with `authorization_type = "NONE"`; CloudFormation `AWS::Lambda::Url` with `AuthType: NONE`; an Azure Function with `authLevel: anonymous` in `function.json` or `[HttpTrigger(AuthorizationLevel.Anonymous, …)]` in code; `gcloud run deploy --allow-unauthenticated` or a `google_cloud_run_service_iam_member` granting `allUsers`; API Gateway with `AuthorizationType: NONE` on a route that is not deliberately public. Each of these is a finding *unless the function is meant to be public*, so read the handler: an unauthenticated function that reads a database by an id from the request body is the finding, and the auth check may legitimately live inside the handler.
- **The function's role.** A single-purpose function with `s3:*`, `dynamodb:*` or `secretsmanager:GetSecretValue` on `Resource: "*"` is item 1's finding located here — the reason it matters more for a function is that a function URL turns the role into an internet-reachable capability.
- **Secrets in function environment configuration.** `environment { variables = { … } }` on `aws_lambda_function` with a literal secret, versus a Secrets Manager or Parameter Store reference resolved at runtime. The literal is visible to anyone with `lambda:GetFunctionConfiguration`, and it lands in the state file.
- **Timeout and concurrency as availability controls.** A 900-second timeout on a public function is a cost and DoS amplifier; no `reserved_concurrent_executions` on a critical function means one caller can consume the account's whole concurrency pool and take out everything else. Both are Low/Medium and both are real.
- **The invoke permission.** `aws_lambda_permission` with `principal = "*"`, or a service principal without `source_arn` — item 1's confused-deputy check, applied to the function.

```detector
match: |
  resource "aws_lambda_function_url" "webhook" {
    function_name      = aws_lambda_function.webhook.function_name
    authorization_type = "NONE"
  }

  resource "aws_lambda_function" "webhook" {
    function_name = "webhook"
    role          = aws_iam_role.webhook.arn
    timeout       = 900
    environment {
      variables = {
        STRIPE_SECRET = "sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxx"
      }
    }
  }
nomatch: |
  resource "aws_lambda_function_url" "webhook" {
    function_name      = aws_lambda_function.webhook.function_name
    authorization_type = "AWS_IAM"
  }

  resource "aws_lambda_function" "webhook" {
    function_name                  = "webhook"
    role                           = aws_iam_role.webhook.arn
    timeout                        = 15
    reserved_concurrent_executions = 25
    environment {
      variables = {
        STRIPE_SECRET_ARN = aws_secretsmanager_secret.stripe.arn
      }
    }
  }
```

```detector
match: |
  {
    "bindings": [
      {
        "type": "httpTrigger",
        "direction": "in",
        "name": "req",
        "authLevel": "anonymous",
        "methods": ["post"]
      }
    ]
  }
nomatch: |
  {
    "bindings": [
      {
        "type": "httpTrigger",
        "direction": "in",
        "name": "req",
        "authLevel": "function",
        "methods": ["post"]
      }
    ]
  }
```

### 15. Terraform state and guard rails (`terraform-state-protection`)

State contains every attribute of every resource, including values the provider marked sensitive: database passwords, private keys, generated secrets. Treat the state backend as a credential store.

- **State committed to the repository.** `*.tfstate` or `*.tfstate.backup` tracked in git is the highest-severity form of this item and needs no inference: read it and see what is in it. Check `.gitignore` too, and check history — a state file removed in a later commit is still in every clone.
- **Do not file "state backend not encrypted at rest" from a missing `encrypt`.** The `encrypt` argument sets `x-amz-server-side-encryption` on the PutObject call; with it absent the object still lands in a bucket that applies default encryption, so the same January-2023 correction that governs item 6 and false positive 4 governs this line too. Omitting `encrypt` is exactly as weak an at-rest claim as a bucket with no SSE block. **What `encrypt`/`kms_key_id` do establish is the narrower CMK claim** — "state is not under a customer-managed key where key ownership and revocability are required" — and that needs the same named classification or contract clause item 6 demands. If you want to state the at-rest fact, state the *bucket's* default encryption; if the repository does not manage the state bucket, that is an open question.
- **State locking is genuinely not the default, so this one is a real absence.** `use_lockfile = true` (S3-native locking) or the legacy `dynamodb_table`; without either, two concurrent applies corrupt state. `backend "local"` in anything that is not a scratch module means state lives on somebody's laptop or in the CI workspace.
- **Backend access control is where the weight of this item belongs.** The bucket holding state is itself an S3 bucket, so item 4 applies to it in full — BPA at bucket and account level, the bucket policy, versioning, who can `s3:GetObject` on the key prefix, and whether a CI role has broader access to it than the operators do. A state bucket with BPA off is Critical rather than High, because the blast radius is every secret in the estate. This, not the `encrypt` flag, is the finding that survives a competent reader.
- **`sensitive = true` on outputs** that carry secrets. Its absence prints the value in `terraform apply` output and in CI logs. Absence sweep.
- **Provider credentials in the configuration.** `provider "aws" { access_key = … secret_key = … }`, `client_secret` on the azurerm provider, `credentials = file("sa.json")` on google. The literal itself is crypto's finding; that the provider block is where it lives is this item's.
- **`lifecycle { prevent_destroy = true }` on stateful resources — grep for the absence.** `prevent_destroy` is a `lifecycle` meta-argument that already defaults to `false`, so the string `prevent_destroy = false` appears almost nowhere and searching for it finds nothing. The check is: does each `aws_db_instance`, `aws_rds_cluster`, `aws_s3_bucket`, `aws_kms_key`, `aws_dynamodb_table`, `azurerm_mssql_database`, `google_sql_database_instance` carry the guard? Keep this **Low or Medium**: it protects against an operator or a refactor destroying data, not against an attacker, and calling it High is how a report loses credibility. The resource-level siblings are `deletion_protection = true` (whose absence is the finding, since the AWS provider defaults it to `false`) and — **greppable in the positive direction, because `false` is already the default for both** — `skip_final_snapshot = true` and `force_destroy = true`. Grepping for `skip_final_snapshot = false` or `force_destroy = false` repeats the exact trap the `prevent_destroy = false` correction above exists to fix: the literal is the default, so nobody types it and the grep finds nothing.
- **Module provenance.** A `source` pointing at a git ref that is a branch rather than a tag or commit, or a registry namespace nobody vets. `terraform init` will happily fetch a moving target.

```detector
match: |
  terraform {
    backend "s3" {
      bucket = "acme-tfstate"
      key    = "prod/terraform.tfstate"
      region = "us-east-1"
    }
  }

  output "db_password" {
    value = random_password.db.result
  }

  resource "aws_db_instance" "app" {
    identifier          = "app"
    engine              = "postgres"
    skip_final_snapshot = true
  }
nomatch: |
  terraform {
    backend "s3" {
      bucket       = "acme-tfstate"
      key          = "prod/terraform.tfstate"
      region       = "us-east-1"
      encrypt      = true
      kms_key_id   = "arn:aws:kms:us-east-1:111122223333:key/2f8c1e7b-9d0a-4f2c-8e6b-0d2a4f6c8e0b"
      use_lockfile = true
    }
  }

  output "db_password" {
    value     = random_password.db.result
    sensitive = true
  }

  resource "aws_db_instance" "app" {
    identifier          = "app"
    engine              = "postgres"
    deletion_protection = true
    skip_final_snapshot = false
    final_snapshot_identifier = "app-final"

    lifecycle {
      prevent_destroy = true
    }
  }
```

### 16. How a secret reaches a workload (`managed-secret-service-configuration`)

**Get the leak mechanism right, because the source material's was false.** `kubectl describe pod` renders a `valueFrom.secretKeyRef` as `<set to the key 'x' in secret 'y'>` — **it does not print the value.** Citing `kubectl describe` as the exposure is checkable by any Kubernetes engineer in ten seconds and discredits the finding. The accurate reasons an environment variable is a worse delivery mechanism than a file:

- Readable via `/proc/<pid>/environ` by anything running in the container, including an injected process and a sidecar sharing the process namespace.
- Inherited by every child process, so a shell-out hands the secret to whatever it spawns.
- Captured in core dumps, and by telemetry and crash agents that serialize the environment.
- Printed by `kubectl exec -- env`, by `set -x`, and by application error handlers that dump the environment.
- **The one that matters most: not rotatable without a pod restart.** A projected volume updates in place; an environment variable is fixed for the lifetime of the process, so rotation means a rolling restart of everything.
- **`docker inspect` does print values** — that half of the original claim is correct and is why the finding is stronger for plain Docker and Compose than for Kubernetes.

A literal `value:` in a manifest is a *different and worse* finding: the secret is in the repository, in git history, and in `kubectl get -o yaml` for anyone with read on the namespace. The credential literal itself is crypto's finding; the manifest that carries it is this one's.

Then check the rest of the delivery path:

- **CloudFormation `NoEcho`.** A parameter carrying a secret without `NoEcho: true` is displayed in the console, in `describe-stacks` output, and in the events log. Grep for parameters whose name looks credential-bearing and then for the **absence** of `NoEcho`.
- **Dynamic references rather than literals:** `{{resolve:secretsmanager:…}}` and `{{resolve:ssm-secure:…}}` in CloudFormation, `data "aws_secretsmanager_secret_version"` in Terraform (which puts the value **into state** — that is the trade-off, and it is why item 15's backend encryption matters), `azurerm_key_vault_secret` referenced by id, `google_secret_manager_secret_version`. In Bicep the reference form is `getSecret()` on an `existing` vault or a `keyVaultReference` in a `Microsoft.Resources/deployments` parameter — both keep the value out of the template and out of the deployment history, which a plain `@secure()` parameter passed from a pipeline variable does not. A CSI Secrets Store driver or External Secrets Operator keeps the value out of both the manifest and the state.
- **The vault's own data plane, which is this item's most-missed artifact.** `Microsoft.KeyVault/vaults` with `properties.publicNetworkAccess: 'Enabled'` — **the default**, so its absence counts — or `properties.networkAcls.defaultAction: 'Allow'`, is a secret store reachable from the internet: authorization then rests entirely on Entra RBAC or an access policy, with no network boundary in front of it. The network defect is item 3's, established with `bicep_absent` per item 0; what belongs *here* is the delivery consequence, and it is worth saying out loud in the finding, because a vault is the one store whose entire contents are credentials. Read `enableRbacAuthorization`, `enableSoftDelete` and `enablePurgeProtection` beside it — a vault with a public data plane and a wildcard access policy is the pair that turns one leaked token into every secret in the estate.
- **A secret fetched at boot and then written to disk or exported into the environment** — the pattern that undoes a correct secret manager. Grep entrypoint scripts for `export`, `>` into a file under `/tmp` or `/app`, and `.env` writes.
- **Rotation.** `aws_secretsmanager_secret_rotation` present, a Key Vault rotation policy, or a documented manual process. Absent rotation is Low on its own and escalates when the same secret is referenced from many places, because rotating it becomes a coordinated deploy.
- **Kubernetes Secrets are base64, not encrypted.** Whether etcd encrypts them is a control-plane setting you cannot see (see Scope). Do not claim they are encrypted and do not claim they are not; state that you could not establish it.

```detector
match: |
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: api
    namespace: prod
  spec:
    template:
      spec:
        containers:
          - name: api
            image: acme/api@sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809
            env:
              - name: DATABASE_URL
                value: postgres://app:s3cr3t-pr0d@db.prod.internal:5432/app
              - name: STRIPE_SECRET
                valueFrom:
                  secretKeyRef:
                    name: stripe
                    key: secret
nomatch: |
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: api
    namespace: prod
  spec:
    template:
      spec:
        containers:
          - name: api
            image: acme/api@sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809
            env:
              - name: DATABASE_URL_FILE
                value: /etc/secrets/database-url
            volumeMounts:
              - name: secrets
                mountPath: /etc/secrets
                readOnly: true
        volumes:
          - name: secrets
            csi:
              driver: secrets-store.csi.k8s.io
              readOnly: true
              volumeAttributes:
                secretProviderClass: api-secrets
```

```detector
match: |
  AWSTemplateFormatVersion: '2010-09-09'
  Parameters:
    DbPassword:
      Type: String
      Description: master password for the database
  Resources:
    Db:
      Type: AWS::RDS::DBInstance
      Properties:
        Engine: postgres
        MasterUsername: app
        MasterUserPassword: !Ref DbPassword
nomatch: |
  AWSTemplateFormatVersion: '2010-09-09'
  Resources:
    Db:
      Type: AWS::RDS::DBInstance
      Properties:
        Engine: postgres
        MasterUsername: app
        MasterUserPassword: '{{resolve:secretsmanager:prod/db:SecretString:password}}'
        StorageEncrypted: true
```

### 17. Control-plane audit logging (`control-plane-audit-logging`)

No audit trail means no forensics, which is both a security failure and a compliance failure in its own right. It is also the finding most often invisible, because the absence of a resource is not a line of code.

- **Existence.** `aws_cloudtrail` (and whether it is `is_multi_region_trail = true`, plus `is_organization_trail` where an organization exists); `azurerm_monitor_diagnostic_setting` on the subscription and on each sensitive resource; `google_logging_project_sink` and whether Data Access audit logs are enabled at all — on GCP, Admin Activity logs are always on but **Data Access logs are off by default**, so "audit logging exists" does not mean reads are logged.
- **On Bicep and ARM the resource type is `Microsoft.Insights/diagnosticSettings`, and a deployment containing none of them is this item's finding in its strongest form.** It is an absence with no dangerous value anywhere to grep for, and it is common: the type appears in no template unless somebody deliberately added it. Establish it with the count line in item 0 — `diag: 0` beside a non-zero `stores:` — and then read the two things the count cannot tell you. First, **pairing:** each setting names its target in `scope:`, so two settings on one store balance the arithmetic over a store with none; diff the `scope:` set against the store set. Second, **what the setting actually routes:** `logs[].categoryGroup: 'audit'` carries the data-plane audit categories (Key Vault `AuditEvent`, a flexible server's logs, a storage account's read/write/delete events), `'allLogs'` carries everything, and a setting with only a `metrics[]` array logs no *access* at all — which is a real finding wearing the artifact that closes it. Third, name the destination: `workspaceId`, `storageAccountId` or `eventHubAuthorizationRuleId`, at least one of which is required.
- **What Azure gives you without a diagnostic setting, stated precisely so the finding is neither overstated nor cleared.** The **Activity log** — control-plane writes: who deployed, who changed a firewall rule, who fetched a storage key — is collected for every subscription automatically and kept for 90 days, so "no control-plane audit trail at all" is the wrong sentence for Azure. What does *not* exist without a diagnostic setting is **anything longer than 90 days, anything exported beyond the subscription's own blast radius, and every data-plane log there is** — no record of a secret being read, a row being selected or a blob being downloaded. That is the finding: reads are unlogged and the retention is 90 days of a log the compromised subscription owns.
- **Data-plane events.** A CloudTrail with no `event_selector`/`advanced_event_selector` for S3 object-level or Lambda invocation events records who changed the bucket policy but not who read the objects. For a bucket holding regulated data that is the half you need.
- **Integrity.** `enable_log_file_validation = true` on CloudTrail; a log bucket with object lock or a retention policy; a bucket policy that denies `s3:DeleteObject` to everyone including the account's own administrators.
- **Destination.** Logs written into the same account that would be compromised can be deleted by whoever compromises it. A cross-account or centralized log archive is the control. Say which one the configuration shows.
- **Retention.** Read the retention setting as a fact — `retention_in_days` on a CloudWatch log group, a bucket lifecycle rule, a Log Analytics workspace retention. **Whether the number satisfies a regulatory minimum is not this lens's call**: hand it to hipaa or privacy with the number you found. Do not assert a retention requirement here.
- **Alerting on the events that matter**, which is where "logs exist but nobody looks" turns into a finding: root or break-glass account usage, IAM policy changes, security-group changes, CloudTrail itself being stopped, KMS key deletion scheduled. GuardDuty / Defender for Cloud / Security Command Center enabled is the platform version of the same control.

```detector
match: |
  resource "aws_cloudtrail" "main" {
    name                       = "main"
    s3_bucket_name             = aws_s3_bucket.logs.id
    is_multi_region_trail      = false
    enable_log_file_validation = false
  }
nomatch: |
  resource "aws_cloudtrail" "main" {
    name                          = "main"
    s3_bucket_name                = aws_s3_bucket.logs.id
    is_multi_region_trail         = true
    is_organization_trail         = true
    enable_log_file_validation    = true
    kms_key_id                    = aws_kms_key.logs.arn
    include_global_service_events = true

    advanced_event_selector {
      name = "s3-object-level"
      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }
      field_selector {
        field  = "resources.type"
        equals = ["AWS::S3::Object"]
      }
    }
  }
```

The absence form, in Bicep. The `match` side has no dangerous value in it at all — the finding is that the file ends where it does, which is why this row needs the count sweep and not a grep:

```detector
match: |
  resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
    name: vaultName
    location: location
    properties: {
      tenantId: subscription().tenantId
      sku: {
        family: 'A'
        name: 'standard'
      }
      enableRbacAuthorization: true
      publicNetworkAccess: 'Disabled'
    }
  }
nomatch: |
  resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
    name: vaultName
    location: location
    properties: {
      tenantId: subscription().tenantId
      sku: {
        family: 'A'
        name: 'standard'
      }
      enableRbacAuthorization: true
      publicNetworkAccess: 'Disabled'
    }
  }

  resource vaultDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
    scope: vault
    name: 'audit-to-workspace'
    properties: {
      workspaceId: workspace.id
      logs: [
        {
          categoryGroup: 'audit'
          enabled: true
        }
      ]
    }
  }
```

### 18. Backup, replica and snapshot configuration (`backup-and-replica-configuration`)

- **Backups exist and survive deletion of the primary.** `backup_retention_period = 0` on `aws_db_instance` means no automated backups; `skip_final_snapshot = true` means destroying the instance destroys the last copy; `deletion_protection = false` on a production database; `point_in_time_recovery` disabled on a DynamoDB table; Azure `backup_retention_days`; Cloud SQL `backup_configuration.enabled`.
- **Backups are not in the same blast radius as the primary.** A backup in the same account and region as the database it protects is destroyed by whoever destroys the database. Cross-account copy, AWS Backup with a vault lock, or an immutable destination is the control. Report which the configuration shows.
- **A replica or export inherits the primary's protections.** AWS forbids an unencrypted read replica or snapshot copy of an encrypted RDS/Aurora source, and Cloud SQL and Azure SQL encrypt by default with no off switch — so "replica without the same encryption as the primary" is rarely findable in managed IaC and should not be filed speculatively. **Where it is real is self-managed replication and exports:** a logical dump to a bucket, a `pg_dump` in a CronJob, a self-managed streaming replica on an EC2 instance, a BigQuery or Redshift export target, an analytics copy in a different account. Check those destinations against the primary's encryption, network exposure and access control.
- **Snapshot and image sharing** is item 6's exposure check, and it belongs in this item's report when the snapshot is a backup: an `aws_db_snapshot_copy` / `aws_db_cluster_snapshot` shared with another account, an `aws_snapshot_create_volume_permission` naming a **foreign `account_id`**, or an `aws_ami_launch_permission` with `group = "all"` on an image built from the backup. Per item 6: Terraform cannot express a *public* EBS snapshot — that is an out-of-band `ModifySnapshotAttribute --group-names all`, so look for it in scripts and SDK calls and record the live snapshot attributes as an open question.

```detector
match: |
  resource "aws_db_instance" "app" {
    identifier              = "app"
    engine                  = "postgres"
    backup_retention_period = 0
    deletion_protection     = false
    skip_final_snapshot     = true
  }
nomatch: |
  resource "aws_db_instance" "app" {
    identifier                = "app"
    engine                    = "postgres"
    backup_retention_period   = 14
    deletion_protection       = true
    skip_final_snapshot       = false
    final_snapshot_identifier = "app-final"
    copy_tags_to_snapshot     = true
  }
```

### 19. Region and replication inventory (`data-region-inventory`)

This item produces an **inventory, not a verdict.** Collect the facts; the lawfulness of a transfer is privacy's `cross-border-transfer-route` and the PHI question is hipaa's.

Enumerate and report:

- Every `region` / `location` value across providers, provider aliases, `aws_region` data sources, and per-resource overrides. A provider alias in a second region is easy to miss and is exactly how data lands somewhere unintended.
- Every replication and geo-redundancy setting: `aws_s3_bucket_replication_configuration` and its destination bucket, region and account; `account_replication_type` on an Azure storage account (`GRS`/`RA-GRS` replicates to the paired region, which may be in another jurisdiction); GCS `location` of `MULTI_REGION` or `DUAL_REGION`; Cloud SQL and RDS cross-region read replicas; DynamoDB global tables; a CDN with no geo restriction.
- Backup and snapshot copy destinations, and log archive destinations — these are data too and are routinely in a different region from the primary.
- Managed AI/ML and analytics service regions, where a service may process data outside the region it is called from.

Report as a table of *store → region → replication destination(s) → account*, and mark each row you could not resolve as unresolved rather than filling it in.

```detector
match: |
  resource "aws_s3_bucket_replication_configuration" "exports" {
    bucket = aws_s3_bucket.exports.id
    role   = aws_iam_role.replication.arn

    rule {
      id     = "all"
      status = "Enabled"
      destination {
        bucket        = "arn:aws:s3:::acme-exports-apse1"
        account       = "999988887777"
        storage_class = "STANDARD"
      }
    }
  }
nomatch: |
  resource "aws_s3_bucket_replication_configuration" "exports" {
    bucket = aws_s3_bucket.exports.id
    role   = aws_iam_role.replication.arn

    rule {
      id     = "all"
      status = "Enabled"
      destination {
        bucket        = aws_s3_bucket.exports_dr.arn
        storage_class = "STANDARD"
      }
    }
  }
```

### 20. BaaS security rules (`baas-security-rules`)

A rules file is the entire authorization layer for a client that talks to the datastore directly. There is no server in the path to fall back on, so a permissive rule is not a hardening gap — it is unauthenticated access to the database.

- **`allow read, write: if true;`** and every variant: `if true` on any rule, a rule guarded only by `request.auth != null` (which means *any* signed-in user of the project, including one who just self-registered), and a match block on `/{document=**}` that grants broadly and is not narrowed by a later, more specific rule. Firebase rules do **not** work like a firewall where a later deny wins: if any matching rule allows, access is allowed. A broad `allow` at a parent path cannot be revoked by a child rule.
- **Realtime Database:** `".read": true` / `".write": true` in `database.rules.json`, and rules that validate shape but not ownership.
- **Storage rules:** the same pattern on `storage.rules`, plus write rules with no `request.resource.size` or `contentType` constraint, which is an upload-abuse path.
- **The expiry trap:** rules generated in test mode carry `request.time < timestamp.date(YYYY, M, D)`. After that date they deny everything, before it they allow everything. Read the date and say which side of it the project is on.
- **Ownership predicates that do not bind to the document being written.** `request.auth.uid == request.resource.data.ownerId` lets the client set `ownerId` to itself on a document it does not own — the check must compare against `resource.data.ownerId` for updates, and creates must additionally constrain the field.
- **`firebase.json`** — which rules files are actually deployed. A hardened `firestore.rules` that is not referenced in `firebase.json` is not in force.

```detector
match: |
  rules_version = '2';
  service cloud.firestore {
    match /databases/{database}/documents {
      match /{document=**} {
        allow read, write: if true;
      }
    }
  }
nomatch: |
  rules_version = '2';
  service cloud.firestore {
    match /databases/{database}/documents {
      match /patients/{patientId} {
        allow read: if request.auth != null
                    && request.auth.uid == resource.data.ownerId;
        allow update: if request.auth != null
                      && request.auth.uid == resource.data.ownerId
                      && request.resource.data.ownerId == resource.data.ownerId;
        allow create: if request.auth != null
                      && request.resource.data.ownerId == request.auth.uid;
        allow delete: if false;
      }
    }
  }
```

```detector
match: |
  {
    "rules": {
      ".read": true,
      ".write": "auth != null"
    }
  }
nomatch: |
  {
    "rules": {
      "patients": {
        "$uid": {
          ".read": "auth != null && auth.uid === $uid",
          ".write": "auth != null && auth.uid === $uid"
        }
      }
    }
  }
```

### 21. Chart and manifest provenance (`helm-and-manifest-source-pinning`)

- **`Chart.yaml` dependencies with a version range.** `version: ">=1.0.0"` or `~2.1.0` resolves at `helm dependency update` time, so the chart you audited is not the chart that deploys. Pin an exact version, commit `Chart.lock`, and — the stronger form — vendor the chart under `charts/` or reference it by OCI digest.
- **`Chart.lock` absent, or present and stale** relative to `Chart.yaml`. Absent means nothing records what was resolved. `helm dependency update` rewrites it, so a lock whose `digest` does not match the dependencies is a signal nobody runs the pinned path.
- **Repository trust.** A `repository:` URL pointing at a personal or unvetted host, or an OCI registry nobody controls. Prefer `oci://` with a digest, and check whether `helm` verification (`--verify` with a provenance file) is used anywhere.
- **`kubectl apply -f https://…`** in a Makefile, a README, a bootstrap script or a CI job pulls an arbitrary manifest at apply time from a URL whose content can change. This is the "install the operator" one-liner that ends up in production. The same applies to a remote Kustomize base: `resources:` entries in `kustomization.yaml` pointing at `github.com/...?ref=main` — a branch ref, not a tag or commit.
- **Operator and controller permissions.** Operators install their own ClusterRoles, and many request `cluster-admin` or the equivalent wildcard. Read the operator's RBAC manifest as item 10's finding, and note in the report that installing the operator grants it.
- **Helm rendering hides things.** Audit the *rendered* output (`helm template`) as well as the values file — a chart's default `values.yaml` may enable a privileged sidecar, a hostPath, or a LoadBalancer that the repository's own values never mention.

```detector
match: |
  apiVersion: v2
  name: platform
  version: 0.4.0
  dependencies:
    - name: ingress-nginx
      version: ">=4.0.0"
      repository: https://kubernetes.github.io/ingress-nginx
nomatch: |
  apiVersion: v2
  name: platform
  version: 0.4.0
  dependencies:
    - name: ingress-nginx
      version: 4.12.1
      repository: oci://ghcr.io/acme/charts
```

```detector
match: |
  apiVersion: kustomize.config.k8s.io/v1beta1
  kind: Kustomization
  resources:
    - github.com/acme/platform//manifests?ref=main
    - https://raw.githubusercontent.com/example/operator/main/install.yaml
nomatch: |
  apiVersion: kustomize.config.k8s.io/v1beta1
  kind: Kustomization
  resources:
    - github.com/acme/platform//manifests?ref=8f1c4b2e9d7a0c3f6b5e8a1d4c7f0b3e6a9d2c5f
    - ../../base
```

## Severity calibration

`severity_floor: low` is presentational: it orders this lens's findings in the report. It never suppresses a finding, and nothing below may be dropped because it sits at Low or Info.

**The rule that does the most work here: no severity may rest on a condition the repository cannot establish.** Every High and Critical below names the artifact that satisfies it — a resource name, a config key, a label, a policy element, an API symbol or a glob. A row phrased as a property nobody can look up ("the resource is internet-facing", "the role is assumable by an untrusted principal", "the cluster enforces the policy") silently downgrades that finding forever, and a permanently downgraded finding is worse than an absent row, because it looks like it was assessed.

**The second rule: twelve re-grades, because correcting the prose and leaving the consumer in place ships a fully operational bug behind corrected documentation.** Each row below was a live instruction in the source material.

| Source instruction | Why it was wrong | Re-graded |
|---|---|---|
| "Bucket policies overriding account-level block public access" | BPA is the backstop and overrides bucket policies and ACLs; nothing overrides BPA. The instruction described an impossible artifact, so it found nothing. | **Critical — Block Public Access disabled or absent.** Established from `aws_s3_account_public_access_block` / `aws_s3_bucket_public_access_block` being absent, or any of `block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets` set `false`; or `aws_s3_bucket_ownership_controls` re-enabling ACLs. Since April 2023 new buckets ship BPA-on with ACLs disabled, so this is now a *deliberate* act — narrower finding, higher confidence. Where the account-level resource is not in the repository, the account setting is an open question, not an assumption. |
| "Resource-based policies overriding identity-based denies in unexpected ways" | An explicit `Deny` in any applicable policy always wins. The instruction sent reviewers looking for an override that cannot exist, and left resource policies unaudited. | **High — a grant that exists only in a resource policy.** Inside one account, either policy allowing is sufficient. Established by enumerating `aws_s3_bucket_policy`, `aws_kms_key_policy`, `aws_sqs_queue_policy`, `aws_sns_topic_policy`, `aws_lambda_permission`, `aws_ecr_repository_policy`, `aws_cloudwatch_event_bus_policy`, `aws_secretsmanager_secret_policy`. **High — confused deputy**: a service principal with no `aws:SourceAccount`/`aws:SourceArn` (no `source_account`/`source_arn` on `aws_lambda_permission`). Critical when the principal is `*` or a foreign account with no identity-bearing condition. |
| "PodSecurityPolicy (deprecated) or Pod Security Admission policies not enforced" | PSP was removed in Kubernetes 1.25, so half the check could never fire and the other half was unspecified. | **High — no enforced pod-security control.** Established from `pod-security.kubernetes.io/enforce` absent on `kind: Namespace`, or present with value `privileged`; plus no Kyverno `ClusterPolicy`, Gatekeeper constraint or `ValidatingAdmissionPolicy` — or one present in audit-only mode (`validationFailureAction: Audit`, `enforcementAction: dryrun`, `validationActions: [Audit]`), which is its own finding because the artifact exists and reads as done. |
| "`hostPath` volumes (especially `/var/run/docker.sock`, `/etc`, `/var/lib/kubelet`)" | Dockershim was removed in 1.24; ranking the Docker socket first walked reviewers past the sockets a modern node actually has. | **Critical — container runtime socket mounted into a workload**, in this order: `/run/containerd/containerd.sock`, `/run/crio/crio.sock`, then `/var/run/docker.sock` (still real on Compose hosts and DinD build pods). **Critical** also for a writable `hostPath` on `/`, `/etc`, `/etc/kubernetes`, `/var/lib/kubelet`; **High** for `/var/log`, `/dev`, `/sys`; **Low** for a read-only mount of a certificate bundle. |
| "`create` on serviceaccounts/tokenrequest" | Not an RBAC resource string, so the grep matched nothing in any cluster. | **Critical — `create` on `serviceaccounts/token`**, plus the escalation grants the source omitted: `create` on `pods`, `pods/exec`, `pods/attach`, `pods/portforward`; `get`/`list`/`watch` on `secrets`; `update`/`patch` on `nodes`; `get`/`create`/`patch` on `nodes/proxy`; `escalate`/`bind` on `roles`/`clusterroles`; `impersonate`; `create` on `certificatesigningrequests` with `update` on `certificatesigningrequests/approval` and `approve` on `signers`; `create` on webhook configurations. |
| "ServiceAccount tokens with no expiry (pre-1.22)" | A version-history note, not a check — bound tokens are the default since 1.22 and auto-created token Secrets stopped in 1.24. | **High — a hand-written `kind: Secret` of `type: kubernetes.io/service-account-token`**, which still yields a non-expiring credential and is visible in the repository. |
| "Resources created with `prevent_destroy = false`" | A `lifecycle` meta-argument whose default is already `false`; the literal appears in almost no configuration. | **Low, or Medium for a store of record — no `lifecycle { prevent_destroy = true }`** on `aws_db_instance`, `aws_rds_cluster`, `aws_s3_bucket`, `aws_kms_key`, `aws_dynamodb_table`, `azurerm_mssql_database`, `google_sql_database_instance`. It is a guard rail against an operator mistake, not a security control, and must not be filed higher. |
| "No image signature verification (Cosign, Notary)" | Notary v1 / Docker Content Trust is legacy; naming it points a team at a dead mechanism. | **Medium — no enforcing verification in the deploy path** (Cosign or Notation, enforced by Kyverno `verifyImages` with `required: true` and `mutateDigest: true`, a Gatekeeper constraint, Binary Authorization not in `dryrun`, or AWS Signer with ECR). **High — keyless `cosign verify` with no effective identity constraint**, stated with the cosign version established: absent flags on a pinned 1.x, or an unconstraining `--certificate-identity-regexp '.*'` / `--insecure-ignore-tlog` on any version. Cosign 2.0 made both flags mandatory, so a version-free "flags are missing" finding is wrong on a current toolchain — see Checklist item 13. |
| "No automated unused permission detection (AWS Access Analyzer, Azure PIM, GCP Recommender)" | Entra PIM is JIT elevation and detects nothing; accepting it clears a finding nothing addressed. | **Low — no unused-access review process**, with the control named correctly: IAM Access Analyzer unused access findings, Entra Permissions Management (CIEM) plus access reviews, IAM Recommender / Policy Analyzer. PIM may be cited only as JIT elevation. Never run Access Analyzer from inside the audit — it is a credentialed call to the provider. |
| "secrets mounted as env vars … leak via `kubectl describe`" | `kubectl describe` prints `<set to the key 'x' in secret 'y'>`, not the value. The stated mechanism is checkable and false. | **Medium — secret delivered as an environment variable**, on the real grounds: `/proc/<pid>/environ`, child-process inheritance, core dumps and telemetry, `kubectl exec -- env`, and non-rotatable without a restart. **`docker inspect` does print values**, so Docker/Compose delivery is Medium on that ground too. **High — a literal `value:` in a committed manifest**, which is a different finding. |
| "KMS key policies that grant `kms:*` to the root user of any account" | The own-account `root` ARN with `kms:*` is AWS's default key policy and delegates to IAM; the check fired on nearly every key. | **High — `Principal: "*"` or an org-wide grant with no `aws:PrincipalOrgID`** on a key policy. **High — a `root` principal belonging to a different account**, which delegates the key to that whole account. Absent `kms:ViaService`/`kms:CallerAccount` scoping is a Medium contributor, and `aws_kms_grant` / `CreateGrant` must be enumerated because they never appear in the policy. The default statement is **not a finding**. |
| GCP "primitive roles" | Renamed; also the reason the default Compute service account matters is its Editor grant. | **High — a basic role (`roles/owner`, `roles/editor`, `roles/viewer`) on a project**, and **High — the default Compute Engine service account attached to GKE nodes or instances**, which holds Editor unless changed. |

### Severity table

Every row names what establishes it.

**Read the minus-one rule below carefully, because the obvious reading downgrades this lens's principal findings across the board.** Most rows here are absence-shaped (Scope, first bullet): no `metadata_options`, no PSA label, no BPA resource, no `prevent_destroy`. For those rows **the absence *is* the finding**, and the establishing artifact is the construct that should have carried the setting — an `aws_instance`, a `kind: Namespace`, a bucket resource, a launch template. That construct is in the repository, so the row fires at its stated severity. Minus-one does **not** apply.

**Minus one applies only when the construct that would carry the setting is itself outside the repository** — account-level Block Public Access this repository does not manage, an SCP that lives in the management account, a launch template owned by a module in another repo. In that case report at the stated severity minus one with the assumption written out — not dropped, and not asserted. Applying minus-one to an absence-shaped row produces a permanently downgraded finding that looks like it was assessed, which is the harm the paragraph above this table names.

| Severity | Finding | Established by |
|---|---|---|
| Critical | Object storage readable by anonymous or all-authenticated principals | `Principal: "*"`/`{"AWS": "*"}` with no identity-bearing condition, `allUsers`, `allAuthenticatedUsers` (**grep both — they share no substring**), `container_access_type = "blob"` **or** `"container"`, `acl = "public-read"` with ACLs enabled — **and** BPA not enforcing per the re-grade row above. In Bicep and ARM: `properties.allowBlobPublicAccess: true` on `Microsoft.Storage/storageAccounts` **with** `properties.publicAccess: 'Blob'` or `'Container'` on a `…/blobServices/containers` child, and the account's `properties.networkAcls.defaultAction` not `'Deny'`. Listing is the aggravator, not the threshold: `s3:ListBucket` to the anonymous grant, or `container_access_type = "container"` / `publicAccess: 'Container'`, additionally turns the store into an index of every key. |
| Critical | `iam:PassRole` with `Resource: "*"` | `actions = ["iam:PassRole"]` with `resources = ["*"]` and no `iam:PassedToService` condition |
| Critical | Wildcard action and resource on a role | `"Action": "*"` with `"Resource": "*"`, or `*`/`*`/`*` in a Kubernetes ClusterRole rule |
| Critical | Trust policy assumable by anyone | `Principal: {"AWS": "*"}` with no identity-bearing condition; an OIDC `sub` `StringLike` wildcarded in the org or repository segment; a Workload Identity pool provider with `attribute_mapping` and no `attribute_condition` |
| Critical | Managed database reachable from the internet | `publicly_accessible = true` / `public_network_access_enabled = true` / Cloud SQL `authorized_networks` of `0.0.0.0/0`, with an ingress rule on the engine port from `0.0.0.0/0` or `::/0`. **In Bicep and ARM, the exact paths:** `properties.network.publicNetworkAccess: 'Enabled'` on `Microsoft.DBforPostgreSQL/flexibleServers` or `Microsoft.DBforMySQL/flexibleServers`, or `properties.publicNetworkAccess: 'Enabled'` on `Microsoft.Sql/servers`, **paired with** a `…/firewallRules` child whose `properties.startIpAddress` and `properties.endIpAddress` are both `'0.0.0.0'` — the "allow all Azure services" sentinel, which admits Azure IP space across every tenant and shares no substring with `0.0.0.0/0` — or `'0.0.0.0'` to `'255.255.255.255'`, which is the internet-wide rule and worse. Absence of both `delegatedSubnetResourceId` and a `Microsoft.Network/privateEndpoints` naming the server is what makes the public endpoint the only path in. A firewall rule on a server whose public access is `'Disabled'` establishes nothing — read the pair, per item 3. |
| High | Azure PaaS data plane reachable from the internet | `properties.publicNetworkAccess` **absent or `'Enabled'`** on `Microsoft.KeyVault/vaults`, `Microsoft.Storage/storageAccounts`, `Microsoft.DocumentDB/databaseAccounts`, `Microsoft.Search/searchServices`, `Microsoft.CognitiveServices/accounts` — **absent counts, because `Enabled` is the platform default on these types** — together with `properties.networkAcls.defaultAction: 'Allow'` (or no `networkAcls` at all) and no `Microsoft.Network/privateEndpoints` resource naming the store in `privateLinkServiceConnections[].properties.privateLinkServiceId`. Established with `bicep_absent` and the `pe:` count in item 0. **Critical on `Microsoft.KeyVault/vaults`**, where the store's entire contents are credentials and the only remaining control is Entra authorization. |
| Critical | Terraform state exposed | a tracked `*.tfstate` or `*.tfstate.backup`, or a state bucket whose own BPA is off |
| Critical | Privileged pod or node-takeover mount | `privileged: true`; `hostPath` on a runtime socket or a writable `/`, `/etc`, `/etc/kubernetes`, `/var/lib/kubelet` |
| Critical | RBAC subject that can mint credentials or read all secrets cluster-wide | the grant table in item 10, at `ClusterRole` scope, or any powerful role bound to `system:authenticated`, `system:unauthenticated`, `system:serviceaccounts`, or `cluster-admin` |
| Critical | BaaS rules allowing unauthenticated read and write of user data | `allow read, write: if true;`, `".read": true`/`".write": true`, or a `/{document=**}` allow with no ownership predicate |
| High | IMDSv1 permitted | `http_tokens = "optional"`, or no `metadata_options` block on `aws_instance`/`aws_launch_template`/`aws_launch_configuration` |
| High | Pods can reach the node's IMDS and assume the node role | `http_put_response_hop_limit` ≥ 2 on the launch template behind a node group that runs **pod-networked** workloads — the EKS managed-node-group default — with no egress `NetworkPolicy` on `169.254.169.254/32` and no IRSA / EKS Pod Identity. A `hostNetwork` pod reaches IMDS at *any* hop limit, so hop limit 1 is never its mitigation; for those the establishing artifacts are `http_tokens` and a node-level block. `AWS_EC2_METADATA_DISABLED` does not establish this row in either direction — it is an SDK variable, not a reachability control. |
| High | Grant reachable only through a resource policy, or a confused deputy | the resource-policy enumeration in item 1; a `Service` principal with no `source_account`/`source_arn` |
| High | Foreign-account or wildcard KMS key grant | a `root` principal from another account, or `Principal: "*"` with no `aws:PrincipalOrgID` |
| High | Unauthenticated serverless invocation path | `authorization_type = "NONE"`, `AuthType: NONE` (`AWS::Lambda::Url`), **`AuthorizationType: NONE`** (API Gateway) and **`DefaultAuthorizer: NONE`** (SAM), `authLevel: anonymous` and **`AuthorizationLevel.Anonymous`** (Azure Functions, JSON and C# respectively), `--allow-unauthenticated`, `allUsers` on a Cloud Run service — with a handler that performs a state change or reads data by a request-supplied id. **`AuthType` and `AuthorizationType` are different keys on different resources**; a row that names only the first clears every open API Gateway route. |
| High | No enforced pod-security control | per the re-grade row: PSA label absent or `privileged`, and no enforcing admission policy |
| High | No control-plane audit trail, or one that can be tampered with | no `aws_cloudtrail`/diagnostic setting/audit-log sink; `enable_log_file_validation = false`; `is_multi_region_trail = false`; log destination inside the audited account with no immutability. **On Bicep and ARM: zero `Microsoft.Insights/diagnosticSettings` resources in the deployment** — `diag: 0` beside a non-zero `stores:` on item 0's count line — or settings that exist but carry only a `metrics[]` array, or whose `scope:` set does not cover every store. Phrase the Azure finding as item 17 states it: the Activity log still exists for 90 days, and what is missing is every data-plane read record and any export outside the subscription's own blast radius. |
| High | Sensitive port open to `0.0.0.0/0` or `::/0` | ingress on 22, 3389, 3306, 5432, 27017, 6379, 1433, 9200/9300, 2375/2376, 5984, 11211, or `protocol = "-1"` / all-ports range, on a group this repository attaches to a workload |
| High | Keyless signature verification with no effective identity constraint | on a pinned cosign 1.x, absence of `--certificate-identity`/`--certificate-identity-regexp` or `--certificate-oidc-issuer`; on any version, `--certificate-identity-regexp '.*'`, an unanchored regexp, `--insecure-ignore-tlog` or `--insecure-ignore-sct`. Name the version you established. |
| High | Explicitly disabled encryption on a store that supports disabling it | `storage_encrypted = false`, `encrypted = false`, `at_rest_encryption_enabled = false` |
| High | Machine image shared publicly | `aws_ami_launch_permission` with `group = "all"` (the only valid value of `group`). `aws_ami` has no settable `public` argument and Terraform cannot express a public EBS snapshot — for snapshots the establishing artifacts are an `aws_snapshot_create_volume_permission` naming a foreign `account_id`, or an out-of-band `ModifySnapshotAttribute --group-names all` in a script or SDK call. |
| Medium | Secret delivered as an environment variable | `valueFrom.secretKeyRef` under `env:`, or a literal in `environment { variables }` — on the mechanisms in item 16, not on `kubectl describe` |
| Medium | No backup, or a backup in the primary's blast radius | `backup_retention_period = 0`, `skip_final_snapshot = true`, `deletion_protection = false`, backup destination in the same account and region |
| Medium | No enforcing signature verification in the deploy path | `cosign sign` in CI with no admission-time enforcement; Binary Authorization in `dryrun`; Kyverno `verifyImages` with `required: false` |
| Medium | Mutable image reference in a deployed workload | a tag-only `FROM` or `image:`, `:latest`, `:main`; no digest and no renovation path behind a pin |
| Medium | Transport security not enforced at the resource | no `aws:SecureTransport` deny; `min_tls_version` of `TLS1_0`/`TLS1_1`; a port-80 listener with no redirect; `require_ssl`/`require_secure_transport` absent. In Bicep and ARM: `properties.minimumTlsVersion: 'TLS1_0'`/`'TLS1_1'` or `properties.supportsHttpsTrafficOnly: false` on `Microsoft.Storage/storageAccounts`, `properties.minimalTlsVersion` on `Microsoft.Sql/servers`. **Both Azure properties have safe defaults, so here the value written out establishes the row and an absence does not** — the opposite direction from `publicNetworkAccess` on the same resource. |
| Medium | No customer-managed key where key ownership is required | absence of `kms_key_id`/CMEK/disk encryption set **plus a named classification or contract clause** that requires it. Without that named requirement this is Info, phrased as "platform-managed keys in use". |
| Low | No `lifecycle { prevent_destroy = true }` on a store of record | absence on the resource list in item 15 (Medium where the resource is the system of record) |
| Low | No unused-access review process | absence of IAM Access Analyzer unused access findings / Entra Permissions Management / IAM Recommender in the estate's tooling |
| Low | Availability and cost controls absent | no `reserved_concurrent_executions`, a 900-second function timeout on a public URL, no `limits` on a Kubernetes workload |
| Low | CIS Level 1 hygiene | `HEALTHCHECK` absent (Docker/Compose only — **Kubernetes ignores it and uses probes**), no multi-stage build, no `.dockerignore`, default NACLs left as-is, extensive inline policies where managed policies would be auditable |
| Low | Default VPC used for production | the real defect is `map_public_ip_on_launch = true` on its subnets, not the VPC's existence — say which one you found |
| Info | Region and replication inventory | the table in item 19, with unresolved rows marked unresolved |
| Info | CIS Level 2 profile gaps | named as Level 2 in the finding, never displacing a real finding in the ranked list |

### How proof tier interacts with severity here

**A static checker executed by the repository's own test runner, asserting both directions, is T1 — an executed repo-local test — not a static observation.** Concretely: a test that asserts `detect(fixtures/vulnerable/X) == 1` **and** `detect(fixtures/clean/X) == 0`, run by `pytest` / `npm test` / `go test`, is an executed proof. Without this rule every finding in this lens caps at Medium, because the hard rails strip the dynamic half of every cloud recipe — and that would systematically under-rate the domain with the largest blast radius in the audit.

Two corollaries:

- **A one-directional checker does not qualify.** A test that only asserts the clean fixture passes proves nothing about detection: it is exactly the failure mode that shipped the unfireable checks in the Scope table. Both fixtures, or it is not T1.
- **The tier governs the strength of the evidence, not the severity of the defect.** A Critical configuration defect that is fully visible in the artifact stays Critical when the only available proof is T1-static. Do not discount a finding because the exploit could not be run against an account you are forbidden to touch — state the reachability assumption instead.

## Known false positives

Each entry names a pattern a competent reviewer would flag and states why it is not the finding it looks like. **None is a licence to drop a finding**: every entry names the narrower finding that survives, and the discriminator that decides between them. A wrong clearance is worse than a wrong finding, because nobody re-opens a closed item — so if you cannot establish the discriminator, the finding stays open at the lower severity with the assumption written out.

1. **`Resource: "*"` in an IAM statement.** A large set of AWS actions do not support resource-level permissions and are only expressible with `Resource: "*"`: `ec2:Describe*`, `s3:ListAllMyBuckets`, `cloudwatch:PutMetricData`, `logs:DescribeLogGroups`, `sts:GetCallerIdentity`, `kms:ListAliases`, and most `*:List*` / `*:Describe*`. For those, least privilege is expressed with condition keys (`aws:RequestedRegion`, `aws:ResourceTag`, `aws:PrincipalTag`), not with ARNs. **File only when the action is resource-scopable** — `s3:GetObject`, `secretsmanager:GetSecretValue`, `dynamodb:*Item`, `kms:Decrypt`, `iam:PassRole`, `sqs:ReceiveMessage` — or when `Action` itself is `*`. Check the service authorization reference for the specific action before filing; guessing which actions support resource-level permissions is how this becomes a false positive.

2. **`Principal: "*"` in a trust or resource policy.** A wildcard principal must be judged together with the statement's `Condition`. Wildcard plus `aws:PrincipalOrgID`, `sts:ExternalId`, `aws:SourceAccount`/`aws:SourceArn`, `aws:PrincipalArn`, or an OIDC `sub`/`aud` `StringEquals` is how vendor integration roles and GitHub Actions/EKS OIDC roles are legitimately written. **Three discriminators keep this from clearing a real finding:** the condition must be in the *same statement* as the wildcard; the key must be **identity-bearing** — a statement whose only condition is `Bool: {"aws:SecureTransport": "true"}`, or `aws:RequestedRegion`, or `aws:UserAgent`, is open to the internet and this entry does not cover it; and a `StringLike` wildcard in a load-bearing segment is the finding, not the clearance — an OIDC `sub` of `repo:org/*:*` is satisfied by every repository in the organization. Quote the whole statement in the finding, never the `Principal` line alone.

3. **A KMS key policy granting `kms:*` to `arn:aws:iam::<own-account-id>:root`.** That is AWS's own default key policy. The ARN does not mean the root *user*; it means "delegate authorization for this key to this account's IAM policies," and it is required for IAM-based access to work — the console, CloudFormation and Terraform all generate it, and removing it can leave the key unmanageable. **Flag instead when the principal is `"*"`, a *different* account's `root`, or an org-wide principal with no `kms:ViaService`/`kms:CallerAccount` constraint.** Read the twelve digits against the account this configuration deploys to; a `root` ARN that merely *looks* like the local account in a multi-account repository is the case this entry most often gets wrong in the dangerous direction.

4. **A bucket with no explicit server-side-encryption block.** Since January 2023 S3 applies SSE-S3 (AES-256) to every new object upload in **every** bucket, old buckets included, and it cannot be turned off; Azure Storage and GCS have always encrypted at rest with platform-managed keys and offer no off switch. A missing `aws_s3_bucket_server_side_encryption_configuration` therefore does not mean unencrypted. **Where key ownership matters, reframe explicitly as the narrower claim** — "no customer-managed key (SSE-KMS / CMEK / disk encryption set) where the data classification or the contract requires key ownership and revocability" — and name the classification or clause. Say in the finding that it is the narrower claim. This entry does **not** cover stores where encryption genuinely can be disabled: `storage_encrypted = false`, `encrypted = false` and `at_rest_encryption_enabled = false` are real findings.

5. **`runAsUser` unset, read as running as root.** Unset means "inherit the image's `USER`", and distroless `:nonroot`, `nginxinc/nginx-unprivileged`, Chainguard/Wolfi and Bitnami images already declare a non-root UID. Either verify the base image, or — better — look for the control that enforces this regardless of the image: `runAsNonRoot: true`, which makes the kubelet refuse to start a container whose effective user is UID 0, or Pod Security Admission `restricted` on the namespace. **Report "no enforcement mechanism", not "`runAsUser` is unset".** Two notes that keep this honest: `runAsNonRoot: true` can only be verified by the kubelet when the image's `USER` is numeric, so a named user still needs the image checked; and this entry says nothing about `privileged: true`, `allowPrivilegeEscalation`, capabilities or `hostPath`, each of which is a finding on its own terms.

6. **Any `0.0.0.0/0` rule reported as exposure.** Egress `0.0.0.0/0` is the default and near-universal, and `0.0.0.0/0` on 80/443 attached to a public ALB or an ingress security group is the intended design. **Hold to the sensitive-port list** in item 3 and to the all-ports forms (`protocol = "-1"`, `from_port = 0, to_port = 65535`), and check `::/0` alongside `0.0.0.0/0`. What this entry deliberately does **not** license is a clearance based on runtime reachability: whether the group is attached to an internet-reachable ENI is account state this audit cannot see, and a group that is attached to nothing today is attached by the next `terraform apply`. Where the group is not referenced by any resource in this repository, that is a **downgrade to Medium with the assumption stated** — a latent misconfiguration that will be attached by whoever adds the next instance — and never a dismissal. (See the first rejected candidate below.)

   **The Azure forms of this entry, because the camelCase stack has two of its own.** `sourceAddressPrefix: 'Internet'` on an NSG rule is this same entry: on 443 to an application-gateway subnet it is the design, and the discriminator is still item 3's port list plus `access`/`priority` relative to the deny rule that follows. The second form is the one to get exactly right, and it cuts both ways. **A `startIpAddress`/`endIpAddress` pair of `'0.0.0.0'`–`'0.0.0.0'` must not be reported as `0.0.0.0/0` or as "open to the internet"** — it is Azure's allow-all-Azure-services sentinel, a reviewer who has read the Azure docs will say so, and the overstatement is what gets the whole finding closed. **What survives is not smaller by much and must be stated instead:** the rule admits Azure IP space across every tenant, so an attacker with any Azure subscription is past the network boundary, which is a real Critical on a database whose `publicNetworkAccess` is `'Enabled'`. The genuinely clearing case is narrow and checkable: the same rule on a server whose public data plane is `'Disabled'` or which is VNet-injected is **inert configuration**, and that is an Info-grade hygiene note rather than an exposure. And `'0.0.0.0'`–`'255.255.255.255'` is not covered by this entry at all — that one is the internet-wide rule.

7. **A bucket policy whose only grant is to the CloudFront service principal.** `Principal: {"Service": "cloudfront.amazonaws.com"}` with `s3:GetObject` and a `Condition` on `AWS:SourceArn` matching a specific distribution is **not** a public bucket — it is the origin access control pattern that makes the bucket *private* and forces traffic through the distribution. Flagging it as a public grant is the most common misread of a correct S3+CloudFront configuration. The finding survives in three shapes, all checkable: the `SourceArn` condition is absent, so any CloudFront distribution in any account can read the bucket; the same bucket *also* carries an anonymous grant or has BPA off; or there is no origin access control at all, in which case the bucket's own endpoint is reachable directly and bypasses whatever the distribution enforces.

### Rejected candidates

Candidates considered for the list above and deliberately excluded. Nothing here should be quietly re-added; each would have suppressed a real finding, or moved a finding into a section that cannot enforce it.

**Rejected because it is a clearance the audit cannot establish:**

- **"A security group is not an exposure because it is attached to no ENI, or sits behind SSM Session Manager."** Rejected as a clearance, kept as a downgrade. ENI attachment, route tables and the live instance inventory are account state that this audit is forbidden to query — the same recon material that proposed this clause also lists "whether a permissive security group is attached to anything internet-reachable" among the facts no proof recipe can establish. A clause that requires an unobtainable fact resolves, in practice, to whichever answer the reviewer prefers, and it resolves toward "clear" because clearing is cheaper. The checkable version is in entry 6: whether *this repository* references the group, which downgrades to Medium and states the assumption.
- **"IMDSv1 is acceptable because the current SDKs prefer IMDSv2."** Rejected. `http_tokens` defaults to `optional`, which means v1 still answers regardless of what the application's SDK prefers, and an SSRF payload is not written with an SDK. The SDK's preference is irrelevant to the attack.
- **"Kubernetes Secrets are fine because etcd encryption is presumably enabled."** Rejected: `EncryptionConfiguration` is an API-server flag this audit cannot see, and "presumably" is not a control. State it as undetermined in both directions, per Scope.
- **"Terraform state in S3 is fine because the bucket is private."** Rejected: "private" is exactly the property item 4 exists to verify, and the state bucket is the highest-value bucket in the estate. Verify BPA, the bucket policy, `encrypt = true` and locking, and report what you found.
- **"A permissive rule is acceptable because the app enforces authorization server-side."** Rejected for BaaS rules specifically: the client talks to the datastore directly, so there is no server in the path. A rules file that allows is the whole authorization decision.
- **"`allowPrivilegeEscalation: true` is the default, so it is not a finding."** Rejected: default-ness is why the field is missing, not a reason it is acceptable. The Pod Security Standards `restricted` profile requires it `false`. The legitimate narrow case — a container that genuinely needs a setuid binary — must be named in the finding, not assumed.
- **"A repository-private configuration cannot be exploited."** Rejected: repository visibility is not a cloud control, and the configuration deploys to an account whose reachability is unrelated to who can read the code.

**Rejected because it is a severity calibration, not a suppression** (a severity cap suppresses less than a false-positive rule does, and these are all real findings at a low grade):

- **CIS hygiene items — `HEALTHCHECK` absent, no multi-stage build, default VPC, default NACLs, inline versus managed policies.** Moved to `## Severity calibration` at Info/Low, never displacing a real finding in the ranked list. Two facts carried with them: **Kubernetes ignores `HEALTHCHECK` entirely** and uses probes, so it is meaningful only for Docker/Compose; and the default VPC's real defect is `map_public_ip_on_launch = true` on its subnets, not the VPC's existence.
- **Pre-signed URL with long expiry or broad scope.** Split rather than kept. The durable finding — a URL minted from a user-controlled object key with no ownership check — is web-and-api's IDOR and is deferred. The remaining fact is a severity downgrade recorded in calibration: a URL signed with role or IMDS credentials expires with those credentials (roughly one hour, twelve at most), so a nominal seven-day expiry is only real when the signer holds long-lived IAM *user* keys.
- **`imagePullPolicy: IfNotPresent`.** Not a false-positive class but an internal-consistency note, folded into item 11's digest-pinning text: `Always` earns its keep only for mutable tags on a multi-tenant cluster, and a digest-pinned image makes the policy irrelevant.
- **"Replica without the same encryption as the primary."** Correct but rarely findable in managed IaC — AWS forbids an unencrypted replica or snapshot copy of an encrypted RDS/Aurora source, and Cloud SQL and Azure SQL encrypt by default with no off switch. Redirected into item 18 as a checklist instruction pointed at the places it *is* real: self-managed replication, logical dumps, CronJob exports and analytics copies.
- **`hostPath` mounts on node-agent DaemonSets.** Cut for volume — vendor DaemonSets (CNI, CSI, fluent-bit, node-exporter) are usually not in an application repository. The discriminator is kept in item 9: a *workload* pod, a writable mount, or an escape path (`/`, `/etc/kubernetes`, `/var/lib/kubelet`, a runtime socket, `/dev`) — with the note that the modern sockets are `containerd.sock` and `crio.sock`, not `docker.sock`.
- **"No `.dockerignore`."** Real but low-signal on its own; folded into item 11 with the discriminator that decides it — whether any `COPY`/`ADD` copies a broad path such as `.` — because without a broad copy the missing file changes nothing.

## Proof recipes

Shared harness components are referenced by name and not restated here: the **canary fixture set**, the **socket-layer destination recorder**, and the **registry-driven enumerator**. Their implementations live in `lenses/_harness.md`.

**Tier rule.** **T1** is a proof the repository's own test command executes — including a static checker, provided it asserts *both* directions over a fixture pair, per `## Severity calibration`. **T2** requires the auditor to stand up infrastructure the repository does not already stand up, and the user is asked every time. A recipe the auditor writes but cannot run is reported **UNPROVEN**, never silently omitted.

**This lens has almost no T1 runtime story, and that must be said in the report rather than discovered by the reader.** Unauthenticated bucket sweeps, pod-escape demonstrations, RBAC `can-i` matrices and live IMDS probes all require either a cluster or an account. What is genuinely T1 here is *assertions over rendered artifacts*, and P1 below carries most of the weight.

### P1 — Detector plus fixture pair over the rendered artifact (T1)

**Assert against the rendered artifact, never the source.** A module, a variable default, a Helm value or a Kustomize overlay can flip any of the settings in the Checklist, so a grep over `.tf` files audits the wrong text.

- Terraform: `terraform show -json plan.out` — and because `terraform plan` against a provider that needs credentials is not permitted here, **a checked-in plan JSON fixture is an acceptable audited input** when a live plan cannot be produced offline. Say in the report which one you used.
- **Bicep: `bicep build --stdout main.bicep`, which is the one rendering step in this recipe that needs no credentials and no network** — it is a compiler, not a provider call, so the ARM JSON it emits is a T1 input on any machine with the CLI. Assert over `resources[]`, keyed on `type` and the `properties` path, which removes every layout, loop, `module` and nested-child assumption `bicep_absent` carries. Two caveats belong in the report: a `br:` registry module reference needs a restore that does reach the network, and `.bicepparam` values resolve at deployment rather than at build, so a parameterized `publicNetworkAccess` is unresolved in the built output and must be read from the parameter file or recorded as unresolved.
- Kubernetes: `helm template`, `kustomize build`, or the rendered manifests the deploy pipeline applies.
- Policy engines: `conftest test fixtures/vulnerable/x.yaml fixtures/clean/x.yaml`, or `kyverno apply` against the same pair.

**One vulnerable fixture and one clean fixture per rule, both exercised.** The assertion is `detect(vulnerable) == 1 and detect(clean) == 0`. A test that only exercises the clean side proves the rule *runs*, not that it *fires* — that is precisely how the checks in the Scope table came to report clean for years.

**Tighten the checker, then run it against the previous revision and require it to fail there.** A rule that passes on both the old and new artifact is not testing what you think. This is cheap for configuration: `git show HEAD~1:path/to/artifact` into the same checker.

**Every rule iterates resources, never files.** `terraform show -json` gives you `planned_values.root_module.resources` with a `address` per resource, and the rendered Kubernetes output is a document stream — so the assertion is "for each resource of type T, setting S holds", and the failure message names the address. A rule written as "the file does not contain S" is the file-granularity defect from item 0 moved into the test suite, where it will look green forever. Where a rule cannot resolve a cross-resource pairing (bucket → `aws_s3_bucket_public_access_block`), a **count identity** is the fallback — but write it as a tripwire, never as the assertion, and seed the fixture set with the two shapes that break it in opposite directions: **two BPA resources naming the same bucket** (the counts balance while a third bucket is bare — verified at 3/3) and **a `for_each` BPA covering five buckets** (the counts diverge while nothing is wrong — verified at 5/1). Over a plan, neither shape is a problem and the identity is unnecessary: `terraform show -json` expands `for_each` into one resource per instance and carries the resolved `bucket` reference, so assert *pairing* — every bucket address appears in the set of `bucket` values on BPA resources — and let the count identity go.

Rules worth writing first, each mapping to a checklist item: BPA flags all true at account and bucket level, and one BPA resource per bucket (item 4); over built ARM JSON, every store type in item 0's Azure pattern carries `properties.publicNetworkAccess == 'Disabled'` or a `delegatedSubnetResourceId`, every one of them is named by some `Microsoft.Network/privateEndpoints` connection, no `…/firewallRules` resource has `startIpAddress == '0.0.0.0'`, and every store is the `scope` of a `Microsoft.Insights/diagnosticSettings` carrying a `logs[]` entry — **with the vulnerable fixture being the `0.0.0.0`–`0.0.0.0` sentinel, because that is the shape a `0.0.0.0/0` rule cannot produce** (items 3, 4, 17); no ingress from `0.0.0.0/0` or `::/0` on the sensitive-port list (item 3); `http_tokens == "required"` **and `http_put_response_hop_limit <= 1`** on every launch template and instance, with a hop-limit-2 EKS node group as the vulnerable fixture because it is the platform default (item 5); every namespace carries `pod-security.kubernetes.io/enforce` with a value in `{baseline, restricted}` (item 10); no `hostPath` in the runtime-socket or node-escape set (item 9); every image reference contains `@sha256:` (items 11, 12); state backend has a lock (`use_lockfile` or `dynamodb_table`) — **not** `encrypt`, which does not establish an at-rest claim (item 15); no rule in any Role or ClusterRole grants `create` on `serviceaccounts/token`, `pods/exec` or `pods`, `get`/`list` on `secrets`, `escalate`/`bind`/`impersonate`, or `*` on `*` (item 10); every `cosign verify` invocation in the tree carries an **anchored** `--certificate-identity`/`--certificate-identity-regexp` and a `--certificate-oidc-issuer`, and carries no `--insecure-ignore-tlog`/`--insecure-ignore-sct` (item 13) — assert the anchoring, not merely the flag's presence, or the rule clears `'.*'`.

**Seed the fixture set with the multi-resource shapes, not one resource per file.** A five-bucket `s3.tf` with one BPA resource, a four-document manifest with one `securityContext`, a two-stage `Dockerfile` with `USER` only in the builder stage, and a `data "aws_iam_policy_document"` in a file of its own. Those four shapes are what every file-granular rule passes and every correct rule fails. Add the three that break a count identity or a granularity assumption: **two BPA resources naming one bucket**, **a `for_each` BPA over five buckets**, and **a two-container Deployment with a `securityContext` on the first container only**.

**Drive the resource list through the registry-driven enumerator, and commit its count.** The rules above are all of the form "for every resource of type T", and an enumeration that silently returns zero rows passes every one of them perfectly — the same failure as a `buckets: 0` count line and a `--files-without-match` that matched nothing. The component rejects a committed count of zero outright and fails when the discovered count diverges from the committed one, which is what turns these rules from a snapshot into a regression gate: the day someone adds a bucket with no BPA, or a stack the parser does not model, the test fails instead of the sweep quietly not covering it. Where the input is a plan JSON rather than a live registry, the count assertion matters *more*, not less, and the report says which input you enumerated.

### P2 — Local policy-document parser over the rendered plan (T1)

The AWS-API forms of this check — `accessanalyzer check-access-not-granted`, `check-no-new-access`, `iam simulate-principal-policy` — are credentialed network calls, and `simulate-principal-policy` additionally requires the role to already exist. **They are not run from inside the audit.** Recommend Access Analyzer to the operator as a manual follow-up.

What runs locally: parse every policy document out of the rendered plan and assert against a pinned list.

- **Both halves of the grant graph.** Enumerate identity policies *and* the resource-policy resources named in item 1. A parser that only walks `aws_iam_policy` reproduces the inversion this lens exists to correct — so the test itself should assert that the resource-policy resource types present in the plan are all covered, and fail when a new one appears unhandled.
- Escalation-action list: `iam:PassRole`, `iam:CreateAccessKey`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`, `sts:AssumeRole`, `lambda:UpdateFunctionCode`.
- Wildcard-principal-with-no-identity-condition, implemented as an **allowlist of identity-bearing condition keys** rather than "has a condition" — otherwise `aws:SecureTransport` satisfies the rule and clears an internet-open statement. Seed the test with exactly that case as a vulnerable fixture, because it is the shape that has slipped through.
- Service principal with no `aws:SourceAccount`/`aws:SourceArn`, over both policy documents and `aws_lambda_permission` arguments.
- Foreign-account `root` principals, compared against the account this plan deploys to rather than against a hardcoded id.

### P3 — Canary sweep of image layers, state and pod environment (T1)

Uses the **canary fixture set**. Populate every secret-shaped input with an unmistakable canary, build, then sweep every artifact for the canary **and its derived encodings** using that component's own expander rather than a hand-written list — a list written here drifts from the one the harness ships, and the missing form is the finding.

**Do not sweep for a precomputed `gzip` form.** Compressing the value on its own produces bytes that do not appear in a compressed *body*, where the value's bytes are interleaved with everything else, so a `gzip+base64` pattern is a sweep that cannot match — and image layers and build logs are the compressed sinks this recipe walks. Decompress the sink and sweep the result, per the component's `alsoDecompress`. Sweep as **bytes**, not as a UTF-8 string: decoding a layer tar as UTF-8 replaces invalid bytes and can destroy the sequence you are hunting.

- `docker save` the built image and grep every layer tar. This catches a secret written and then deleted in a later layer, which `docker history` alone does not show.
- `terraform show -json` over the plan or a state fixture, grepping for the canary — a `data "aws_secretsmanager_secret_version"` puts the value in state, which is the trade-off item 16 describes.
- The rendered pod spec, for a literal `value:` carrying the canary.
- `docker inspect` on a Compose service, which does print environment values — the half of the source material's env-var claim that is true.

Do not assert that `kubectl describe` leaks a `secretKeyRef`; it does not, and a test built on that premise fails for the right reason and is then deleted along with the finding.

### P4 — Destination-set assertion for metadata endpoints (T1)

Uses the **socket-layer destination recorder**. Install the guard first so an unexpected connection fails loudly instead of quietly reaching the network, record the destination set, and assert it is a subset of the allowlist. Then parametrize the metadata corpus: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, `http://[fd00:ec2::254]/`, `http://metadata.google.internal/computeMetadata/v1/`, `http://100.100.100.200/`, plus the encoded forms (`http://2130706433/`, `http://0177.0.0.1/`, `http://[::ffff:169.254.169.254]/`).

This proves the *application* cannot reach metadata. It does not prove `http_tokens = "required"`, which is P1's job — and the application-side SSRF finding belongs to web-and-api. File the pair.

### P5 — Admission-policy fixture pair (T1)

`conftest test` or `kyverno apply` against one vulnerable and one clean manifest per policy, run by the repository's test command. This is the only proof in this lens that exercises the same engine the cluster would use, which makes it the highest-value item after P1.

Assert the *enforcement mode* as well as the rule: a policy whose `validationFailureAction` is `Audit`, whose Gatekeeper constraint uses `enforcementAction: dryrun`, or whose `ValidatingAdmissionPolicyBinding` lists only `Audit`/`Warn`, blocks nothing — so the fixture pair must include a policy in audit-only mode as a *vulnerable* fixture, not just a missing policy.

### T2 — and why most cloud findings will not have one

The user is asked every time, and most repositories will decline:

- **LocalStack** for an unauthenticated-access sweep against a bucket (`403`/`404` assertions) and for state-backend behaviour.
- **kind or k3d** for everything cluster-side: `kubectl apply --dry-run=server` against a PSA-labelled namespace, a `kubectl auth can-i` matrix over the RBAC in the repository, a pod-escape demonstration from a runtime-socket mount, and the ServiceAccount-token request to `kubernetes.default`.
- A **container build host** for the layer sweep in P3 where the repository's test command does not already build the image.

### Recipes deliberately dropped, and why

These were proposed for this domain and violate the hard rails. They are recorded so they are not reintroduced as improvements:

- **`curl https://<bucket>.s3.amazonaws.com/canary.txt`**, `</dev/tcp/$DB_HOST/5432` "from a runner outside the VPC", a nightly job in a sandbox account, and `curl http://169.254.169.254/…` from a launched instance. All reach remote hosts. Dropped in their remote form; kept as the LocalStack variant (T2, localhost) and the plan-time assertion (T1).
- **`aws accessanalyzer check-access-not-granted`, `check-no-new-access`, `aws iam simulate-principal-policy`.** Credentialed calls to AWS. Replaced by P2.

### Not provable here, and reported as such every run

State these in the coverage section of the report. Silence would be read as safety.

- **Live-account reachability:** whether a permissive security group is attached to anything internet-reachable, whether an over-broad role is assumable by an untrusted principal, whether IMDSv2 is enforced on already-running instances, whether an admission controller is installed and enforcing in production, whether the cluster's CNI enforces an egress `NetworkPolicy` at all, whether a snapshot or AMI is publicly shared today, and whether account-level Block Public Access is on when the repository does not manage it.
- **That an absence sweep which returned nothing means the setting is present everywhere.** State the granularity you actually ran at and the denominator you measured: how many constructs the left-hand pattern matched, and how many of them carried the setting. A count with no denominator is indistinguishable from a broken pattern. Three qualifiers belong in the same sentence, because each one turns a denominator into a wrong denominator: a denominator **in blocks is not a denominator in instances** where `for_each` or `count` is in play; a denominator of **zero** means the pattern may simply not read this repository's syntax; and item 0's helpers cover **HCL, `*.bicep` and multi-document YAML only** — a CloudFormation, SAM, ARM-JSON, CDKTF, Terraform-JSON, Pulumi or Serverless Framework stack has no absence sweep here at all, so for those the honest coverage statement is *not assessed*, not *clean*. **Bicep is covered but not fully covered, and the residual is specific**: `bicep_absent` cannot see a store declared through a `module`, a child resource nested inside its parent's braces, an instance produced by a `= [for` loop, or a value supplied from a `.bicepparam` — and the type list it takes is a list somebody wrote, so a resource type nobody named is a stack reported clean. Where any of those four applies, say *not assessed* for that resource and run the `bicep build --stdout` form in P1, which has none of the four limits.
- **Whether the deployed estate matches the committed configuration.** Drift and console edits are invisible here.
- **Whether etcd encryption is enabled**, and what the API server's audit policy actually records.
- **Whether a named scanner or policy engine gates anything**, which is cicd's finding and, at the provider level, only the provider can demonstrate.
- **That a digest-pinned base image is free of vulnerabilities.** A digest proves immutability, not safety.
- **The CIS benchmark and version assessed**, which the auditor states rather than the repository establishing.
