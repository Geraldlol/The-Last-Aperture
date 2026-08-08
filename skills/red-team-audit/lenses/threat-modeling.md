---
name: threat-modeling
title: Architecture threat modeling
runs_in: fanout
activates_on:
  paths:
    - '**/ARCHITECTURE.md'
    - '**/DESIGN.md'
    - '**/THREAT_MODEL.md'
    - '**/docs/architecture/**'
    - '**/docs/adr/**/*.md'
    - '**/docs/rfc/**/*.md'
    - '**/docs/design/**/*.md'
    - '**/*.puml'
    - '**/*.drawio'
    - '**/*.mmd'
    - '**/*.bpmn'
    - '**/docker-compose*.y*ml'
    - '**/openapi.y*ml'
    - '**/openapi.json'
    - '**/asyncapi.y*ml'
    - '**/*.proto'
    - 'services/*/Dockerfile'
    - 'apps/*/Dockerfile'
    - 'packages/*/package.json'
    - '**/k8s/**/*.y*ml'
    - '**/helm/**/values.y*ml'
    - '**/manifests/**/*.y*ml'
    - '**/terraform/**/main.tf'
    - '**/*network*policy*.y*ml'
    - '**/*virtualservice*.y*ml'
    - '**/*authorizationpolicy*.y*ml'
  signals:
    - 'Markdown containing mermaid diagram blocks: ```mermaid with graph TD / flowchart / sequenceDiagram / C4Context'
    - 'PlantUML @startuml / @startdot in repo docs'
    - 'docker-compose.yml with 3 or more entries under services:'
    - '3+ top-level directories that each contain their own Dockerfile or entrypoint (multi-deployable repo)'
    - 'Kubernetes manifests with kind: Ingress, kind: NetworkPolicy, or kind: ServiceAccount'
    - 'Service mesh / workload identity: istio.io VirtualService, AuthorizationPolicy, linkerd annotations, spiffe:// IDs, SPIRE'
    - 'openapi: / asyncapi: top-level keys, or .proto files declaring service X { ... }'
    - 'Inter-service transport deps: @grpc/grpc-js, grpcio, kafkajs, confluent-kafka, pika, bullmq, celery, @aws-sdk/client-sqs, @aws-sdk/client-eventbridge'
    - 'Multi-tenancy markers: tenant_id / org_id / account_id columns, Postgres CREATE POLICY (RLS), SET app.current_tenant, per-tenant schema switching'
    - 'Identity brokers spanning components: auth0, @okta/, keycloak, next-auth, passport, oidc-client-ts, openid-client, python-social-auth'
    - 'Webhook receivers plus outbound third-party integrations in the same repo (an organizational trust boundary inside one codebase)'
    - 'Admin and end-user surfaces in one deployable: /admin routes, is_staff, role === "admin", impersonation / "login as user" helpers'
    - 'Literal strings "trust boundary", "threat model", "STRIDE", "DFD", "data flow diagram" anywhere in docs or ADRs'
    - 'User prompt supplies a diagram, topology description, or design proposal instead of code'
  evidence_classes:
    source:
      state: not-consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
owns:
  - trust-boundary-inventory
  - attacker-profile-model
  - stride-decomposition
  - attack-tree-construction
  - cross-boundary-attribution-logging
  - pivot-feasibility
  - exfiltration-path-enumeration
  - architecture-trust-design-gaps
  - threat-detectability-gap
defers:
  authz-object-level: web-and-api
  authz-function-level: web-and-api
  authentication-and-credential-flows: web-and-api
  rate-limiting-and-request-quotas: web-and-api
  tenant-isolation-enforcement: web-and-api
  injection-sql-nosql-orm: web-and-api
  cors-policy: web-and-api
  csrf: web-and-api
  xss-and-output-encoding: web-and-api
  session-and-cookie-management: web-and-api
  graphql-api-surface: web-and-api
  debug-and-admin-endpoint-exposure: web-and-api
  csprng-and-token-entropy: crypto-and-key-management
  hmac-and-constant-time-comparison: crypto-and-key-management
  jwt-jws-and-jwks-verification: crypto-and-key-management
  key-separation-derivation-and-destruction: crypto-and-key-management
  network-exposure-and-segmentation: cloud-and-iac
  iam-policy-and-privilege-scope: cloud-and-iac
  imds-hardening: cloud-and-iac
  object-storage-exposure: cloud-and-iac
  kubernetes-workload-hardening: cloud-and-iac
  action-and-workflow-ref-pinning: cicd-and-supply-chain
  artifact-signing-and-provenance-emission: cicd-and-supply-chain
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  pipeline-scanner-gating: cicd-and-supply-chain
  prompt-injection: llm-and-ai
  tool-call-authority-and-mediation: llm-and-ai
  rag-retrieval-authorization: llm-and-ai
  mobile-local-data-storage: mobile-app-security
  certificate-pinning-implementation: mobile-app-security
  deep-link-and-ipc-surface: mobile-app-security
  apex-sharing-declaration: salesforce-platform
  apex-crud-fls-enforcement: salesforce-platform
  connected-app-configuration: salesforce-platform
  flow-run-context-and-authz: salesforce-platform
  phi-access-audit-controls: hipaa-and-phi
  hipaa-policy-documentation-retention: hipaa-and-phi
  phi-severity-uplift: hipaa-and-phi
  pci-scope-and-cardholder-data: privacy-and-data-protection
  retention-lawfulness-and-deletion-completeness: privacy-and-data-protection
  personal-data-severity-uplift: privacy-and-data-protection
  pii-inventory-and-data-map: privacy-and-data-protection
frameworks:
  - stride
  - attack-trees
severity_floor: low
---

## Scope

This lens reasons about a *system*: components, the flows between them, the trust domains they sit in, and what an attacker reaches by moving between them. It is the only lens whose subject is the shape of the architecture rather than the contents of a file, and it is the only lens whose output is not naturally falsifiable — nothing in a repository can prove that a threat is absent.

That asymmetry is the whole design problem here, and it is what the anchor rule in `## Severity calibration` exists to solve. Read that section before writing a single threat. An un-anchored threat is not a finding in this lens, and a threat whose *subject* is the logic inside one unit is not this lens's finding at all — Gate 2 tests the subject of the threat, never the number of files its evidence occupies.

**Posture, not activation.** A checklist audit is the right frame for a single function or a contained feature; this frame is the right one when the bugs are not in any one place but in how the pieces fit — auth flows spanning services, a queue with an unauthenticated producer, an admin surface and a customer surface in one deployable. Activation is now mechanical (`activates_on` in the frontmatter), so do not spend output re-deciding whether to run. You are running. Decide instead how much of the system you can actually see, and say so.

### Owns

| Topic | What that means here |
|---|---|
| `trust-boundary-inventory` | Enumerating the crossings: where data or control passes between trust domains, and which artifact establishes each one. **The enumeration is this lens's; the control at any given crossing is almost always another lens's slug.** |
| `attacker-profile-model` | Which adversaries are realistic for this system, what each is defeated by, and the "the client device is attacker-controlled" premise. |
| `stride-decomposition` | Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege applied per component or crossing — including which letters are genuinely N/A and why. |
| `attack-tree-construction` | Decomposing an attacker goal into paths, with AND/OR semantics, cost propagation, and shared preconditions factored out. |
| `cross-boundary-attribution-logging` | Whether an action can be attributed to the human or service that caused it *after* it crosses a boundary — service tokens, queue hops, impersonation, batch jobs. |
| `pivot-feasibility` | Lateral movement and persistence reasoning: given a foothold at component A, what does the attacker reach at B, and what does the repository show that makes the hop cheap. |
| `exfiltration-path-enumeration` | Every route bulk data can leave by, including the ones nobody calls an API: backups, dumps, log shipping, analytics, third-party integrations, scheduled exports. |
| `architecture-trust-design-gaps` | Trust granted by position rather than by identity — "it came from the VPC", "only our frontend calls this", "the mesh handles auth" — and boundaries the design asserts but the code does not create. |
| `threat-detectability-gap` | Would the attack be noticed. Distinct from any audit-control slug: this is about whether an event is emitted at all on the path an attacker takes, not whether a compliance regime requires one. |

### Does not own

Every slug below is deferred in this lens's frontmatter. Do not raise a finding on any of them. When the architecture makes one worse, note it in the candidate's `impact` as an aggravator and hand the owning lens the file and line.

This list is long, and that is the point: **most of what a threat model touches is somebody else's finding.** A trust boundary crossing is a fact this lens records; the missing control at that crossing is a finding the owner files.

- **web-and-api** — `authz-object-level`, `authz-function-level`, `authentication-and-credential-flows`, `rate-limiting-and-request-quotas`, `tenant-isolation-enforcement`, `injection-sql-nosql-orm`, `cors-policy`, `csrf`, `xss-and-output-encoding`, `session-and-cookie-management`, `graphql-api-surface`, `debug-and-admin-endpoint-exposure`. Three of these are the ones this lens files by accident, so they are named individually:
  - **Account takeover is `authentication-and-credential-flows`.** Credential stuffing, phishing, password-reset weaknesses, session-token theft and OAuth flow flaws are all one lens's, and it is not this one. What stays here is the *attacker profile* that reaches them and the blast radius once one succeeds.
  - **Cross-tenant access is `tenant-isolation-enforcement`.** A query with no visible tenant predicate is not evidence of cross-tenant reach; scoping is frequently enforced by Postgres row-level security, a per-tenant schema or database, a pooled `SET app.current_tenant`, an ORM global scope, or per-tenant credentials. Record "tenant A → tenant B" as a boundary in the inventory and a scope assumption. Never assert the access — and equally, do not read the presence of one of those mechanisms as a clearance: a session-scoped `SET` on a pooled connection is a known cross-tenant leak unless it is `SET LOCAL` inside a transaction. Either way the grading is that lens's.
  - **Service-to-service spoofing is `authentication-and-credential-flows`.** "No authentication between microservices" is the same rule as any other missing-authentication finding, one layer down. When the mesh, ingress and deployment manifests are out of the checkout, the correct output is an explicit assumption at Info — not a Spoofing finding carrying a severity.
- **crypto-and-key-management** — `csprng-and-token-entropy`, `hmac-and-constant-time-comparison`, `jwt-jws-and-jwks-verification`, `key-separation-derivation-and-destruction`. Including share-link and capability-URL token entropy: if the defect is "this grant token is guessable", that is `csprng-and-token-entropy` and it belongs to crypto, with the file and line.
- **cloud-and-iac** — `network-exposure-and-segmentation`, `iam-policy-and-privilege-scope`, `imds-hardening`, `object-storage-exposure`, `kubernetes-workload-hardening`. A missing `NetworkPolicy`, a `0.0.0.0/0` ingress rule and a public bucket are all cloud's findings. This lens records that a crossing exists there and reasons about what the hop buys an attacker.
- **cicd-and-supply-chain** — `action-and-workflow-ref-pinning`, `artifact-signing-and-provenance-emission`, `dependency-pinning-and-lockfiles`, `pipeline-scanner-gating`. The build system is a trust domain and belongs in the inventory; every control inside it belongs to that lens.
- **llm-and-ai** — `prompt-injection`, `tool-call-authority-and-mediation`, `rag-retrieval-authorization`. Corrected boundary framing for agents is in Checklist item 1; the *controls* on those crossings are entirely that lens's.
- **mobile-app-security** — `mobile-local-data-storage`, `certificate-pinning-implementation`, `deep-link-and-ipc-surface`. This lens contributes only the premise that the device is attacker-controlled, which is an `attacker-profile-model` statement.
- **salesforce-platform** — `apex-sharing-declaration`, `apex-crud-fls-enforcement`, `connected-app-configuration`, `flow-run-context-and-authz`. A system-context Flow or a `without sharing` entry point is a privilege change at an intra-process boundary — record the boundary, file nothing.
- **hipaa-and-phi** — `phi-access-audit-controls`, `hipaa-policy-documentation-retention`, `phi-severity-uplift`. **Record-level read auditing of PHI is that lens's, not this one's.** `cross-boundary-attribution-logging` here is the narrower question of whether the actor identity survives a hop at all; whether a regulation requires the record, and any uplift that follows, is decided there.
- **privacy-and-data-protection** — `pci-scope-and-cardholder-data`, `retention-lawfulness-and-deletion-completeness`, `personal-data-severity-uplift`, `pii-inventory-and-data-map`. **The data map is privacy's.** This lens enumerates *egress paths*; the inventory of what personal data exists and where it lives is `pii-inventory-and-data-map`. When both are needed, do the boundary enumeration and cite theirs.

**Six adjacent slugs have no `defers` entry here.** They are stated so nothing is double-filed, and they are reported to the registry owner rather than resolved in this body:

- `kubernetes-rbac-and-admission` (cloud-and-iac) — a `ClusterRoleBinding` granting a workload more than it needs is cloud's finding, even when it is the reason a pivot is cheap. Cite it, do not file it.
- `control-plane-audit-logging` (cloud-and-iac) — whether CloudTrail or the equivalent is on is cloud's. `threat-detectability-gap` is about whether the *application* emits anything on the attacker's path.
- `multi-agent-trust-propagation` (llm-and-ai) — agent-to-agent trust is theirs even though it is literally a trust boundary. Put the crossing in the inventory and stop.
- `chat-exfiltration-channels` (llm-and-ai) — markdown-image and link exfiltration from a model surface is theirs. `exfiltration-path-enumeration` here is the architectural set of egress routes; when the two describe the same route, the sink-level finding is llm's and this lens keeps only the route in the inventory.
- `tls-and-certificate-validation` (crypto-and-key-management) and `resource-tls-enforcement-flags` (cloud-and-iac) — **encryption in transit at a crossing.** STRIDE's **T** letter asks whether an attacker can modify data in transit, and an unencrypted internal hop (`http://records-svc/...`, a listener with no TLS, a mesh with mTLS in permissive mode) is its canonical answer. The crossing and the plaintext hop go in the inventory with the file and line; the *control* — whether the code validates the chain, whether the load balancer or bucket enforces a TLS policy — is one of those two slugs and is cited, not filed. Without this entry the honest options at an `http://` internal call were to file in violation of Gate 3 or to drop it.

### What cannot be determined from a repository

This list is longer for this lens than for any other, because architecture is deployed rather than committed. Every item here is an **assumption**, written into the `Assumptions to confirm` output described in Checklist item 10 — never a finding, and never silently treated as safe.

- **Whether a component is actually reachable from the internet.** An `Ingress` manifest, a `ports:` mapping and a route file all describe intent. DNS, load-balancer rules, WAF placement and security groups decide the fact, and none of them are reliably in the checkout.
- **Whether the deployed topology matches the manifests.** A repository shows what someone committed. It does not show what is running, what was applied out-of-band, or what a second repository deploys into the same cluster.
- **Which principals hold which credentials at runtime.** A `secretKeyRef` names a secret; it does not tell you which humans can read it, or whether the same value is also in a laptop's `.env`.
- **Whether an emitted log line reaches anything.** `threat-detectability-gap` can establish that an event *is emitted*. Whether a SIEM ingests it, whether a rule fires, and whether anyone is paged are downstream of the repository entirely. Never write "this would be detected" — write "an event is emitted at `file:line`; whether it is alerted on was not verifiable."
- **Whether a control lives in infrastructure not in the checkout.** A service mesh, an API gateway, a VPN, an identity-aware proxy. Their absence from the repository is not evidence of their absence from the system, and their presence in a diagram is not evidence they are enforcing.
- **Organizational trust relationships.** Which third party operates which endpoint, which contracts exist, and which team owns which deployable.
- **Whether a stated architectural assumption is still true.** An ADR is dated. A comment saying "internal only" is intent, not a control. Say which one you are citing.

## Activation coverage

This lens often begins from inventory rather than a detector. `PARTIAL` therefore
means the format can seed an anchored model; it does not claim every construct in
the format was interpreted.

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| Architecture documents, ADRs, RFCs, Mermaid, PlantUML, MMD and BPMN | PARTIAL | `threat-model-input-anchors` | Text-backed participants and flows can be inventoried; there is no committed fixture pair |
| Draw.io | PARTIAL | `threat-model-input-anchors` | Inline XML can be triaged; compressed or mixed pages remain NO VERDICT |
| Compose, multi-deployable, Kubernetes and service-mesh boundaries | PARTIAL | `trust-boundary-inventory` | Transport and policy inventories exist; deployed topology still requires anchoring |
| Inter-service transport, webhook and outbound-integration signals | PARTIAL | `exfiltration-path-enumeration` | Code-derived boundary and egress inventories exist; runtime destinations and broker policy remain external |
| Multi-tenancy and identity-broker signals | PARTIAL | `trust-boundary-inventory` | Tenant and identity boundaries can be inventoried; deployed isolation and broker policy still require proof |
| Admin and end-user surface signals | PARTIAL | `architecture-trust-design-gaps` | Privilege-boundary review paths exist; route reachability and deployed guard order require anchoring |
| OpenAPI, AsyncAPI, protobuf and Terraform format inventories | NOT ASSESSED | — | Discovery or inventory only; no format-specific threat semantics |

## Checklist

Work in the order below. Item 0 and items 1–4 build the model; items 5–9 are where this lens's findings actually come from; item 10 is what you return. Item 0 is not optional preamble — it is the gate everything after it inherits.

### 0. Establish the system, and establish your anchors (`threat-model-input-anchors`)

Before any threat, produce two artifacts.

**The component and flow list.** If the user supplied a diagram, a topology description or a design proposal, that is your source and it is an explicitly stated architectural assumption — the strongest anchor available. If not, derive it from the repository and cite the file for each component.

```bash
# EVERY command in this lens ends in an explicit `.`, and the dot is load-bearing.
# Given no path argument, `rg` searches *stdin* whenever stdin is not a terminal.
# So the identical command returns a silent exit-1 zero when something pipes into
# it, and blocks waiting for input when nothing does — and a zero from this lens
# is read as "no threat". Keep the `.`, or replace it with a narrower path on
# purpose and say so in the negative-result record.
# EVERY repository traversal also carries `--hidden`: a glob does not un-prune a
# hidden directory. Do not add it to an intentional stdin-only filter or an
# explicit single-file call; neither traverses the repository.

# deployables and their edges. Compose indentation is not fixed at two spaces and
# `compose.yaml` is the Compose Specification's own default filename, so match any
# indented key under both filenames and read the level you got.
rg -n --hidden --glob 'docker-compose*.y*ml' --glob 'compose*.y*ml' '^services:|^\s{2,}[A-Za-z0-9_.-]+:' .
rg --files --hidden -g 'Dockerfile' -g 'Dockerfile.*' -g '*.Dockerfile' .

# manifests: repo-wide, not just k8s/ and manifests/. deploy/, charts/, kustomize/,
# overlays/ and root-level manifests are all real, and the policy count in item 8 is
# repo-wide — if this command is narrower, the two halves of one severity row see
# two different trees.
rg -ln --hidden --glob '*.y*ml' --glob '!**/node_modules/**' 'kind: (Deployment|StatefulSet|DaemonSet|CronJob|Job|Ingress|Service|Route)' .

# declared interfaces between components
rg --files --hidden -g '*.proto' -g 'openapi.*' -g 'asyncapi.*' .
rg -ln --hidden 'graph TD|flowchart|sequenceDiagram|C4Context|@startuml' .

# standalone diagram formats named in activates_on: inventory first, then read
# the text-backed formats for participants, nodes and edges.
rg --files --hidden -g '*.puml' -g '*.mmd' -g '*.bpmn' -g '*.drawio' .
rg -n --hidden -g '*.puml' '@start(uml|dot)|\b(actor|boundary|component|container|database|node|queue)\b|[-.]+>' .
rg -n --hidden -g '*.mmd' '^(graph|flowchart|sequenceDiagram|C4Context)|\b(participant|subgraph)\b|-->|->>' .
rg -n --hidden -g '*.bpmn' '<(bpmn2?:)?(process|collaboration|participant|messageFlow|sequenceFlow)\b' .

# draw.io triage only. Inline mxGraphModel is readable XML; a diagram payload
# without it may be compressed and is NO VERDICT until decoded.
rg -n --hidden -g '*.drawio' '<diagram\b|<mxGraphModel\b' .
rg --files-without-match --hidden -g '*.drawio' '<mxGraphModel\b' .

# transports that create a crossing the call graph does not show. Polyglot on
# purpose: a Python service whose only inter-service hop is SQS via boto3 writes
# none of the Node literals.
rg -n --hidden -i '@grpc/grpc-js|\bgrpcio\b|kafkajs|confluent-kafka|aiokafka|kafka-python|@KafkaListener|\bpika\b|amqplib|bullmq|sidekiq|resque|celery|\bnats\b|@aws-sdk/client-(sqs|sns|eventbridge)|boto3\.client\(.(sqs|sns|eventbridge|kinesis)|azure-servicebus|ServiceBusClient' .

# identity brokers, then multi-tenancy markers in both spellings. `-i` does not
# bridge snake_case to camelCase, so a Java or TypeScript service reads as
# single-tenant unless both are listed — and losing the tenant crossing loses the
# scope assumption that goes with it.
rg -n --hidden 'auth0|@okta/|keycloak|next-auth|passport|oidc-client-ts|openid-client|spiffe://' .
rg -n --hidden -i 'CREATE POLICY|ROW LEVEL SECURITY|SET (LOCAL )?app\.current_tenant|set_config\(.app\.|tenant_id|tenantId|org_id|orgId|organization_id|organizationId|account_id|accountId|workspace_id|workspaceId' .

# stated architectural assumptions — quotable anchors. Claims live in comments and
# docstrings at least as often as in markdown, so this half is not restricted by
# extension.
rg -n --hidden -i 'internal[- ]only|internal use only|not (publicly )?exposed|never exposed|trusted network|private network only|behind the (gateway|mesh|vpn|proxy|firewall)|only the frontend|the mesh (handles|enforces)|gateway authenticates|assumed to be' -g '!**/node_modules/**' -g '!**/vendor/**' .

# threat-model vocabulary, documents only. `STRIDE` case-insensitively is also an
# ordinary identifier in numeric code (`kernel_size=3, stride=2`,
# `np.lib.stride_tricks`), so this half stays scoped or it floods.
rg -n --hidden -i 'trust boundary|threat model|STRIDE|data flow diagram' -g '*.md' -g '*.rst' -g '*.adoc' -g '*.txt' .

# hop 3 of the Critical row in `## Severity calibration`: the data artifact that
# names the sensitive columns. Without this the lens's only Critical has one
# mandatory artifact nothing in the body tells you how to find. `icd[-_]?10`
# covers the standard written form `ICD-10`, which `icd_?10` cannot match. Every
# separator is optional (`date_?of_?birth`) because the globs above deliberately
# reach `*.prisma` and `**/entities/**`, which are the camelCase ecosystems: a
# snake_case-only column list reads a schema declaring `dateOfBirth`,
# `cardNumber` and `claimId` as holding no sensitive data at all.
rg --files --hidden -g '**/migrations/**' -g '**/migrate/**' -g '*schema*.sql' -g 'models.py' -g '**/models/**' -g '*.prisma' -g '**/entities/**' .
rg -n --hidden -i '\b(ssn|social_?security|dob|date_?of_?birth|mrn|medical_?record|diagnosis|icd[-_]?10|npi|card_?number|pan|cvv|iban|patient|claim_?id)\b' .
```

Treat every `.drawio` file without an inline `mxGraphModel` as **NO VERDICT**, not as an empty diagram or a diagram with no boundary. Draw.io commonly stores each `<diagram>` body as base64-wrapped raw-deflate data, which a text sweep cannot inspect. Decode it with a draw.io-compatible decoder or export it to uncompressed XML before modeling it. A file-level hit on `mxGraphModel` is only a triage signal: multi-page files can mix compressed and uncompressed `<diagram>` elements, so classify every page before claiming coverage; unresolved pages are named individually in `Coverage`.

**The anchor ledger.** For every component and every flow, record which of the three anchor kinds you have: a **file path with a line**, a **config key with its value**, or an **explicitly stated architectural assumption** (a quoted sentence from a repository document, or a sentence the user wrote in the prompt). A component you inferred with none of the three is not part of the model — it is an assumption. Write it into the `Assumptions to confirm` list now, at the start, so it cannot leak into a threat later.

The reference material this lens replaces said to "infer from code" when no architecture was supplied, and said nothing about recording what the inference rested on. That single omission is the direct cause of the failure mode this lens is built to prevent: unlimited plausible speculation that no one can act on or refute.

### 1. Trust boundary inventory (`trust-boundary-inventory`)

A trust boundary is any place data or control flow passes between **trust domains** — a change of principal, of privilege, or of who operates the code. It is not a change of folder, layer or call depth.

Crossings that are genuinely boundaries, each of which must be anchored to an artifact before it enters the inventory:

- Internet → your servers
- Client application → API
- One deployable → another deployable, in either direction
- Tenant A → tenant B in a multi-tenant system
- An authenticated principal → a request scoped to a different principal (impersonation, delegation, "act on behalf of")
- Application code → database, **where the database enforces authorization the application cannot bypass** — row-level security, per-tenant roles, `SET ROLE`, or a connection role whose grants are narrower than the schema; otherwise it is one domain with the app. The last of those is the control item 6's `nomatch` rewards (`DATABASE_URL_WEB  # role app_web, grants on its own tables`), so a rule that excluded it would collapse the app and the database into one domain in precisely the repository where the shared-credential row is meant to fire
- Application code → file system, **where the paths are attacker-influenced or shared with another workload**
- Queue producer → queue consumer, where the producer set is wider than the consumer's caller set
- Build system → runtime artifact
- Production environment → non-production, **and** non-production → production. These are two different crossings with two different findings, and collapsing them loses one of them: the first is production data reaching a lower-assurance environment; the second is a lower-assurance credential or artifact reaching production. Name which direction you found.
- User input → admin interface, and admin surface → user surface in one deployable

**Two agent crossings, stated in the correct direction.** Data flowing from a model's context into a tool's output is not a trust crossing, and describing it that way inverts the control. The two real crossings are:

- **Tool output or retrieved document → model context.** This is untrusted *input* entering the context.
- **Model output → tool invocation or privileged action.** This is untrusted *control flow* leaving the context.

Record both; file neither. `prompt-injection`, `tool-call-authority-and-mediation` and `rag-retrieval-authorization` all belong to llm-and-ai.

**The intra-process test.** Two modules in one process, running as the same principal, with the same privilege and the same set of callers, are **one trust domain**. Counting every module-to-module or layer-to-layer call as a boundary yields infinite boundaries and infinite filler threats — "the service layer trusts the controller layer" is the canonical example, and it is not a finding. A genuine intra-process boundary requires a privilege or principal change: a sandbox, a deserializer, a plugin host, a template engine or `eval`, a sudo or impersonation hop, or a Salesforce class that switches sharing or execution context. (A queue consumer whose producer is unauthenticated is a real boundary but an *inter*-process one — it is already in the crossing list above and does not need this test.)

```detector
match: |
  @celery_app.task
  def apply_bulk_update(payload: dict):
      # producer is anything that can reach redis; envelope is unsigned
      Patient.objects.filter(id__in=payload["ids"]).update(**payload["fields"])
nomatch: |
  @celery_app.task
  def apply_bulk_update(envelope: str):
      payload = verify_envelope(envelope, key=QUEUE_SIGNING_KEY)
      allowed = {"status", "assigned_to"}
      Patient.objects.filter(id__in=payload["ids"]).update(
          **{k: v for k, v in payload["fields"].items() if k in allowed})
```

**Re-validation at a crossing, stated without the absolute.** Data crossing a boundary should be re-validated, and the common bug is real: code validates at the API edge, passes the value inward through several layers that trust the outer check, and then someone adds a second entry point that does not validate. The defense is to validate at every boundary and at least once at the most sensitive operation.

The absolute form — "every time data crosses a trust boundary it must be re-validated" — is wrong often enough to matter, and it is the sentence that produces this lens's most common false positive. Parse-don't-validate is *stronger* than re-validation: when the inner function receives a Pydantic model, a Zod-parsed object, a branded `UserId`, a Rust newtype or a value object whose constructor is the validator, the type cannot exist in an invalid state and a second check is dead code. The finding exists only when you can name a second construction path that bypasses the parser.

```detector
match: |
  class PatientRef(BaseModel):
      id: UUID
      tenant_id: UUID

  def from_row(row) -> PatientRef:
      return PatientRef.model_construct(id=row[0], tenant_id=row[1])
nomatch: |
  class PatientRef(BaseModel):
      id: UUID
      tenant_id: UUID

  def from_row(row) -> PatientRef:
      return PatientRef(id=row[0], tenant_id=row[1])
```

Bypass paths worth grepping for by name: `model_construct`, `construct(`, `.copy(update=` and its Pydantic v2 spelling `.model_copy(update=` — the literal for v1 cannot match v2, and v2 is what new code writes — a raw `dict` cast, `unsafe`, a deserializer (`pickle.loads`, `JSON.parse` into a typed slot with no schema call, `Marshal.load`), an ORM row hydrated directly, and a test factory imported into production code.

**Output of this item:** a table of crossings, each with its anchor and its owning lens for the control. Nothing here is a finding on its own.

### 2. Attacker profiles (`attacker-profile-model`)

Tailor the model to the adversaries this system realistically faces. Each profile below carries a **Defeated by** list — the controls that stop it. (The material this replaces labelled that field "Defends against", whose grammatical subject is the attacker, so every line asserted that the attacker defends against your controls. In a brief handed to an autonomous auditor that field *is* the mitigation list, and reading it backwards inverts the recommendation.)

**Opportunistic / mass scanner.** Untargeted, sweeping address space for known CVEs and default credentials. Low sophistication, high volume.
*Defeated by:* current dependencies and base images, no unnecessary services exposed, no default credentials, no debug surface in production.

**Authenticated insider abuse.** An existing user or employee exceeding their permissions. Medium sophistication, knows the system, and is inside every network control you have.
*Defeated by:* authorization enforced at the data layer rather than the UI, least privilege on the roles that exist, and attribution logging that survives the hop — which is `cross-boundary-attribution-logging` and is this lens's to check.

**Targeted external attacker.** Wants this system's data or access specifically, will chain bugs, will phish staff, will spend weeks. Medium-high sophistication.
*Defeated by:* defense in depth, least privilege, phishing-resistant MFA on every production path, short credential lifetimes, and detection that fires on the second hop when the first was missed.

**Supply chain attacker.** Compromises a dependency, an action, a build tool or a vendor. High sophistication, rarely aimed at you specifically. All controls belong to cicd-and-supply-chain.
*Defeated by:* pinning and lockfiles, a quarantine window on new versions, build-environment isolation, and verifying what actually ships rather than who signed it.

**Compromised employee endpoint.** Code execution on a developer or administrator laptop. Medium-high sophistication.
*Defeated by:* short-lived credentials, hardware-backed MFA on production access, no long-lived cloud keys on disk, and an admin token scope small enough that the endpoint is not a control-plane takeover.

**Well-resourced targeted adversary (including state-level).** Model this only when the system's own documentation, regulatory posture or user prompt puts it in scope. The reason is not that such an attacker is harmless — it is that **the profile adds no distinct *in-repo* checks.** Every control that matters against it that a repository can show is already listed above, so a separate profile inflates the model without changing a single finding. Do not write "out of scope, not worth defending against": for a behavioral-health, healthcare or infrastructure codebase that sentence is both wrong and quotable.

**The device premise.** For any client the user controls — browser, mobile app, desktop app, CLI, a partner's server — the correct premise is that the client is attacker-controlled: every value it sends is chosen by the attacker, every check it performs can be removed, and every secret it holds is readable. This is a premise, not a finding. The findings it implies (`client-trusted-business-rules`, `secrets-in-browser-bundle`, `secrets-in-mobile-binary`) belong to web-and-api and mobile-app-security.

### 3. STRIDE decomposition (`stride-decomposition`)

For each component and each crossing in the inventory, ask which of the six apply. For every "yes", state how, what the impact is, and what is missing. For every "no", mark it **N/A with a one-line reason** — that is a complete threat model, not an incomplete one. The method does not require one threat per letter per component, and forcing a full matrix produces findings whose only justification is the shape of the acronym.

- **Spoofing** — can an attacker pretend to be another user, service or host?
- **Tampering** — can an attacker modify data in transit, at rest, or in a token they hold? Where the answer is a plaintext internal hop, the crossing is recorded here and the control is cited: `tls-and-certificate-validation` or `resource-tls-enforcement-flags`, per the adjacent-slug list in `## Scope`.
- **Repudiation** — can an actor deny having performed an action, because nothing attributable was recorded?
- **Information disclosure** — can an attacker read data they should not?
- **Denial of service** — can an attacker make the system unavailable?
- **Elevation of privilege** — can a low-privilege actor obtain higher privilege?

**Worked example, with T and E distinguished.** Take a "share document by link" feature. The version of this example that ships in most threat-modeling material emits the same threat twice — once under Tampering as "can the link be modified to grant broader access" and again under Elevation as "can a viewer link be modified to grant editor" — which demonstrates the exact duplicate-finding failure this corpus exists to eliminate.

- **S** — Can the link be forged rather than obtained? Depends on token entropy and whether the payload is signed. → the entropy half is `csprng-and-token-entropy`, crypto-and-key-management's.
- **T** — *Integrity of the capability token itself*: is the payload unsigned or malleable, can it be truncated, can a duplicate parameter be injected into the redeem handler (`?perm=view&perm=edit`)?
- **R** — If a document leaks through a shared link, is there a record of who redeemed it, and does that record survive the anonymous-to-session transition? → **this one is this lens's**, under `cross-boundary-attribution-logging`.
- **I** — Can the existence of a document be inferred from the URL space, or from a differing response to a valid-but-unauthorized identifier?
- **D** — Can link generation be driven to exhaust a bounded resource? Be specific about which resource; "storage" is rarely the right answer for a row of token metadata, and request-count limits are `rate-limiting-and-request-quotas`, web-and-api's.
- **E** — *The authorization consequence, reached by any means*: does the redeem endpoint derive the grant from a client-supplied role, or do viewer and editor share a code path with the level chosen by an input?

**The rule that stops the duplicate: if the only path to E is through T, report one threat.** Two threats require two independent paths.

```detector
match: |
  const url = `${BASE}/s/${doc.id}?token=${share.token}&perm=${role}`
  // redeem handler
  const perm = req.query.perm
  if (perm === 'edit') grantEditor(session, doc)
nomatch: |
  const url = `${BASE}/s/${share.token}`
  // redeem handler
  const share = await Shares.findByToken(req.params.token)
  if (share.role === 'edit') grantEditor(session, share.doc)
```

Note where that detector's finding goes. Its subject is the redeem handler's own authorization logic — whether *this* handler derives the grant from a client-supplied value — so under Gate 2 in `## Severity calibration` it is **not a threat model finding**; it is handed to web-and-api as `authz-object-level` with the file and line. Contrast the middleware in Checklist item 8, which is also one function in one file and *does* stay here, because its subject is which callers are trusted and on what basis. What stays here from the share-link case is the boundary statement and the R answer.

### 4. Attack trees (`attack-tree-construction`)

Decompose an attacker goal into paths. **Label every internal node `[AND]` or `[OR]`.** A tree without those labels cannot be evaluated, because the feasibility instruction is different for each and the two are drawn with identical glyphs.

```
Goal: exfiltrate patient records from the primary database          [OR]
├── Path 1: Direct database access                                  [AND]
│   ├── Obtain database credentials                                 [OR]
│   │   ├── From a committed config file
│   │   ├── From the app server's environment (requires: app server compromise)
│   │   └── From git history
│   └── Reach the database on the network                           [OR]
│       ├── Database is publicly reachable
│       └── Pivot from the app server (requires: app server compromise)
├── Path 2: Application layer                                       [OR]
│   ├── Injection on any endpoint reaching the records table
│   ├── Object-level authorization gap enumerated over identifiers
│   ├── A bulk-export endpoint with a weaker check than the item endpoint
│   └── Account takeover, then in-product data view
└── Path 3: Supply chain                                            [OR]
    ├── Backdoored dependency
    ├── Compromised build pipeline injecting code
    └── Compromised administrator endpoint
```

**Cost propagation, which is the part that makes the tree worth drawing:**

- An **OR** node is as feasible as its *cheapest* child.
- An **AND** node is as hard as its *hardest* child.
- **The highest-leverage mitigation is the cheapest cut on an AND node**, because defending *either* child kills the whole subtree. This is why the labels are mandatory: "for each leaf, evaluate feasibility and ask whether it is defended" is straightforwardly wrong on an AND node, where you do not need to defend every leaf.
- **Factor out shared preconditions before you price an AND node.** In the tree above, "From the app server's environment" and "Pivot from the app server" are two children of two different subtrees under one AND — and both are satisfied by the single event *app server compromise*. An AND node whose children collapse to one precondition is a **single-event compromise wearing a conjunction's clothes**, and pricing it as a conjunction overstates the attacker's cost and under-rates the finding. Annotate every leaf with the precondition it requires, then check for repeats across the AND's branches before concluding anything is hard.

**Leaves are not findings.** "Compromised administrator endpoint", "compromised CI pipeline", "phish staff" are *preconditions* — they are not defects in the reviewed system, no in-repo patch exists for the precondition **itself**, and filing them with severities inflates the count and buries the real findings. The qualifier matters: an in-repo artifact that makes the precondition *cheaper* is a finding in its own right, and for "compromised CI pipeline" there are several — unpinned action refs, a missing environment protection rule, a long-lived cloud key where OIDC would do. Those belong to cicd-and-supply-chain, and the leaf is not licence to skip them.

The correct output for a precondition leaf is a **blast-radius statement**: given that the precondition holds, what does the attacker reach, and **which in-repo control is the fixable finding**? Credential lifetime, admin token scope, the absence of a second factor on the production path, a service account that is also the deploy account. That control, cited to a file or config key, is the finding. The leaf is the setup.

Do not attach a percentage to any of this. Claims of the form "most of the effort is on one path while another is wide open" are a real and useful observation about trees; a number attached to them is invented.

### 5. Cross-boundary attribution (`cross-boundary-attribution-logging`)

The question: after an action crosses a boundary, can it still be attributed to the human or service that caused it?

Three shapes cover nearly every instance.

**Service-token collapse.** The inbound request is authenticated as a user; the outbound internal call carries only a service credential. Downstream, every action looks like the service. The record on the far side answers "which service" and cannot answer "which user".

```detector
match: |
  def fetch_chart(patient_id: str) -> dict:
      return httpx.get(
          f"{RECORDS_SVC}/charts/{patient_id}",
          headers={"authorization": f"Bearer {SERVICE_TOKEN}"},
      ).json()
nomatch: |
  def fetch_chart(patient_id: str, actor: Actor, trace: str) -> dict:
      return httpx.get(
          f"{RECORDS_SVC}/charts/{patient_id}",
          headers={
              "authorization": f"Bearer {SERVICE_TOKEN}",
              "x-actor-id": actor.id,
              "x-actor-scope": actor.scope,
              "traceparent": trace,
          },
      ).json()
```

**Impersonation with no dual record.** An admin "log in as user" helper that overwrites the session subject and keeps no record of the operator. Every subsequent action is attributed to the victim.

```detector
match: |
  def impersonate(admin: User, target_id: str):
      session["user_id"] = target_id
      return redirect("/")
nomatch: |
  def impersonate(admin: User, target_id: str):
      session["user_id"] = target_id
      session["impersonator_id"] = admin.id
      audit.emit("session.impersonate", actor=admin.id, subject=target_id)
      return redirect("/")
```

**Asynchronous hops.** A queue message, a scheduled job or a batch import that carries the payload but not the initiating actor or a correlation identifier. The finding is on the **producer** side, at the enqueue call: that is the last place the human is known.

```detector
match: |
  await exportQueue.add('cohort-export', {
    cohortId: req.body.cohortId,
    columns: req.body.columns,
  })
  res.status(202).json({ queued: true })
nomatch: |
  await exportQueue.add('cohort-export', {
    cohortId: req.body.cohortId,
    columns: req.body.columns,
    actorId: req.user.id,
    actorScope: req.user.scope,
    traceparent: req.headers.traceparent,
  })
  res.status(202).json({ queued: true })
```

Grep for the propagation, and grep for its **absence** — the dangerous default has no literal at all:

**The two searches are not one search, and conflating them is how this item files High against correct code.** An actor identity and a correlation identifier answer different questions, and the severity table grades them differently: no actor is the **High** row, an actor recoverable downstream through a propagated correlation identifier is the **Medium** carve-out. A hit on `requestId` alone does not establish that the actor survives the hop. Both commands carry `-i` and both spellings of every token, because `-i` does not bridge `actor_id` to `actorId` — and `actorId` is the identifier this item's own `nomatch` above writes.

```bash
# actor identity across the hop — the half the High row rests on. Its *zero* is
# the finding, so it needs the positive control in `## Severity calibration`
# before that zero counts as evidence about the code.
rg -n --hidden -i 'actor_id|actorId|actor_scope|actorScope|on_behalf_of|onBehalfOf|x-actor-|impersonator_id|impersonatorId|acting_user|actingUser' .

# correlation identifier only — this is the Medium carve-out, not a clearance
rg -n --hidden -i 'traceparent|tracestate|x-request-id|request_id|requestId|correlation_id|correlationId|causation_id|causationId|trace_id|traceId' .

# queue/job entry points that take a payload and nothing identifying. `@celery_app`
# is one project's variable name; standalone Celery projects overwhelmingly write
# `@app.task`, so the decorator is matched by shape. `.process(` was dropped: it
# matched `child_process` and every `.process(` in the tree. Sidekiq renamed
# `Sidekiq::Worker` to `Sidekiq::Job` and new code writes the latter, so both.
rg -n --hidden --glob '!**/test/**' --glob '!**/tests/**' --glob '!**/spec/**' --glob '!**/specs/**' --glob '!**/__tests__/**' '@\w+\.task\b|@shared_task\b|@task\(|new Worker\(|@Processor\(|kind: CronJob|Sidekiq::(Worker|Job)|ActiveJob::Base|@KafkaListener|def perform\b' .

# impersonation helpers
rg -n --hidden -i 'impersonat|login_as|log_in_as|become_user|su_user|switch_user|assume_identity' .
```

Sequence to follow for each: find the entry point where the human is known, follow the value inward, and name the **first** call after which the actor identity no longer exists. That call site is the finding's `location`.

**Boundary with hipaa-and-phi, restated because it is easy to cross:** whether a *regulation* requires a record-level read audit, and any severity uplift for PHI, are `phi-access-audit-controls` and `phi-severity-uplift`. This item establishes only whether the identity survives the hop.

### 6. Pivot feasibility (`pivot-feasibility`)

Given a foothold at one component, what does the attacker reach next, and what does the repository show that makes the hop cheap?

Anchor each hop to an artifact. The hops that show up in real repositories:

- **A credential in the reachable component that authorizes the next one.** `secretKeyRef`, an `environment:` block in compose, a `.env.example` naming a production-shaped variable, a mounted secret volume, a static token in a config map.
- **One credential shared across trust zones.** The same `DATABASE_URL`, the same service account, the same API key in two service definitions that are not in the same zone. Grep for the *value's name repeated*, not for a vulnerability literal — a shared credential writes no string a scanner recognizes, and the repetition is the whole evidence.
- **A workload whose identity is stronger than its exposure.** An internet-facing deployable bound to a cluster-wide or account-wide role.
- **A build system that can write to production.** A workflow with deploy credentials and a trigger reachable by a fork or a low-privilege actor.

The shared-credential hop, which is the one with no literal of its own. One variable name appears in an internet-facing service and in one that is not, which is the **High** condition in `## Severity calibration`; in the `nomatch` the two zones hold separate roles and the repetition is gone:

```detector
match: |
  services:
    web:                        # edge zone: published port
      build: ./web
      ports: ["443:8443"]
      environment:
        DATABASE_URL: ${DATABASE_URL_ADMIN}
      networks: [edge, data]
    billing-admin:              # back-office zone, no published port
      build: ./billing-admin
      environment:
        DATABASE_URL: ${DATABASE_URL_ADMIN}
      networks: [data]
nomatch: |
  services:
    web:
      build: ./web
      ports: ["443:8443"]
      environment:
        DATABASE_URL: ${DATABASE_URL_WEB}      # role app_web, grants on its own tables
      networks: [edge, data]
    billing-admin:
      build: ./billing-admin
      environment:
        DATABASE_URL: ${DATABASE_URL_BILLING}  # role app_billing, separate grant
      networks: [data]
```

The workload-identity hop, where the RBAC grant itself is cloud-and-iac's finding and the composite is this lens's:

```detector
match: |
  apiVersion: apps/v1
  kind: Deployment
  metadata: { name: web, namespace: prod }
  spec:
    template:
      spec:
        serviceAccountName: web
        containers: [{ name: web, image: ghcr.io/example/web:1.4.2 }]
  ---
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRoleBinding
  metadata: { name: web-admin }
  roleRef: { kind: ClusterRole, name: cluster-admin, apiGroup: rbac.authorization.k8s.io }
  subjects: [{ kind: ServiceAccount, name: web, namespace: prod }]
nomatch: |
  apiVersion: apps/v1
  kind: Deployment
  metadata: { name: web, namespace: prod }
  spec:
    template:
      spec:
        serviceAccountName: web
        automountServiceAccountToken: false
        containers: [{ name: web, image: ghcr.io/example/web:1.4.2 }]
  ---
  apiVersion: rbac.authorization.k8s.io/v1
  kind: Role
  metadata: { name: web-config-read, namespace: prod }
  rules:
    - apiGroups: [""]
      resources: ["configmaps"]
      resourceNames: ["web-runtime"]
      verbs: ["get"]
```

The RBAC grant in that match is **cloud-and-iac's finding** (`kubernetes-rbac-and-admission`). What this lens files is the composite: the internet-facing surface and the control plane are one trust zone, so a single application-layer bug is a cluster takeover with no second step. Cite the RBAC finding, do not restate it as your own.

**Boundary with attack-chaining.** That lens is a triage lens: it composes *proven* findings by `candidate_id` after fan-out. This item reasons about feasibility from architecture, before anything is proven. Emit the pivot finding with `component_finding_ids` empty and let triage merge. **Never pre-elevate a severity on the strength of a chain you constructed here** — chain elevation is attack-chaining's, and doing it in both places double-counts the same path.

**ATT&CK annotation.** See item 9.

### 7. Exfiltration path enumeration (`exfiltration-path-enumeration`)

Enumerate every route by which bulk data can leave, including the routes nobody calls an API. The categories, each with what to grep:

| Route | Establish it from |
|---|---|
| Database dump or replica | `pg_dump`, `mysqldump`, `mongodump`, `COPY .* TO`, `SELECT .* INTO OUTFILE`, a replica or read-only endpoint in IaC |
| Scheduled export job | `kind: CronJob`, `schedule:` in a workflow, `celery beat`, a `cron` entry, a queue consumer that writes outward |
| Backups and their destination | backup tooling config, a bucket or SFTP host literal, retention settings |
| Log and telemetry shipping | a log forwarder config, an APM or error-reporting DSN, a `transport` or `endpoint` setting |
| Third-party integrations | outbound HTTP clients with a host literal, webhook *senders*, analytics SDK initialization |
| Out-of-band channels | outbound email, DNS-based lookups on attacker-influenced names, a file drop into shared storage |
| Side channels | differing error text, differing response size or status for authorized vs. unauthorized identifiers, timing |

```detector
match: |
  # .github/workflows/nightly-export.yml
  on:
    schedule: [{ cron: "0 3 * * *" }]
  jobs:
    export:
      runs-on: ubuntu-latest
      steps:
        - run: |
            pg_dump "$DATABASE_URL" | gzip > dump.sql.gz
            curl -T dump.sql.gz "https://reports.partner.example/upload"
nomatch: |
  # .github/workflows/nightly-export.yml
  on:
    schedule: [{ cron: "0 3 * * *" }]
  jobs:
    export:
      runs-on: ubuntu-latest
      steps:
        - run: |
            pg_dump --schema-only "$DATABASE_URL" | gzip > schema.sql.gz
            aws s3 cp schema.sql.gz "s3://$INTERNAL_BUCKET/exports/"
```

For each route, record three things: **what data volume it can move**, **who can trigger it**, and **whether it is in the destination set the system otherwise contacts**. A route that moves one record on a user action is a different finding class from one that moves the table on a schedule.

Two boundaries: the CI-secret handling in that workflow is cicd-and-supply-chain's, and the bucket's configuration is cloud-and-iac's. The egress route itself — a scheduled full-table dump leaving to a host the application never otherwise contacts — is this lens's.

### 8. Architecture trust design gaps (`architecture-trust-design-gaps`)

The single highest-yield item in this lens, because the defect is a *design decision* and therefore genuinely has no other owner.

**Trust derived from network position.** The receiving side grants identity or authority because of where the request appeared to come from, rather than because of what it proved. **Every variant of this is this lens's subject** — the question is which side is trusted and on what basis, which is a relationship, so Gate 2 keeps it here even though the evidence below is one middleware function in one file. It becomes a *finding* only once Gate 1 anchors it, and the severity table's **Medium** carve-out applies where the position check layers over a real identity check rather than replacing one:

```detector
match: |
  @app.middleware("http")
  async def internal_only(request: Request, call_next):
      if request.client.host.startswith("10."):
          request.state.user = SERVICE_ACCOUNT
      return await call_next(request)
nomatch: |
  @app.middleware("http")
  async def internal_only(request: Request, call_next):
      request.state.user = verify_workload_token(request.headers.get("authorization"))
      return await call_next(request)
```

Grep for the shapes, then read what you matched — several of these strings also appear in code that is *rejecting* the position-based signal, which is the opposite finding:

```bash
# accessors. `-i` is mandatory: Node lowercases every header name, so
# `req.headers['x-forwarded-for']` is the canonical Express spelling and the
# capitalized header literal never appears. Django's is `HTTP_X_FORWARDED_FOR`.
# Two ecosystems spell the accessor with neither `addr` nor `ip` alone: Rails is
# `request.remote_ip` and ASP.NET Core is `HttpContext.Connection.RemoteIpAddress`,
# so a sweep built from `remote_addr` and `req.ip` is silent on both.
rg -n --hidden -i 'request\.client\.host|remote_addr|remoteaddr|remote_ip|RemoteIpAddress|getRemoteAddr\(|req\.ip\b|request\.ip\b|x-forwarded-for|x_forwarded_for|x-real-ip|x_real_ip|cf-connecting-ip|true-client-ip' .

# private-range literals, quote-agnostic. An anchor on `"` cannot match a
# single-quoted Python or JavaScript literal or an unquoted YAML list entry
# (`- 10.0.0.0/8`), and `172.1[6-9]|172.2[0-9]` misses 172.30 and 172.31 — both
# inside RFC 1918 and inside Docker's default bridge pool.
rg -n --hidden '10\.\W|10\.[0-9]{1,3}\.[0-9]|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|10\.0\.0\.0/8|172\.16\.0\.0/12|192\.168\.0\.0/16' .

rg -n --hidden -i 'X-Internal-|X-Service-|x-admin-|trusted_?proxy|is_internal|allow_?internal|internal_?only' .
```

The private-range command is deliberately loose in the direction that produces noise rather than silence — `10\.[0-9]{1,3}\.[0-9]` also matches a version string like `10.15.7`. That is the safe direction here, because a hit is a site to read and a miss is a High finding that never gets written. Read what you matched.

**Boundaries the design asserts but the code does not create.** Find the claim, then find the enforcement. A document, comment or ADR saying "this service is internal only", "the gateway authenticates every request", "the mesh enforces mTLS", or "only the frontend calls this" is a claim. The claim is at least as likely to live in a comment or a docstring as in a document, which is why the claim sweep in Checklist item 0 is not restricted by extension. Locate the artifact that enforces it — all eight kinds the command below counts, which are `NetworkPolicy`, the Gateway API's `AdminNetworkPolicy`, Cilium's `CiliumNetworkPolicy` and `CiliumClusterwideNetworkPolicy`, Calico's `GlobalNetworkPolicy`, and Istio's `AuthorizationPolicy` and `PeerAuthentication` plus Linkerd's `ServerAuthorization`; or a gateway route with an auth filter, or a listener bound to a loopback or private address — and if you cannot, the gap between the asserted boundary and the created boundary is the finding. Quote the claim, name the file it is in, and state what you searched for and did not find. **Searching only for `kind: NetworkPolicy` is how this finding gets filed against a correctly segmented cluster**, because a Cilium- or Istio-managed tree contains none.

**Grep for the absence, because the dangerous default has no literal.** A compose file with no `networks:` key puts every service on one network where any container reaches any other; a manifest tree with `Deployment` objects and zero policy objects of *any* enforcing kind is default-allow. Neither writes a string you can search for. Count the policy kinds the cluster's own CNI or mesh would use, not just the built-in one — zero `NetworkPolicy` objects in a Cilium-segmented tree is a fact about Cilium, not about segmentation.

```detector
match: |
  services:
    web:
      build: ./web
      ports: ["8080:8080"]
    worker:
      build: ./worker
    postgres:
      image: postgres:16
      environment:
        POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
nomatch: |
  services:
    web:
      build: ./web
      ports: ["8080:8080"]
      networks: [edge, data]
    worker:
      build: ./worker
      networks: [data]
    postgres:
      image: postgres:16
      networks: [data]
  networks:
    edge: {}
    data:
      internal: true
```

```bash
# list both sides: workloads declared, policies declared. Zero policies alongside
# any workload is the finding, and it has no literal of its own.
rg -c --hidden --glob '*.y*ml' 'kind: (Deployment|StatefulSet|DaemonSet)' .

# `kind: NetworkPolicy` alone reads zero on a Cilium-, Calico- or Istio-segmented
# cluster and files this row against a correctly segmented one. All of these are
# real enforcement artifacts, and the severity row already names AuthorizationPolicy
# in its own condition. Cilium's cluster-wide kind is CiliumClusterwideNetworkPolicy
# — that word order, or the literal is dead and can never fire.
rg -c --hidden --glob '*.y*ml' 'kind: (NetworkPolicy|AdminNetworkPolicy|CiliumNetworkPolicy|CiliumClusterwideNetworkPolicy|GlobalNetworkPolicy|AuthorizationPolicy|PeerAuthentication|ServerAuthorization)' .

# compose files that declare services and no networks key at all. `compose.yaml` is
# the Compose Specification's default filename; omit it and the whole sweep is blind
# on a V2 repository.
rg --files-without-match --hidden '^networks:' --glob 'docker-compose*.y*ml' --glob 'compose*.y*ml' .
```

**Read those two outputs as lists, never as a subtraction, and never as a pass.** Both directions of the arithmetic are wrong:

- **A non-zero policy count clears nothing.** A `NetworkPolicy` is namespaced and selects pods by label, so its existence *somewhere in the tree* says nothing about whether it selects the workload you are reasoning about. Two policies aimed at the same front-end balance the count over a third workload that nothing selects at all — and a policy whose `podSelector` is empty with an ingress rule carrying no `from` selector is an explicit allow-all, which counts as enforcement and enforces nothing. Only **zero policies of every kind** is the mechanical finding; above zero you are reading namespaces and selectors by hand, workload by workload, or you are not making the claim.
- **A matching line is not an instance.** `rg -c` counts lines: several documents in one `---`-separated file count several times, a Helm template inside a `range` counts once and renders many, and a Kustomize base plus its overlays count the same workload twice. So the two numbers can diverge on a correctly segmented tree and match on a broken one. Use them to find the files, then read the files.

**The `NetworkPolicy` absence itself is cloud-and-iac's finding** (`network-exposure-and-segmentation`). What is filed here is narrower and is not theirs: the design asserts a boundary that the deployment does not create, so a control elsewhere in the system was priced as if the boundary existed.

**Shared-fate components.** Two things the design treats as separate trust domains that share a credential, a database role, a service account, a host or a process. Naming the shared resource is the finding; the resource's own configuration belongs to its owner.

### 9. Threat detectability (`threat-detectability-gap`)

For each significant threat: on the path the attacker takes, does the system emit anything at all?

This is deliberately the weakest possible claim, because it is the only one a repository can support. **Never write that something "would be detected."** Whether an emitted event reaches a SIEM, matches a rule, or pages a human is entirely outside the checkout.

The two checks:

- **Deny paths.** An authorization failure that raises and returns without emitting an event is invisible to everything downstream. Enumeration attempts, credential stuffing and identifier walking all present as a stream of denials, and a stream of nothing is not a stream.
- **Success paths on sensitive operations.** A bulk export, a permission grant, an impersonation, a credential rotation, a configuration change. If the only record is the effect, the action cannot be reconstructed.

```detector
match: |
  if not user.can_read(record):
      raise HTTPException(status_code=403, detail="forbidden")
nomatch: |
  if not user.can_read(record):
      audit.emit(
          "access.denied",
          actor=user.id,
          object=record.id,
          boundary="api->records",
          outcome="deny",
      )
      raise HTTPException(status_code=403, detail="forbidden")
```

```bash
# denial sites, then check each for an emit in the same block. `-i` is load-bearing:
# Rails writes `head :forbidden`, Sinatra and any lowercase symbol likewise, and
# without it the sweep survives only on Go's capitalized `http.StatusForbidden`.
# ASP.NET Core's deny is the action result `Forbid()` — no status number and no
# word "denied" anywhere on the line, so it needs its own alternative.
rg -n --hidden -i -B2 '\b40[13]\b|permission.?denied|forbidden|unauthori[sz]ed|not.?authori[sz]ed|access.?denied|permission.?error|StatusForbidden|\bForbid\(' .

# what the codebase uses to emit, so you know what absence looks like. This is the
# command whose silence is most often its own rather than the code's, so it carries
# every ecosystem's real spelling and `-i`:
#   Python   logger.warning  (the canonical method; `logger.warn` is deprecated)
#   Java     log.warn( via Lombok's @Slf4j, and LOGGER.info( / .severe( —
#            lowercase and full-caps, which a Go-cased `log.Warn` cannot match
#   .NET     _logger.LogWarning( / LogInformation( — the level is inside the
#            method name, so `logger\.` followed by `warn|info` never fires
#   Go       slog.Warn, log.Warn    Node  console.error    Rails  Rails.logger
# `\blog\.` keeps the word boundary so `catalog.info` and `backlog.error` stay out.
rg -n --hidden -i 'audit\.|audit_log|logger\.(warn(ing)?|error|info|exception|critical|debug|severe)|\blog\.(warn|err|info|debug|trace|fatal|critical)|Log(Warning|Information|Error|Critical|Debug|Trace)\(|structlog|slog\.|console\.(warn|error)|Rails\.logger|Sentry|capture_message' .
```

**Run the emit sweep repo-wide before you read any silence as a finding, and this is not optional.** A codebase with zero log or audit emits *anywhere* is not a detectability gap; it is a sweep that does not speak the codebase's language. That is the positive control required by "The gates' blind spot" in `## Severity calibration`, and this is the sweep it exists for: the deny sweep above succeeds while this one fails, so you hold deny sites and no mechanism, and the row gets filed against correctly instrumented code. Once this command fires *somewhere* in the tree, its silence inside a particular deny block is evidence about that block. Until it does, the output is a blind spot, not a finding.

**ATT&CK annotation, and the only thing it is for.** The output of items 6, 7 and 9 is the only output of this skill a detection or incident-response team can consume directly, and they consume it by technique. Annotate those findings — and only those — with ATT&CK Enterprise technique identifiers, so the finding can be checked against existing detection coverage.

Three rules, all of which are load-bearing:

1. **The annotation never establishes ownership, severity or reachability.** It is a label for a downstream team. A technique identifier on a finding whose control belongs to cloud-and-iac does not move the finding here, and a technique identifier never appears in the condition that earns a severity row.
2. **Annotate only what an artifact anchors.** The anchor rule applies unchanged. Do not tag a threat `T1611` because containers exist; tag it because a manifest in the checkout requests the privilege that makes it possible.
3. **Record the matrix version you consulted in the report header.** Technique identifiers are *durable* across versions where names and sub-technique structure are not, and this lens deliberately does not pin a version rather than pin a stale one. Durable is not immutable: identifiers do get deprecated and superseded (`T1086` PowerShell became `T1059.001`; `T1064` Scripting was deprecated). If the ID you were going to cite is absent from the version you record, find its replacement — do not hand a detection team a dead identifier.

**Where the identifier goes in the record.** The candidate-finding schema has a `cwe` field and no equivalent for ATT&CK, so do not invent a field: the schema *is* the merge contract, so a key it does not define has no consumer downstream, and an annotation with no consumer is a claim nobody can see. Write it as a leading tag on `attack`, in this exact shape, so it is greppable and survives merge:

```
attack: "[ATT&CK Enterprise <version> | T1567.002 Exfiltration to Cloud Storage] <the attack path>"
```

`cwe` stays whatever the underlying weakness is, or empty. The two identifier systems answer different questions and neither substitutes for the other.

The identifier is the load-bearing half of every row: per rule 3 above, IDs are durable across matrix versions and names are not, so the names below are the ones current at the version you record, and a mismatch in a name is not licence to change the ID.

**The tactic column is a subset, not a definition.** Most techniques carry several tactics — `T1078` is Initial Access and Privilege Escalation as well as the Persistence and Defense Evasion shown; `T1098` is Privilege Escalation as well as Persistence — and each row lists the ones that fit the repository anchor beside it. So where a row's tactic is not the one you expected, **check the technique's own tactic list in the version you record; where the matrix and this table differ, the matrix wins.** The reason to care is the same in both directions: a detection team handed a tactic that does not contain the technique searches the wrong place, finds nothing, and reports coverage.

| Repository anchor | Tactic | Technique |
|---|---|---|
| An internet-reachable route or `Ingress` with a known-vulnerable handler path | Initial Access (TA0001) | T1190 Exploit Public-Facing Application |
| An unpinned action, an unpinned dependency, or an install-time script | Initial Access (TA0001) | T1195.001 Compromise Software Dependencies and Development Tools |
| A vendor or partner integration with inbound authority | Initial Access (TA0001) | T1199 Trusted Relationship |
| A credential in a committed file, a config map, or git history | Credential Access (TA0006) | T1552.001 Unsecured Credentials: Credentials In Files |
| An HTTP client reaching a link-local metadata address, or IMDS reachable from a request path | Credential Access (TA0006) | T1552.005 Unsecured Credentials: Cloud Instance Metadata API |
| A long-lived integration user, service account or cloud key with no rotation | Persistence (TA0003), Defense Evasion (TA0005) | T1078 Valid Accounts; T1078.004 Cloud Accounts |
| An OAuth token or API token accepted without binding to a caller | Defense Evasion (TA0005), Lateral Movement (TA0008) | T1550.001 Use Alternate Authentication Material: Application Access Token |
| A code path that creates users, grants roles, or inserts access records | Persistence (TA0003) | T1098 Account Manipulation; T1136 Create Account |
| A container manifest requesting host privileges, host paths or host namespaces | Privilege Escalation (TA0004) | T1611 Escape to Host |
| A workload identity that can read cluster or account inventory | Discovery (TA0007) | T1613 Container and Resource Discovery; T1526 Cloud Service Discovery |
| A component holding credentials for a second component in another trust zone | Lateral Movement (TA0008) | T1021 Remote Services; T1210 Exploitation of Remote Services |
| A bulk read path over a collaborative repository — a wiki, a document store, a ticket system, a CRM, a code host | Collection (TA0009) | T1213 Data from Information Repositories. Its sub-techniques are the collaborative products; an application's *own* records table is not one of them |
| A bulk read path over the application's own datastore | Collection (TA0009) | T1530 Data from Cloud Storage where the store is object storage or a managed cloud database; otherwise cite the parent `T1005 Data from Local System` rather than stretching `T1213` |
| A scheduled export to an external host | Exfiltration (TA0010) | T1567 Exfiltration Over Web Service; T1567.002 Exfiltration to Cloud Storage |
| An egress route on a non-application protocol — outbound SMTP, FTP, or a raw socket to a host the application never otherwise contacts | Exfiltration (TA0010) | T1048 Exfiltration Over Alternative Protocol. Cite the parent unless you have checked the sub-technique's current name in the version you record |
| Outbound DNS resolution on attacker-influenced names, or DNS used as the channel itself | **Command and Control (TA0011)** | T1071.004 Application Layer Protocol: DNS. **Not an Exfiltration-tactic technique** — a reviewer who files DNS tunnelling under TA0010 hands the detection team a tactic that does not contain it. Where the DNS channel carries the data out rather than carrying commands in, the Exfiltration mapping is a sub-technique of T1048 and the parent is the safe citation |
| A deletable or writable audit store, or a code path that disables logging | Defense Evasion (TA0005) | T1070 Indicator Removal; T1562.008 Impair Defenses: Disable or Modify Cloud Logs |

### 10. What this lens returns

Return candidate findings in the standard schema from `lenses/_schema.md`. **This lens does not carry a report format override**, and the narrative "system understanding / trust boundaries / threats / recommendations" layout that threat-modeling material conventionally uses is not an output format here — a second output contract cannot be merged or deduplicated with the rest of the lens registry. Map it onto the schema instead:

| Narrative element | Where it goes |
|---|---|
| Which of this lens's nine topics the finding is | `topic`, **required**, one of the slugs in `### Owns`. Topic ownership is the deduplication boundary, so a finding that does not carry its slug cannot be deduplicated at all — and with nine owned slugs against 42 deferred ones, the slug is this lens's entire discipline in one field |
| System understanding | The run's `Coverage` block, plus `Assumptions to confirm` and the negative-result record |
| Trust boundaries identified | The boundary inventory table, attached once to the run — not one finding per boundary |
| Attacker profile | Prefix of the finding's `attack` |
| Attack path, step by step | `attack` |
| ATT&CK technique identifier, where item 9 licenses one | Leading tag on `attack`, in the shape item 9 specifies. Never `cwe`, and never a new field |
| Where the system is vulnerable | `location` and `evidence`, quoting the actual text. **When the anchor is a sentence the user wrote in the prompt** rather than a repository artifact, `location` still needs a `file:line`: use the repository file the claim is about, at the line the claim describes, and quote the prompt sentence in `evidence`. A threat whose only anchor is a prompt sentence with no in-repo referent has no `location` and therefore no record — it belongs in `Assumptions to confirm`, not in the findings table |
| The entry point the path starts at | `reachable_from`, which is required. Name the internet-facing route, the queue producer or the scheduled trigger; `unknown` is honest but caps `effective_severity` at Medium at triage, and on a composite-pivot finding that cap silently erases hop 1. Where the path is traced end to end and one runtime fact decides whether it is live, write the schema's `contingent:<entry point>` form with `contingent_fact` and `contingent_query` — same Medium cap, but the entry point survives and the reader gets the one query that settles it |
| Mitigations missing | `impact` and `proof_plan` |
| Severity rationale | The condition from `## Severity calibration` that the finding satisfies |
| Recommendations, prioritized | Ordering falls out of `effective_severity`; concrete patches are Phase 4, not a lens output |

**Ranking.** Conventional threat-modeling practice ranks by likelihood × impact in one number. Do not do that here — it silently overwrites the pipeline's severity model. Impact alone drives `claimed_impact_severity`, which is never overwritten. Likelihood, reachability and capping enter later as `effective_severity`, at triage, where they can be seen and argued with.

**The second output: `Assumptions to confirm`.** Every threat that failed the anchor gate lands here, and this list is a required deliverable of every run, including runs that produce zero findings. One line each:

```
- <assumption> | matters because: <the threat it would become> | verify by: <the exact question, artifact or command> | if false: <the finding, and the lens that owns it>
```

An empty `Assumptions to confirm` on a system whose deployment is not in the checkout is a sign the anchor gate was not applied, not a sign the architecture is understood.

**The third output: the negative-result record.** Every sweep that returned nothing, every owned topic the run did not reach, and the five topics that have no possible proof — the exact contents are specified under "The gates' blind spot" in `## Severity calibration`. It goes in the run's `Coverage` block and it is required on every run, most of all on the runs that produced no findings.

## Severity calibration

`severity_floor: low` is presentational. It orders this lens's findings in the report; it never suppresses one.

### The anchor rule — a hard gate, applied before any severity is assigned

This lens produces findings that cannot be disproved by reading the repository. Left ungated it generates unlimited plausible speculation that nobody can act on or refute, and a report full of that is worse than no threat model, because it consumes the reviewer attention the real findings need. Three gates, in order. A threat that fails any of them is not a finding.

**Gate 1 — Anchored.** Every threat must cite at least one of:

- a **specific file**, with a line number, whose content the finding quotes;
- a **specific configuration key and its value** — `serviceAccountName: web`, `networks:` absent from `docker-compose.yml`, `schedule: "0 3 * * *"`, an environment variable name in a manifest;
- an **explicitly stated architectural assumption** — a sentence quoted from a repository document with its path, or a sentence the user wrote in the prompt.

Inference from the general shape of the stack is not an anchor. "Most systems like this have X" is not an anchor. A component you believe exists because a dependency implies it is not an anchor.

**An un-anchored threat is not a finding. It moves to `Assumptions to confirm`** with the verification step and the finding it would become. It carries no severity, no `candidate_id` and no line in the findings table. This is not a downgrade mechanism — it is a different output, and it is the honest one.

**Gate 2 — The subject is a relationship, not a unit.** The test is what the threat is *about*, not how many files its evidence occupies. If the threat's subject is the logic inside one unit — this handler's authorization check, this query's tenant predicate, this function's input validation — it is not a threat model finding. It is a defect in that unit, and it goes to the lens that owns the unit, usually web-and-api, with the file and line.

A threat whose subject is a **relationship** stays here **even when its evidence is one line in one file**: who trusts whom and on what basis, whether identity survives a hop, whether anything is emitted on a crossing, what two components share, where bulk data leaves to. The middleware in Checklist item 8 that sets a service account from a source-IP match is one function in one file and it *is* this lens's finding, because its subject is which callers are trusted and why.

**Cardinality was the earlier form of this gate and it was wrong.** "Resolves to one endpoint, handler, function or file" ejected four of the severity-carrying rows below — position-based trust, missing attribution, the detectability gap and the scheduled-export egress route — and for the first three no other lens's frontmatter will accept the handoff, so the round trip deleted the finding instead of moving it. If you find yourself rejecting a threat because its evidence is small, you are applying the wrong test.

**Gate 3 — Not another lens's control.** If what is missing is the control at a crossing rather than the shape of the crossing, the crossing goes in the inventory and the finding goes to the owner. Consult the "Does not own" list in `## Scope`; it is 42 slugs long and it is where most of the candidates go.

### The gates' blind spot, and the record that closes it

All three gates are **suppressors**: each one removes something the auditor was about to write. Nothing in them touches a threat the auditor never wrote — and in this lens that is the more expensive failure, because a threat that should have been raised and was not is indistinguishable in the report from a system that does not have it. There is no empty row, no `UNPROVEN` tag and no assumption line to notice. The anchor gate makes this lens's positives trustworthy; only the record below makes its negatives mean anything.

So the coverage block carries a **negative-result record**, and it is not optional:

- **Every sweep in `## Checklist` that returned zero matches, named, with the command as run.** A zero from `rg` is one of three things: the pattern is absent from the code, the pattern is present in a spelling the command does not cover, or **the command searched no files at all**. Only the first is evidence about the codebase; the other two are facts about the command. Separate the third mechanically — re-run the sweep with `--stats` and quote the `files searched` line. `0 files searched` is a fact about your globs; a healthy count with no match is a fact about the code. Do not rely on the exit code to make this distinction: exit 2 and *"No files were searched"* appear only when `rg` is given no path argument, and every command here is given one deliberately, so a glob that matches nothing exits 1 exactly like a real miss.
- **Every crossing in the inventory you could not anchor.** That is `Assumptions to confirm`, already required.
- **Every owned topic the run did not reach, by slug.** Nine slugs; if findings came out under three of them, name the other six and why — no artifact of that kind in the checkout, outside the assigned file list, or not attempted.
- **The five topics with no possible proof**, per `## Proof recipes`.

"No findings under `architecture-trust-design-gaps`" and "no `architecture-trust-design-gaps` sweep matched anything in the assigned file list" are different sentences. Write the one that is true, and never write the first when the second is what happened.

### The record's own blind spot: a sweep whose *zero* is the finding

The record above catches a sweep that went quiet when it should have spoken. It cannot catch the inverse, and the inverse is where this lens files High and Medium rows against correct code. Three of this lens's sweeps are **absence checks** — the emit sweep in item 9, the actor-identity sweep in item 5, and the policy count in item 8 — and for those the zero *is* the finding. Reporting "this sweep returned nothing" is then indistinguishable from reporting the finding, so the record is inert on exactly the sweeps that can manufacture a false positive.

**So an absence sweep's zero does not count until the sweep has been shown to fire somewhere.** Before you read any of those three zeros as evidence about the code, establish a positive control and write it into the record:

- **The emit sweep** — run it repo-wide. If it matches nothing anywhere, the codebase's logger has a spelling the command does not cover, and that is the answer: record the blind spot, name the languages present in the tree, and do not file `threat-detectability-gap` or the absence half of the attribution row. This is not hypothetical — the sweep was blind to Java's `log.warn(`/`LOGGER.info(` and .NET's `_logger.LogWarning(` while the deny sweep found their deny sites, so a Spring or ASP.NET Core service that emitted on every path graded as uninstrumented.
- **The actor-identity sweep** — a repo-wide zero is genuinely possible on a small service, so the control is weaker and the honest output is weaker with it: say whether *any* identifier propagation exists anywhere in the tree. If none does, the finding is that the system has no propagation convention, which is a different and larger statement than "this hop drops the actor" — write the one you can support.
- **The policy count** — zero across all eight kinds may mean the CNI in use writes a kind not among them. Name the CNI or mesh if the tree shows one, and say you could not if it does not.

A blind spot recorded is a finding someone can go get. A blind spot reported as a clean result is a finding nobody will ever look for again — and in this lens a wrong clearance is permanent, because nobody re-opens a closed item.

### The tier cap, which applies to every row below

Nearly everything this lens produces is **T0 — static reasoning with a cited code path — and is therefore capped at Medium** by the project's tier table, regardless of what any row below says.

Read the severity column as `claimed_impact_severity`: what the impact would be if the finding is real and reachable. It is never overwritten. `effective_severity` reaches High or Critical only when a T1 proof from `## Proof recipes` lands, or when triage elevates on another lens's proven finding. **Do not write a Critical `effective_severity` from architecture alone.** **Five** of this lens's nine topics have no viable proof at all — the five named under "Not provable here" in `## Proof recipes` — and their findings will be `UNPROVEN` and capped every run. Say so in the coverage block rather than letting the cap look like a judgement about the risk.

### Severity table

Every row names the artifact that establishes the condition. A condition no artifact in a checkout can satisfy would downgrade its finding silently and permanently, so if you cannot find the named artifact, the row does not apply and the threat goes to `Assumptions to confirm`.

| Finding | Claimed impact | Condition that earns it, and the artifact that establishes it |
|---|---|---|
| Composite pivot path from an internet-reachable component to a store of regulated or production data, every hop anchored | Critical | **Three artifacts, all required.** Hop 1: an exposure artifact — `kind: Ingress`, a host-published `ports:` mapping in `docker-compose*.y*ml` or `compose*.y*ml`, or a route definition in a served path. Hop 2: a credential artifact reachable at hop 1 — a `secretKeyRef`, an `environment:` entry, a mounted secret, or a service account with a binding. Hop 3: a data artifact — a migration, schema or model file naming the sensitive columns, found by the last two commands in Checklist item 0. **High** if any hop rests on an assumption rather than an artifact. **Hop 1's artifact anchors the claim, not the fact:** per `### What cannot be determined from a repository`, an `Ingress` or a `ports:` mapping describes intent, and actual reachability enters at triage through `reachable_from` — so cite the artifact here, name the route in `reachable_from`, **and write the reachability assumption itself into `Assumptions to confirm`**, because `reachable_from` by itself holds a route name and cannot hold a caveat. **Where the path is traced end to end and one named runtime fact decides whether the route is live, that caveat has a home in the record:** write the schema's `contingent:<entry point>` form, put the fact in `contingent_fact` and the query that settles it in `contingent_query`, and keep the assumption in `Assumptions to confirm` as well. The cap is Medium either way — what the form buys on this row is that hop 1's entry point survives instead of flattening to `unknown`, and the record queues ahead of the `unknown` ones a named query cannot close. The distinction is between the anchor and the fact, not between recording and not recording: an assumption about whether the route is *actually* reachable does not make the row un-anchored, so do not demote it and do not re-file the manifest as though it were a missing anchor. The manifest is the anchor; the reachability it describes is the assumption; this lens's only Critical row is the last place an unverified premise should go undisclosed. If two hops collapse to one precondition (Checklist item 4), it is a single-event compromise and is graded as one hop, not a chain. |
| Trust derived from network position at a crossing | High | The receiving side sets identity, role or authority from `request.client.host`, `remote_addr`, Rails's `remote_ip`, .NET's `RemoteIpAddress`, a lowercase `x-forwarded-for` or `x-real-ip` header read (the canonical Node spelling), `HTTP_X_FORWARDED_FOR`, `req.ip`, `RemoteAddr`, a `cf-connecting-ip`/`true-client-ip` header, a private-range literal in any quoting style, or the presence of an `X-Internal-*`-style header. Quote the conditional. **Read what you matched** — the same strings appear in code that strips or rejects the header, which is the opposite finding. **Medium** where the position check is defense in depth layered over a real identity check. |
| An asserted boundary the deployment does not create | High | Both halves required: a quoted claim with its file path ("internal only", "the gateway authenticates", "the mesh enforces mTLS") — **and the claim is as likely to be a code comment as a document, so search for it repo-wide, not only in `*.md`** — **and** a named absent enforcement artifact: no policy object of *any* enforcing kind in a tree containing `kind: Deployment` — all eight of `NetworkPolicy`, `AdminNetworkPolicy`, `CiliumNetworkPolicy`, `CiliumClusterwideNetworkPolicy`, `GlobalNetworkPolicy`, `AuthorizationPolicy`, `PeerAuthentication`, `ServerAuthorization` — or no `networks:` key in a multi-service `docker-compose*.y*ml` or `compose*.y*ml`, or no auth filter on the gateway route. State what you searched for, using the commands in Checklist item 8 — a sweep narrower than this condition files the row against a correctly segmented cluster, and this parenthetical is not the definition: the command is, and it is the one to run. **A non-zero policy count is not the other half of this row.** Only zero across all eight kinds is mechanical; above zero, item 8 says why the counts prove nothing and what you have to read instead. **Medium** where enforcement plausibly lives in infrastructure outside the checkout — and then it is also an assumption, not only a downgrade. |
| Bulk egress route to a destination the system does not otherwise contact | High | A volume artifact — `pg_dump`, `mysqldump`, `mongodump`, `COPY .* TO`, `SELECT .* INTO OUTFILE`, or a full-table read — **and** a destination literal (URL, bucket URI, SFTP host) absent from the repository's other outbound destinations. **Critical** where the route is unauthenticated or triggerable by a low-privilege actor. **Medium** where the destination is first-party and the volume is bounded. |
| Privileged cross-boundary action with no attribution record | High | A named call site after which the actor identity no longer exists, plus the absence of any emit in that block. **"No actor identity" means both spellings absent** — `actor_id` *and* `actorId`, `on_behalf_of` *and* `onBehalfOf`; a snake_case-only sweep reads a correctly instrumented TypeScript or Java service as uninstrumented and files this row against it. Establish "absence of any emit" against the codebase's own mechanism, using the emit sweep in Checklist item 9 — it must cover the ecosystem's real spelling (`logger.warning` in Python, Lombok's `log.warn(` and `LOGGER.info(` in Java, `_logger.LogWarning(` in .NET, `log.Warn`/`slog.` in Go), and it must have been shown to fire somewhere in the tree before its silence here counts. A repo-wide zero on that sweep is a blind spot, not an absence. **Critical** where the action is impersonation or a permission grant. **Medium** where the actor is recoverable downstream by a correlation identifier that is actually propagated — which is the second command in Checklist item 5, not the first. |
| Detectability gap on an attacker's path | Medium | A deny path or a sensitive success path with no event emitted, cited to the file and line, with the codebase's emit mechanism named so the absence is meaningful — and the emit sweep must cover the language's real method names (`logger.warning`, Lombok's `log.warn(`, Java's `LOGGER.info(`, .NET's `_logger.LogWarning(`/`LogInformation(`, `log.Warn`, `slog.`, `console.error`, `Rails.logger`), or the absence you found is your sweep's, not the code's. **The deny sweep succeeding is not evidence that the emit sweep is working** — that asymmetry is the trap, because it hands you deny sites and no mechanism. Run the emit sweep repo-wide first, per "The record's own blind spot" above; if it is silent everywhere, record the blind spot and do not file this row. **High** only when combined with an anchored egress route from the row above — an exfiltration path that emits nothing anywhere. Never graded on the assumption that an emitted event is or is not alerted on. |
| Two trust domains sharing a credential, role, service account or host | Medium | The shared resource named in two places, each cited. **High** where one of the two is internet-reachable and the other is not. The configuration of the resource itself belongs to its owning lens. |
| A crossing whose control belongs to another lens | — | **Not a finding here at all.** Inventory entry plus a handoff naming the owning lens, the slug, and the file and line. |
| An un-anchored threat, however plausible | — | **Not a finding.** `Assumptions to confirm`. |
| A threat whose *subject* is the logic inside one endpoint, handler or file | — | **Not a finding here.** Hand to the owning lens with the file and line. **This tests the threat's subject, not the size of its evidence** — a relationship threat anchored to a single line stays here, and the rows above it are the proof: four of them are routinely evidenced by one file. See Gate 2. |
| Attack-tree precondition leaf — compromised laptop, compromised CI, phished staff | — | **Not a finding.** Convert to a blast-radius statement, and file the in-repo control it exposes: credential lifetime, token scope, absence of a second factor on the production path. |
| STRIDE letter not addressed for a component | Info | Only as a coverage note, and only where the letter genuinely applies. An N/A with a one-line reason is complete, not incomplete. |
| No threat model document in the repository | Info | A process observation. It must never displace a finding in the ranked list, and it is not evidence that any specific threat exists. |

### Two rules that override the table

- **Never clear a threat because a control might exist somewhere you cannot see.** A mesh, a gateway, a WAF and a VPN are all plausible and none of them are established by their plausibility. The threat stays open at the lower severity with the assumption written out. An unverified control is a hypothesis, not a clearance — and in this lens, where nothing is falsifiable, a wrong clearance is permanent, because nobody re-opens a closed item.
- **Never let the anchor gate become a severity discount.** The gate moves un-anchored threats to a *different output*, not to a lower row. Writing a plausible-but-un-anchored threat into the table at Low is the failure the gate exists to prevent: it looks like a finding, it consumes the same attention, and it can never be resolved.

## Known false positives

Each entry names a pattern a competent reviewer would flag and states why it is not the finding it looks like. **None of these is a licence to drop a finding** — every entry names the narrower finding that does survive, and several name what the entry explicitly does *not* clear.

1. **"Data crosses a trust boundary without being re-validated", filed against an inner function that receives an already-parsed domain type.** A Pydantic model, a Zod-parsed object, a branded `UserId`, a Rust newtype, a value object whose constructor is the validator. Parse-don't-validate is stronger than re-validation: the type cannot exist in an invalid state, so a second check is dead code. This lens's own conventional absolute — "every time data crosses a trust boundary it must be re-validated" — is what invites the finding, and Checklist item 1 states it without the absolute for exactly that reason.
   **What survives:** name a second construction path that bypasses the parser — `model_construct`, `construct(`, `.copy(update=` or `.model_copy(update=`, a raw `dict` cast, `unsafe`, a deserializer, an ORM row hydrated directly, a test factory reused in production. Cite the path or drop the finding.
   **What this does not clear:** a boundary where the *type* is validated and the *authority* is not. A well-formed `UserId` says nothing about whether this caller may act on that user.

2. **Every module-to-module or layer-to-layer call inside one deployable counted as a trust boundary**, producing "the service layer trusts the controller layer". Boundaries are defined by trust domains and principals, not by call-stack depth or folder structure. Two modules in the same process, running as the same principal with the same privilege and the same callers, are one trust domain; splitting them yields infinite boundaries and infinite filler threats.
   **What survives:** a genuine intra-process boundary needs a privilege or principal change — a sandbox, a deserializer, a plugin host, a template engine or `eval`, a sudo or impersonation hop, or a platform construct that switches execution context. Name which one. (A queue consumer with an unauthenticated producer also survives, but as the inter-process boundary it is, not under this test.)
   **What this does not clear:** a process boundary that *looks* internal because the modules live in one repository. A monorepo containing two deployables that talk over the network has a real crossing, and folder adjacency is not evidence against it.

3. **Attack-tree leaves reported as findings** — "compromised admin laptop", "compromised CI pipeline", "phish staff" — each carrying its own severity. These are preconditions and assumptions, not defects in the reviewed system; no in-repo patch exists for them, and listing them inflates the count and buries real findings.
   **What survives:** the blast-radius statement. Given endpoint compromise, what does the attacker reach, and which in-repo control is the fixable finding — credential lifetime, admin token scope, the absence of a second factor on the production path, a deploy identity that is also the runtime identity. That control, cited to a file, is the finding.
   **What this does not clear:** an in-repo artifact that makes the precondition *cheaper*. A committed credential, a workflow triggerable by a fork, or a long-lived token is a finding in its own right and belongs to its owning lens.

4. **STRIDE completeness findings** — "Repudiation is not addressed" on a read-only public catalog, "Denial of service is not addressed" on an internal batch job behind a queue with backpressure. Not all six letters apply to every node, and the method does not require one threat per letter per component. Forcing a full matrix produces findings whose only justification is the shape of the acronym.
   **What survives:** mark inapplicable letters N/A with a one-line reason. That is a complete threat model.
   **What this does not clear:** Repudiation on any surface that performs a privileged or irreversible action. "Read-only" is a claim about the endpoint you read, not about the component.

5. **"Anyone with the link can access the document", filed against a capability-URL or signed-share-link feature.** Capability URLs are a deliberate design used by nearly every document product; the link *is* the grant, and its holder is the authorized party by construction.
   **What survives — name one of these or it is not a finding:** insufficient token entropy or a predictable generator (crypto-and-key-management's `csprng-and-token-entropy`); an enumerable identifier; permission level encoded in the URL without a signature; no expiry on data the repository shows to be regulated or sensitive — a PHI or PII column in the schema or model, a `hipaa`/`phi`/`patient` module path, a documented sensitivity label — rather than on the product happening to have documentation; or the token leaking through server access logs or link unfurling, both unconditional in a default install because each records or re-fetches the whole URL. **Analytics is the conditional one in that trio:** URL capture is configuration, and GA4 query-parameter exclusion or deliberate token stripping turns it off, so cite the analytics initialization and say whether the path or query is captured.
   **`Referer` is not unconditional, and citing it without its condition is itself the false positive.** The current browser default is `Referrer-Policy: strict-origin-when-cross-origin`, which sends only scheme, host and port off-origin, so a token in the path or query does **not** reach a third party by default. Name the condition that reopens the channel or drop this survivor: a response header, a `<meta name="referrer">` tag or a per-element `referrerpolicy` attribute explicitly setting `unsafe-url` or `no-referrer-when-downgrade`, or a non-browser client that does not implement the default — an embedded webview, an SDK, a link checker, a proxy.
   **What this does not clear, and this is the one to watch:** the *subject* of most of those survivors is the redeem handler's own logic or the token generator, not a relationship between components, so under Gate 2 they are **not this lens's findings** — they are handed to web-and-api or crypto-and-key-management with the file and line. "It is a capability URL" clears the *architecture* question. It clears nothing about the handler.

6. **Redundant enforcement flagged as inconsistency** — an authorization check in middleware *and* again in the query builder or ORM scope, or validation at both the edge and the persistence layer. That is exactly what this lens recommends, and it is the control that survives someone adding a new entry point six months later.
   **What survives:** the two checks disagreeing about the policy — different role sets, different tenant resolution, a different notion of "owner" — so one silently widens the other; or the outer check being the only one that runs for some subset of routes.
   **What this does not clear:** two checks that agree today and are maintained in two places with no shared source. That is a durability observation at Info, not an inconsistency finding, and it must not be written as one.

### Rejected candidates

Considered for the list above and deliberately excluded. Nothing here should be quietly re-added; each would have suppressed a real finding, or moved a finding into a section that cannot enforce it.

- **"No authentication between microservices" / "Spoofing: service A can be impersonated."** Deduplicated to web-and-api's `authentication-and-credential-flows` — the same rule as any missing-authentication finding, one layer down. Kept out of this lens's false-positive list because writing it here would teach an auditor to dismiss service-to-service spoofing generally, when the correct behavior is to route it. Per this lens's own guidance, when the mesh, ingress and deployment manifests are out of scope the output is an explicit assumption at Info, never a Spoofing finding carrying a severity.
- **"Tenant A can reach tenant B's data", inferred from a query with no visible tenant predicate.** Deduplicated to web-and-api's `tenant-isolation-enforcement`, which owns the enforcement mechanisms this inference ignores: Postgres row-level security, per-tenant schema or database, a pooled `SET app.current_tenant`, an ORM global scope, per-tenant credentials. This lens states it as a scope assumption instead of asserting the access.
- **"A loopback or same-pod hop counted as a trust boundary."** Tempting and partly true — containers in one Kubernetes pod share a network namespace, so a `localhost` hop between them does not traverse the node network. Rejected as a suppression rule because the conditions that make it true are exactly the ones an auditor gets wrong: it fails for `hostNetwork: true`, for a service-name hop that only *looks* like localhost, for a shared host running unrelated workloads, and for any hop where the two ends run as different principals. The durable half is already in Checklist item 1's intra-process test, where it is stated as a *privilege-change* question rather than a *network-distance* question, which is the framing that does not misfire.
- **"The repository has no `THREAT_MODEL.md`, so threat coverage is a finding."** Not a false positive — a severity question, and it is capped at Info in `## Severity calibration`. Written as a false-positive entry it would invite dismissal of the adjacent thing that *is* a finding: an architecture document that asserts a boundary the deployment does not create, which is Checklist item 8.
- **"A well-resourced or state-level adversary is not modeled."** Rejected in both directions. As a finding it is unfalsifiable and unfixable; as a false-positive entry it would license the sentence "out of scope, not worth defending against beyond basics", which is wrong for the healthcare, behavioral-health and infrastructure codebases this lens activates on. Resolved in Checklist item 2 with the accurate reason instead: the profile adds no *distinct in-repo checks*, so modeling it separately changes no finding this lens can write.
- **"Findings from this lens are inherently speculative, so cap them all at Low."** Rejected outright, and recorded here because it is the plausible-sounding rule someone will propose. A blanket cap is indistinguishable from suppression: it would flatten an anchored three-hop path to a production data store into the same row as a stylistic observation. The tier cap in `## Severity calibration` does the honest version of this — it caps `effective_severity` at Medium for T0 evidence while preserving `claimed_impact_severity`, so the impact stays visible and the missing evidence is named.
- **"An emitted log line means the attack would be detected."** Rejected as a false clearance, and it is the most dangerous one available to this lens. Whether an event reaches a SIEM, matches a rule or pages anyone is entirely outside the repository. Checklist item 9 is written to make the weak claim only: an event is emitted at this line, and whether it is alerted on was not verifiable.

## Proof recipes

Shared harness components are referenced by name and not restated here: the **registry-driven enumerator**, the **socket-layer destination recorder**, the **capturing log handler** and the **canary fixture set**. Their implementations live in `lenses/_harness.md`.

**The honest headline for this lens.** Of nine owned topics, four have a T1 proof, and five have none that is even theoretically possible. You cannot write a test that fails because an analysis is absent — there is no assertion for "this boundary is the wrong boundary" or "this attacker profile is incomplete". Architectural conformance testing checks adherence to a boundary someone already articulated; it never checks whether the boundary is the right one. And the fourth of those four is conditional: R4 reaches T1 only where the repository already states the boundary in machine-readable form, so on a repository that states it in prose, `architecture-trust-design-gaps` is T0 like the rest. Say all of this in the coverage block on every run, alongside the negative-result record required by `## Severity calibration`. Silence here reads as a clean bill of health, and this is the lens where that misreading is most expensive.

### R1 — Boundary-crossing attribution sweep (T1)

Proves `cross-boundary-attribution-logging`.

Enumerate the crossings with the **registry-driven enumerator** rather than hand-listing them: the framework's own route registry, the queue consumer map, and the scheduled-job registry. For each crossing, drive one authenticated request through it and assert that the far side received an actor identity and a correlation identifier — not that a log line exists, but that the *value* arrived.

Three details that must survive into the test:

- Attach the **capturing log handler** to the real logger rather than mocking it, so formatters and serializers run and a value dropped by a formatter is caught.
- Seed the actor with a marker from the **canary fixture set** and assert the marker's presence at the far side. Asserting that *some* actor field is non-empty passes on a hardcoded service name.
- Assert the discovered crossing count against a checked-in number, so an enumerator that silently returns zero rows cannot pass. Exemptions go in a committed allowlist with anchored patterns, never a prefix match — include a self-test that `/publications/secret` is not matched by a `/public` entry.

**Fails on:** an outbound internal call carrying only a service token; an impersonation helper that overwrites the session subject; a queue task whose payload has no actor field. **Passes on:** actor and trace propagated to the far side and observed there.

### R2 — Deny-path event assertion (T1)

Proves `threat-detectability-gap`.

The **registry-driven enumerator** returns entry points — routes and their methods, queue consumers, scheduled jobs — not denial sites, so enumerate the entry points with it and reach the denial inside each one by driving a request the authorization layer must refuse. For each, assert an event was emitted with the actor, the object and a deny outcome. The enumerator's committed-count assertion still applies, and it is what stops this recipe from passing vacuously on zero rows. Include the two controls without which the result is not evidence: a **positive control** — an allowed request that must *not* emit a deny event — and a **sensitivity control** showing the capture would have seen an event had one been emitted.

Then declare the assertion signature before the run. "It failed" is not a signature; `AssertionError: no event matching outcome=deny for actor=CANARY-7731 after 403` is.

**Fails on:** a 403 raised with no emit in the block. **Passes on:** an emit carrying actor, object and outcome.
**What it does not prove, and must be stated in the finding:** that anything downstream consumes the event.

### R3 — Egress destination-set assertion (T1)

Contributes to `exfiltration-path-enumeration`.

**The consent gate, restated.** It governs R1 and R2 as well — all three execute the project's test runner under one consent asked once for the whole audit — and it is restated here because this is the recipe that puts a network on the far side of it. Running the repository's own test suite requires **explicit consent for this audit**, asked before Phase 3 and never remembered — the right answer depends on what the repository is wired to today. Without that consent this recipe does not run and `exfiltration-path-enumeration` stays at T0. And the project **does not sandbox the run and does not pretend to**: the test command executes with the repository's own environment, so if that environment applies migrations, starts containers, emits telemetry or points at shared infrastructure, this run does all of it. The destination recorder makes the run *safer* than an unmonitored `npm test` — it fails loudly on an unexpected outbound connection — but it is disclosure, not isolation. State in the finding that the run happened and under whose consent.

Install the **socket-layer destination recorder** *first*, so an unexpected connection fails loudly instead of silently reaching the internet. Then run the repository's own test suite and the scheduled-job entry points under it, record the destination set, and assert it is a subset of a committed allowlist.

The assertion is deliberately about the *inventory*, not about any one destination: this recipe answers "what does this system talk to", which is the question item 7 asks. A specific destination being wrong is somebody else's finding — an unvalidated user-supplied URL is web-and-api's `ssrf-application-path`, a vendor without a signed agreement is hipaa-and-phi's or privacy-and-data-protection's, and a metadata-service reach is cloud-and-iac's.

**Fails on:** a scheduled export to a host absent from the allowlist; a telemetry client initialized in a code path nobody expected to be networked. **Passes on:** every observed destination present in the allowlist, with the allowlist diff reviewable.
**Coverage caveat:** this observes only destinations the test suite actually exercises. Record the unexercised entry points by name rather than letting the pass imply completeness.

### R4 — Architectural conformance test (two branches, T1 and T0, and narrower than it looks)

Contributes to `architecture-trust-design-gaps`.

**R4a (T1).** Where the repository already articulates a boundary in machine-readable form — a module-boundary configuration, an import-restriction rule set, a layered-architecture rule file — assert conformance to it *with the project's own runner*, and assert that the rule set is non-empty so a deleted rule cannot pass as compliance. Two directions plus a non-empty rule set is what makes this T1.

**R4b (T0), and it must be recorded as T0.** Where the boundary is articulated only in prose, there is no runner and no assertion — only a static claim: the sentence exists at a cited path, and the named enforcement artifact does or does not exist in the tree. That is static reasoning with a cited code path, which is **T0 and caps at Medium**. Recording `proof_tier: T1` on this branch would let the High "asserted boundary" row escape the cap on the strength of an `rg --files` result. Two branches, two tiers, never one label for both.

**R4a fails on:** an import from the edge layer directly into the persistence layer where the rule set forbids it. **Passes on:** conformance against a non-empty rule set.
**R4b fails on:** a `Deployment`-bearing manifest tree with zero policy objects of any enforcing kind — the widened count in Checklist item 8, not `kind: NetworkPolicy` alone. **Passes on:** an enforcement artifact present.
**The limit, which belongs in every finding this recipe supports:** it tests conformance to a boundary someone already articulated. It never tests whether that boundary is the right one, and it says nothing about boundaries nobody wrote down.

### Not provable here, and reported as such every run

Name these in the coverage block. Silence implies safety, and for five of nine topics in this lens there is nothing behind the silence.

- **`trust-boundary-inventory` completeness.** No test fails because a boundary was omitted. The inventory's *contents* can be checked against artifacts; its *exhaustiveness* cannot.
- **`attacker-profile-model`.** There is no oracle for "this is the realistic adversary set".
- **`stride-decomposition`.** Whether the right threats were enumerated, and whether an N/A is justified, are judgements.
- **`attack-tree-construction`.** Tree structure and cost propagation are analysis. Individual leaves may be proven by other lenses; the composition is not.
- **`pivot-feasibility`.** The composed path through a real topology cannot be executed under this project's rails, and the hops' individual controls belong to other lenses. Findings here are analytical and inherit their hops' tiers.
- **Whether an emitted event is alerted on**, anywhere.
- **Whether the deployed topology matches the manifests in the checkout.**
- **Whether a control exists in infrastructure outside the repository** — a mesh, a gateway, a WAF, an identity-aware proxy.

One recipe deliberately not claimed here: the share-link and JWT **forged-and-mutated token table**, including the token-entropy assertion frequently paired with it. Both prove `csprng-and-token-entropy` and `jwt-jws-and-jwks-verification`, which this lens defers to crypto-and-key-management. Running them here would produce a duplicate of crypto's finding under a topic this lens does not own. Cite crypto's result; do not re-prove it.
