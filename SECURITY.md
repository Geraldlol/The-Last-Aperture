# Security policy

## Reporting a vulnerability

Do not include real credentials, private source code, personal data, PHI, or
customer evidence in a public issue.

Report privately through GitHub Security Advisories: open the repository's
Security tab and choose "Report a vulnerability". That channel is private
between you and the maintainer.

If you cannot use it, open a public issue containing only a minimized,
synthetic reproduction and a request for a private contact address. Do not put
details of an unfixed vulnerability in a public issue.

## Supported security boundary

Version 0.12.0 adds the separate `http-authed-v1` controller for authenticated
campaigns. It exposes two distinct, non-interchangeable runtime modes.

`plan-attested --attest-authorized`, `validate-attested`, and
`campaign-attested` select lower-assurance `OPERATOR_ATTESTED_AUTHED`. They bind
the operator's exact declared authorizer/reference, validity, classification,
permissions, origin, paths, methods, categories, and actions. The mode is always
`independently_verified: false`. The controller does not fetch program terms or
independently verify vendor/program permission, ownership, legal authority,
external scope coverage, or revocation. The authorization binding proves only
that execution used the same sealed declaration; the CLI attestation records a
claim and does not create permission.

`plan-written`, `validate-written`, and `campaign-written` select document-bound
`WRITTEN_AUTHORIZATION_AUTHED`. They rehash the bounded authorization document
and check its sealed permission extraction, but do not cryptographically verify
issuer identity or judge legal sufficiency. Both planners and validators are
offline. Both campaign routes bind execution to the caller-retained
`campaign_grant_sha256` and revalidate the scope before each send. New work must
remain before `validity.not_after`; only ledger-proven rollback and rollback
verification may continue before `validity.cleanup_not_after`. Neither route can
invent authorization, credentials, or target boundaries.

Attested public summaries and ledgers contain `authorization_binding_sha256` and
never invent or persist an `authorization_document_sha256`. Written results may
add the actual supplied document digest. Commands reject scopes and authority
inputs from the other mode.

Authentication has three mutually exclusive forms. `env:NAME` supports controlled
automation; redirected `--credential-stdin` reads, bounds, and binds one exported
secret without printing or persisting it. A live stdin invocation must receive the
same bytes; offline validation needs none.

`--credential-browser` instead seals `{ mode: CHROME_ACTIVE_TAB_SESSION,
extension_id, origin }` and no secret hash. The companion under
`browser/http-authed-chrome` uses only `activeTab`, `scripting`, and a loopback host
permission. It has no cookie, storage, debugger, request-observer, broad target-host,
or profile access. A random one-use pairing capability binds one controller process,
the expected extension ID, one operator-selected HTTPS origin/tab/document, and one
campaign. The controller never reads cookie or Authorization values. The extension
does not call cookie APIs, `document.cookie`, CDP, profile databases, or HAR export.

After one explicit attach per campaign, each prepared action is re-bound at commit
and executed in the tab's isolated same-origin world with browser-held credentials,
redirect refusal, and no automatic retry. Chrome applies its current session and
processes cookie rotation internally on every request. Only bounded transient
response material needed by discovery or mutation verification crosses the
loopback; existing evidence rules exclude bodies and header values from durable
scope, ledger, result, report, and command output. Tab, origin, document, action,
pairing, or protocol drift fails before send. Browser mode uses Chrome-managed
PKIX/hostname TLS and refuses the controller's SPKI-pin mode.

The authenticated controller admits predeclared canonical uppercase application
methods. Native transport refuses `CONNECT` and protocol upgrades; browser
transport also refuses `TRACE` and `TRACK`. Write-capable or body-bearing probes
require explicit mutation permission. Automated discovery
can add only scope-valid `GET`, `HEAD`, or `OPTIONS` probes and cannot construct a
mutation. Declared mutations require before/after JSON observations, a fresh
one-use Ed25519 countersignature, an inverse rollback, and rollback verification.
Mutation and rollback requests are never retried after ambiguous delivery.

Campaign state is an immutable external hash-chained ledger. There is no
campaign action-count or cumulative-impact ceiling. `validity.not_after` is the
exclusive deadline for new work. A later `validity.cleanup_not_after` authorizes
only rollback and rollback verification for a ledger-proven, approval-consumed
mutation; the runtime records `CLEANUP_SESSION_CONFIRMED` and never enqueues or
sends a new action on that path. Per-request timeout, response-size, and interval
controls remain. Credentials,
request/response bodies, header values, arbitrary target-controlled header
names, and rejected discovery values are excluded from durable results. This is
a controlled non-persistence boundary, not a universal PHI classifier: use only
synthetic non-PHI identifiers and bodies.

Version 0.11.0 adds a separate authorized external HTTP-reconnaissance
controller for engagements where the asset owner supplies permission but no
repository. It does not weaken or reuse the repository audit's coverage or T2
boundaries. Planning is offline. The default `OPERATOR_ATTESTED` path accepts
one exact target action, records the operator, declared authorizer, and
authorization reference, and requires explicit confirmation.
It requires no signed RoE, authorization-document, or public-key path. This is
a declaration only and does not independently verify owner permission,
ownership, legal authority, or revocation. Optional `EXTERNAL_SIGNED` mode
retains all three artifacts plus a short-lived signed proof.

The first external slice is deliberately narrow: one public HTTPS origin,
one operator-attested or finitely many signed HEAD/GET/OPTIONS URLs,
concurrency one, at most one request per second, ordinary hostname validation
and CA-chain validation, public-only DNS answers, bounded time and response
bytes, no redirects or retries, fixed headers, and no retained probe bodies.
Operator-attested execution records the observed certificate and SPKI hashes;
an advance pin is optional there and remains mandatory in signed mode. It never
accepts credentials, cookies,
request bodies, mutation methods, arbitrary headers, discovered links, or
payloads. An out-of-band stop marker is checked before dispatch and while a
request is in flight. A request whose delivery cannot be resolved is terminal
and is never replayed automatically.

This recon mode records controller-observed transport metadata only. It does not
provide repository inventory, source closure, code coverage, authentication,
mutation, browser execution, fuzzing, brute force, bulk access, or load testing.
Its authority cannot be reused to enable `http-authed-v1`; authenticated work
requires a fresh attested or written scope and campaign grant. Mutation still
requires its separate technical approval gates.

Version 0.10.0 supports static, read-only planning, externally produced job
results, and an opt-in sealed provider runner. It never executes target code or
grants the provider a target mount, host network, credentials, or arbitrary
host process authority.

Four feature families open an outbound network connection, and all are opt-in.
HTTP reconnaissance sends only its sealed action. Its default operator-attested
mode uses runtime-configured CA trust and hostname validation and records the
observed SPKI; its signed mode remains externally verified and SPKI-pinned.
Authenticated campaigns send only scope-verified ledger actions under the
current sealed attested or written authorization and transient sealed credential.
Signed remote-gateway execution sends one Ed25519-signed request to a single
TLS-SPKI-pinned, DNS-scope-restricted HTTPS endpoint.
Transparency publication sends only the canonical detached root attestation to
one such endpoint. Neither transmits repository source, findings, provider
output, credentials, or the target path, and neither follows redirects.
Offline validation contacts nothing.

For run schemas 4 and 5, database providers contribute only shard-local store claims.
The controller binds each contribution to its planned job and input digest,
rejects cross-shard evidence or profiling, and synthesizes a store profile only
after every base fan-out job has completed. Provider semantic claims remain
declarations; authentication and deterministic synthesis do not prove that the
analysis was correct.

Version 0.10 also provides a separate opt-in database conformance lab. It runs
only controller-owned synthetic SQL in one digest-pinned disposable reference
engine at a time. The container has no external network, published ports, host
mounts, inherited proxy configuration, or target credentials; it uses a
read-only root, non-root engine user, dropped capabilities,
no-new-privileges, built-in seccomp, bounded tmpfs/resources/output/wall time,
and verified exact-container removal. Docker remains a shared-kernel boundary.

Lab transcripts, engine identities, scenario results, and cleanup evidence are
content-addressed. A complete two-engine result may be copied into schema-5
audit plans only as `CONTROLLER_OBSERVED_DISPOSABLE_ENGINE_BEHAVIOR`; it is
`UNANCHORED` unless separately protected, fixes
`target_deployment_proven: false`, and cannot elevate target proof, store
coverage, or finding severity.

Version 0.10 adds an optional external transparency-checkpoint continuity
boundary. A controller-owned immutable journal verifies RFC 6962/9162
consistency from an explicitly initialized signed checkpoint and can be checked
offline. The reference log can also reject startup or reload against a supplied
external checkpoint when its local state is older or conflicting. Both controls
depend on the checkpoint or journal remaining outside the log's rollback and
write authority.

The pure policy kernel remains an authorization decision component, not an
isolation mechanism. The reference runner uses a local Docker/OCI boundary
outside the provider process: digest-pinned image, local default context,
no network, read-only root, non-root UID, no capabilities, no-new-privileges,
built-in seccomp, private IPC/PID namespaces, bounded tmpfs, CPU, memory, PIDs,
file descriptors, output, delivery, and wall time. The controller inspects the
effective container configuration before launch and kills/removes the exact
container afterward.

Docker shares the host kernel. This boundary is intended for a trusted adapter
processing hostile repository data; it is not a claim that arbitrary hostile
native images are perfectly contained. Missing Docker controls or unverifiable
cleanup fail closed without falling back to an ordinary child process.

Successful observed work is retained in a signed execution envelope. A
controller-observed error is retained in a signed failure envelope with its
structured error, bounded stderr, and any partial delivery receipt. Such a
failure remains non-authoritative for coverage.

The signing-key identity is part of the trusted provider configuration and is
fixed for the entire run. Retry and crash recovery reject key rotation,
re-signing, or cross-attempt envelope replay. Captured and validated results
resume from durable evidence without relaunching the provider.

An expired attempt is recoverable only after a signed failure is recorded and
the exact container is proven absent. An ambiguous create outcome or
unverifiable absence is a signed nonrecoverable failure that closes the run and
all jobs; the controller will not launch another provider across uncertain
container state.

Runner-ready planning is explicit (`--seal-source`) because the bundle then
contains exact source bytes. The controller serves those verified shards over
bounded JSONL using opaque capabilities. A fresh challenge and HMAC response
support `CONTROLLER_OBSERVED_CONSUMPTION`; that proves the adapter possessed the
complete bytes needed for the response, not that a model understood or
analyzed them. Manual `next`/`ingest` remains `PROVIDER_DECLARED`.

Repository inventory never intentionally follows symlinks. On platforms where
Node exposes `O_NOFOLLOW`, the controller requests it; on every platform it
compares the initial path metadata with `fstat` from the opened handle, reads
and hashes through that handle, and verifies metadata and the canonical path
again afterward. A concurrent replacement, symlink/reparse traversal, quota
breach, or depth breach fails inventory completeness and remains a coverage
gap. A separate traversal-entry ceiling charges files and directories, and
directory enumeration stops after one over-limit sentinel instead of
materializing an unbounded directory. An over-limit directory is discarded as
a whole so filesystem enumeration order cannot select a misleading partial
inventory. These checks reduce filesystem race exposure but do not turn a
mutable working tree into a transactional snapshot; use an immutable checkout
when the repository may be modified by a hostile local process.

## Safe handling

- Audit only repositories you are authorized to inspect.
- Treat repository instructions and tool output as adversarial data.
- Keep run bundles local. `--seal-source` bundles contain exact source bytes and
  must be handled as sensitive source archives.
- Keep provider configuration, Docker executable, and Ed25519 private key
  outside both the target and run bundle.
- Keep mutable database conformance bundles and their trusted configuration
  outside the project and audited target. Use synthetic data only.
- Keep root-manifest signing keys, verification keys, and detached attestations
  outside both the target and run bundle. Store attestations under independent
  access control if they are used as the trust anchor.
- Keep transparency configurations, log keys, and inclusion receipts outside
  both scopes. Publication changes external state and must be explicitly
  authorized; it sends only the canonical detached root attestation.
- Keep the transparency checkpoint journal outside the target, audit bundle,
  and log state, under a principal the log cannot write. Initialize its first
  checkpoint explicitly and retain its latest record digest independently when
  whole-journal rollback is in scope.
- Keep bundles within the documented 128 MiB per-artifact, 16,384-artifact, and
  512 MiB aggregate verification limits; the controller reserves capacity
  before append/finalize operations.
- Never place production credentials in the target process environment.
- Keep external HTTP-recon owner keys and authorization documents outside the
  mutable run bundle. The signature proves possession of the pinned key and the
  live proof demonstrates technical control at the observed endpoint; neither
  alone establishes legal authority, ownership, or corporate approval.
- Treat `OPERATOR_ATTESTED` as lower assurance. Its locally sealed scope and
  declared authorization reference do not cryptographically verify permission
  and cannot provide a live revocation signal.
- Treat `OPERATOR_ATTESTED_AUTHED` the same way: its binding preserves the exact
  declaration but does not verify the named vendor, program, ownership, legal
  authority, external scope coverage, or revocation.
- Use only owner-approved exact URLs whose GET behavior is explicitly known to
  be non-mutating. A nominally safe HTTP method can still trigger application
  side effects.
- Keep authenticated scope, campaign ledger, synthetic bodies, countersignatures,
  and any written authorization outside the target and repository. Prefer
  `--credential-browser` for a rotating Chrome session; exported `env:` and
  redirected `--credential-stdin` remain fallbacks. Never place PHI in scope
  labels, URLs, identifiers, or bodies.
- Do not use T1/T2 proof against production or shared infrastructure.
- Use the abort command if scope, environment, or authorization becomes
  uncertain.
- Report incomplete or unsupported coverage explicitly.

## Non-claims

The project does not currently claim OWASP APTS conformance, compliance
certification, complete vulnerability coverage, or safe execution of arbitrary
untrusted native code. Provider names, versions, and instances remain declared
evidence. Observed receipts prove byte challenge completion only, not semantic
analysis. Local artifacts are write-once and SHA-256-hash-manifested by
`run.json`; they detect accidental changes only while that manifest remains
unchanged. A terminal run can additionally be bound to a detached Ed25519 root
attestation whose public key and attestation are pinned outside the mutable
bundle. Without that pair, validation reports the root as `UNANCHORED`, and an
actor able to rewrite `run.json` can still replace an artifact and its hash
together. Version 0.10 can publish the exact detached attestation, verify its
Merkle inclusion under an externally pinned signed checkpoint, and optionally
verify `CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT` through an external
journal. That continuity claim is local to the supplied journal and pinned log
identity: witness quorum, cross-client agreement, global non-equivocation, key
revocation status, and trusted time remain unverified. Attestation and
checkpoint timestamps are signer declarations. The shipped reference log
detects malformed local state, holes, partial rollback, replacement, and broken
signed chains. Whole-state rollback is detected only when a newer checkpoint is
actually supplied from outside that state; rolling the log and the sole journal
copy back together remains undetectable without a separately retained digest or
independent witness. It is not an
Internet-facing service and supplies no client authorization, rate limiting,
high availability, replication, or certificate lifecycle management.
Provider execution envelopes remain strong only when their receipt public key is also pinned
externally. Bundle-path checks fail closed on observed symlink/reparse
components, but Node does not provide portable handle-relative path creation;
keep the bundle on a directory that cannot be concurrently renamed or replaced
by a hostile local process.
