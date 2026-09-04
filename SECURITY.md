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

**Current release status:** bounded HTTP-recon and fixed authenticated-campaign
commands are active. A `go <exact-https-url>` invocation is the operator's launch
directive for one sealed recon action. Fixed authenticated campaigns execute
only their sealed request list and use the durable campaign ledger. Generic live
adversarial/L3, bounty/OOB, provider/remote, proof, acquisition, and database
execution routes remain gated as described below.

At authenticated controller ingress, an explicit operator statement authorizing
the named target and scope is accepted as the controller's authorization fact.
The controller records and cryptographically seals it without requiring an
external RoE, ownership, or legal-proof artifact or repeated certification of
unchanged authority. It is not independent proof of the statement's legal basis;
the operator remains accountable. No statement can activate a gated transport.
Former active-controller `--attest-authorized` and
`--confirm-authorization-current` spellings are rejected rather than treated as
authority. The release-disabled acquisition prototype still documents its own
historical flags, but that public route cannot execute.

This is a command/package-interface boundary, not an in-process JavaScript
sandbox. `scripts/audit.mjs` still exports selected proof, provider, remote, and
publication kernels so trusted conformance tests can inject controlled
dependencies. Directly importing those exports is privileged maintainer code,
not a supported public API, and can bypass the CLI's early release gate. Agents
and integrations must not import or call them. A production distribution must
split them behind an enrolled controller boundary or enforce the same gate
inside a separately isolated service before it can execute untrusted work.

Every public evidence-acquisition and bounty OOB session command is likewise
disabled before caller-path, bundle, session, secret, process, or network I/O.
Public source sealing and audit evidence-bundle import are disabled before
repository/output or bundle access. Filesystem paths are possible I/O and
disclosure endpoints, not proof of offline custody.

The CLI lexically rejects direct UNC/WebDAV and Windows namespace-prefixed
device/pipe arguments, plus a stored UNC repository root. Other offline paths
are operator-trusted endpoints in this release. Symlink/junction ancestors,
mapped or remote volumes, DOS aliases, paths embedded in other JSON, and
concurrent path replacement require the future enrolled local-volume controller;
do not treat the lexical guard as filesystem attestation.

Repository generators, fixture builders, benchmark generation, residue scans,
shell-lens/Python conformance, and real-service or real-container conformance
launchers are trusted-checkout maintainer tooling, not product audit entry
points. They are outside the product CLI path/no-egress guarantees and may
follow filesystem indirection, overwrite generated files, interpret
checkout-authored commands, or invoke a selected host executable. Do not run
them with untrusted checkout state, mapped/remote paths, or an untrusted process
environment. Default `npm test` does not discover shell-lens or real-Docker
conformance. CI does not execute pull-request head code; main-ref stateful and
Docker conformance requires manual approval through the protected
`release-conformance` environment.

Version 0.12.0 adds the separate `http-authed-v1` controller for authenticated
campaigns. The authenticated operator's exact target/scope statement is its sole
authorization primitive. Planning binds the declared authorizer/reference,
validity, classification, permissions, origin, paths, methods, categories, and
actions. The controller does not fetch program terms or independently verify
vendor/program permission, ownership, legal authority, external scope coverage,
or revocation.

Optional contracts, tickets, RoE, or other governance material may be retained
as evidence, but no document, signature, issuer, or key selects a different
authority mode or unlocks more capability. Planning and validation are offline.
Campaign execution binds to the caller-retained `campaign_grant_sha256` and
revalidates the scope before each send. New work must remain before
`validity.not_after`; only ledger-proven rollback and rollback verification may
continue before `validity.cleanup_not_after`.

Public summaries and ledgers contain `authorization_binding_sha256`, which binds
the accepted operator statement and exact scope. It is a technical integrity and
replay record, not independent legal proof.

The retained authenticated-plan schema has three mutually exclusive credential
forms. `env:NAME` supports controlled
automation; redirected `--credential-stdin` reads, bounds, and binds one exported
secret without printing or persisting it. A live stdin invocation must receive the
same bytes; offline validation needs none.

`--credential-browser` seals
`{ mode: CHROME_ACTIVE_TAB_SESSION, extension_id, origin }` and starts the public
loopback bridge. The packaged companion 0.12.1 grants no host, tab, scripting, or
background permission and cannot attach; execution therefore requires a
separately supplied protocol-compatible companion. Browser dispatch enforces
the exact origin and rejects redirects, but uses the browser network stack and
does not provide native all-answer DNS validation or socket IP pinning.
Previously loaded 0.12.0 copies must be removed or explicitly reloaded and
verified as 0.12.1; updating files on disk alone does not revoke an already
registered extension worker.

The authenticated controller admits predeclared canonical uppercase application
methods. Native transport refuses `CONNECT` and protocol upgrades; browser
transport also refuses `TRACE` and `TRACK`. Write-capable or body-bearing probes
require explicit mutation permission. The retained internal discovery kernel can
derive only scope-valid `GET`, `HEAD`, or `OPTIONS` probes and cannot construct a
mutation, but public campaign commands do not expose response-derived discovery.
Declared mutations require before/after JSON observations, a one-use Ed25519
technical dispatch receipt, an inverse rollback, and rollback verification. The
receipt binds integrity, attribution, and replay state under the selected
autonomy profile; it is not renewed legal certification. In L3 it derives from
the accepted finite envelope without another operator prompt.
Mutation and rollback requests are never retried after ambiguous delivery.

Campaign state is recorded in a locally append-only, hash-chained external
ledger. Standalone active authenticated probes are not public; a one-action
test uses a campaign ledger. Across restarts, detecting rollback or
valid-prefix truncation requires the operator to retain the last trusted record
count and head digest outside that directory and supply both when reopening it;
the local chain alone cannot detect whole-ledger rollback to a valid prefix.
`campaign-stop` writes a grant/operator-bound marker which the runner consumes
as `CAMPAIGN_STOPPED` before another dispatch. The public fixed
lane admits at most 256 sealed actions and no response-derived discovery.
`validity.not_after` is the exclusive deadline for new work. A later
`validity.cleanup_not_after` authorizes
only rollback and rollback verification for a ledger-proven, receipt-consumed
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
authorization reference. The `go` invocation is the explicit operator statement
and confirmation. The controller accepts the declaration as its authorization
fact for the exact target and action, but it does not independently verify owner
permission,
ownership, legal authority, or revocation.

The first external slice is deliberately narrow: one public HTTPS origin,
one operator-statement-bound `HEAD`, `GET`, or `OPTIONS` URL,
concurrency one, at most one request per second, ordinary hostname validation
and CA-chain validation, public-only DNS answers, bounded time and response
bytes, no redirects or retries, fixed headers, and no retained probe bodies.
Operator-attested execution records the observed certificate and SPKI hashes;
an advance pin is optional. It never
accepts credentials, cookies,
request bodies, mutation methods, arbitrary headers, discovered links, or
payloads. An out-of-band stop marker is checked before dispatch and while a
request is in flight. A request whose delivery cannot be resolved is terminal
and is never replayed automatically.

This recon mode records controller-observed transport metadata only. It does not
provide repository inventory, source closure, code coverage, authentication,
mutation, browser execution, fuzzing, brute force, bulk access, or load testing.
Its authority cannot be reused to enable `http-authed-v1`; authenticated work
requires a new explicit operator statement for that route, which the controller
seals into its scope and campaign grant. Written evidence is optional. Mutation
still requires technical permit, ledger, observation, and rollback gates.

Version 0.10.0's protocol supports static, read-only planning, externally
produced job results, and a sealed provider-runner kernel. Public `run-provider`
is currently disabled before bundle/configuration access because a
caller-selected absolute runtime path is not independently authenticated and
could otherwise gain arbitrary host process authority. The intended enrolled
runner never executes target code or grants the provider a target mount, host
network, or credentials.

Four feature families model outbound network connections; availability differs
by route as described here and in the CLI help.
The HTTP-recon kernel sends only its sealed action. Its default operator-attested
mode uses runtime-configured CA trust and hostname validation, optionally checks
an operator-supplied SPKI pin, and records the observed SPKI.
The authenticated-campaign kernel sends only scope-verified ledger actions under the
current sealed operator statement and transient sealed credential.
The remote-gateway protocol can send one Ed25519-signed request to a single
TLS-SPKI-pinned, DNS-scope-restricted HTTPS endpoint, but public `run-remote` is
currently disabled before bundle/configuration access because its gateway and
outbound-data authority are not independently enrolled.
The transparency protocol sends only the canonical detached root attestation to
one such endpoint, but public `publish` is currently disabled before input/config
access until log identity is independently enrolled. Remote-gateway execution intentionally transmits the exact
sealed provider artifacts, including scoped repository source/control bytes,
and can therefore transmit secrets, personal data, or other sensitive content
present in those artifacts. Its historical `remote_static` file is technical
outbound policy, not legal proof; future use still requires the accepted operator
statement and data review. The unavailable transport remains gated.
Transparency publication does not transmit repository source,
findings, provider output, credentials, or the target path. Neither path follows
redirects. Offline validation intentionally opens no sockets, but its
operator-supplied filesystem paths can still resolve to mapped or remote-backed
storage and therefore remain trusted I/O endpoints.

For run schemas 4 and 5, database providers contribute only shard-local store claims.
The controller binds each contribution to its planned job and input digest,
rejects cross-shard evidence or profiling, and synthesizes a store profile only
after every base fan-out job has completed. Provider semantic claims remain
declarations; authentication and deterministic synthesis do not prove that the
analysis was correct.

This also applies to ordinary finding triage and proof. Provider-returned
confirmation, disproof, non-reproduction, drop, merge, severity adjustment, and
fix results are stamped as unauthenticated assertions. Markdown and SARIF render
them as `CLAIMED_*`; they cannot suppress a candidate, lower report priority, or
remove it from proof scheduling. Comparable-coverage absence is
`claimed-fixed`, never the reserved unqualified `fixed` state.

Version 0.10 also defines a separate database conformance-lab protocol. Public
lab `run` is currently disabled before argument/bundle/configuration access
because a caller-selected absolute runtime path is not authenticated Docker
identity. Lower-level real-Docker conformance is release-operator test
infrastructure only. It is outside product CLI path guarantees; the provider
test requires an explicit launcher-only sentinel so ambient Docker variables do
not activate it during ordinary test discovery. The intended container has no external network, published ports, host
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
- Treat `OPERATOR_ATTESTED` and `OPERATOR_ATTESTED_AUTHED` as controller-accepted
  operator statements whose bindings preserve exact scope, identity, and replay
  state. They do not independently verify the named vendor/program, ownership,
  legal authority, external scope coverage, or revocation.
- Use only exact URLs the operator explicitly declares authorized and whose GET
  behavior is known to
  be non-mutating. A nominally safe HTTP method can still trigger application
  side effects.
- Keep authenticated scope, campaign ledger, and synthetic bodies outside the
  target and repository. Controller-issued permits and their consumption records
  remain in the ledger. Optional governance evidence belongs outside the target
  and cannot grant authority. The packaged
  browser companion is release-disabled. A separately supplied compatible
  companion may execute only through the sealed campaign and locally
  append-only, hash-chained ledger. Cross-restart rollback/truncation detection
  requires a supplied trusted retained head. Its browser-managed DNS assurance
  is weaker than native all-answer validation and socket IP pinning. Never place
  PHI in scope labels, URLs, identifiers, or bodies.
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
together. With a caller-supplied public key, validation reports
`SIGNATURE_VERIFIED_WITH_SUPPLIED_KEY`; this proves signature integrity under
that selected key, not controller-enrolled signer identity. Version 0.10 can
publish the exact detached attestation, verify its
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

Ingest acquires the run lock and verifies its compare-and-swap before creating a
content-addressed result. Finalization commits its terminal manifest before
publishing report artifacts under the same lock and can regenerate a missing
artifact from the committed run on retry. A killed ingest can still leave an
unreferenced content-addressed file; it has no manifest authority and cannot
block an alternate result, but it is outside logical artifact accounting.
Production deployments need controller-owned orphan reclamation and a physical
disk quota.

Legacy evidence-bundle manifests authenticate payload descriptors but do not
authenticate profile semantics, acquisition-plan identity, or a trusted signer,
and their former verify-then-reread flow is not an authority boundary. Public
evidence acquisition plan/run and audit `--evidence-bundle` import therefore
fail closed in this release. Reactivation requires one atomic no-follow reader,
a controller-signed canonical manifest covering semantic profile, payloads, and
plan identity, enrolled local artifact roots, and a durable fail-closed stop
channel that can terminate in-flight descendant processes.
