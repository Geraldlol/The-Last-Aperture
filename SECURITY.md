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

Version 0.10.0 supports static, read-only planning, externally produced job
results, and an opt-in sealed provider runner. It never executes target code or
grants the provider a target mount, host network, credentials, or arbitrary
host process authority.

Two features open an outbound network connection, and both are opt-in and
externally authorized. Signed remote-gateway execution sends one Ed25519-signed
request to a single TLS-SPKI-pinned, DNS-scope-restricted HTTPS endpoint.
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
