# Security policy

## Reporting a vulnerability

Do not include real credentials, private source code, personal data, PHI, or
customer evidence in a public issue.

Until a dedicated private reporting channel is published, contact the repository
owner through the private channel by which you received access and request a
security-reporting destination. Public reports should contain only a minimized,
synthetic reproduction.

## Supported security boundary

Version 0.6.0 supports static, read-only planning, externally produced job
results, and an opt-in sealed provider runner. It never executes target code or
grants the provider a target mount, host network, credentials, or arbitrary
host process authority.

For run schema 4, database providers contribute only shard-local store claims.
The controller binds each contribution to its planned job and input digest,
rejects cross-shard evidence or profiling, and synthesizes a store profile only
after every base fan-out job has completed. Provider semantic claims remain
declarations; authentication and deterministic synthesis do not prove that the
analysis was correct.

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
- Keep root-manifest signing keys, verification keys, and detached attestations
  outside both the target and run bundle. Store attestations under independent
  access control if they are used as the trust anchor.
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
together. Attestation timestamps are controller clock declarations, not
trusted timestamps, and the project does not yet claim transparency-log
inclusion, consistency, witness, or revocation guarantees. Provider execution
envelopes remain strong only when their receipt public key is also pinned
externally. Bundle-path checks fail closed on observed symlink/reparse
components, but Node does not provide portable handle-relative path creation;
keep the bundle on a directory that cannot be concurrently renamed or replaced
by a hostile local process.
