# ADR 0022: Public sealed T1 repository proof

- Status: Accepted
- Date: 2026-09-04
- Owners: The Last Aperture platform
- Supersedes for public T1 activation: ADR 0020's disabled `run-proof` and
  source-sealing release gate
- Replaces as current capability statement: the disabled release status in
  `docs/design/2026-08-02-test-execution-capability.md`
- Amended by: ADR 0023, which separates named operator authority from the
  T1 worker's technical capability

## Context

The repository workflow could plan proof jobs but publicly refused both source
sealing and `run-proof`. Even when an operator explicitly named a
local repository and requested dynamic tests, the skill asked again and then
reported T1 as unavailable. That preserved a safety boundary but prevented the
authorized test from happening.

A host-side disposable copy is not a sufficient execution boundary. Target test
code can inherit credentials, open sockets, reach host services, start
descendants, write outside the copy, or leave ambiguous process state. A
read-only bind mount also exposes live target state and does not establish which
bytes were executed.

## Decision

Public repository T1 proof is active under these rules.

1. An operator directive that names a local repository and asks for dynamic
   testing is launch authority for T1. The skill proceeds without a second
   confirmation. The statement is the sole authorization fact for every
   capability it explicitly names; a T1-only statement stays narrow. The T1
   worker cannot boot services, use live credentials, contact external services,
   modify the target, or remediate. Named broader authority is retained for a
   matching implemented route; if absent, report it unavailable without re-asking.
2. Planning uses a `test`-mode technical policy and `--seal-source`. The source
   archive must be written to an explicit local, non-reparse output directory
   outside the target. It is sensitive source material. The policy permits only
   exact proof commands, proof-file writes under security-test leaves, and no
   network.
3. Public `run-proof` accepts only a v2 proof configuration and an external
   `proof-worker` configuration. Both files stay outside the target and bundle.
   The proof config binds the proof-verification job, strategy, attack and
   control commands, oracle, limits, reproducer, and destination-guard
   declaration.
4. The worker config binds the controller-owned Docker CLI path, exact immutable
   local OCI image ID, dependency-manifest digest, and resource limits. The
   controller independently verifies the length-framed
   `package.json`/`package-lock.json` digest in the sealed source, immutable
   image, and copied execution tree. A tag alone is not image identity.
5. The controller reconstructs the complete verified source snapshot in bounded
   staging and streams it into container tmpfs. It never mounts the live target,
   bundle, staging directory, Docker socket, or another host path.
6. Attack and control commands run in separate fresh containers created from the
   same sealed source and proof files. Only exact allowlisted `node` and `npm`
   programs are public. The worker uses the default local Docker context,
   `--network=none`, a read-only root, bounded tmpfs, a non-root identity,
   dropped capabilities, no-new-privileges, seccomp, private IPC, a minimal
   environment, and wall-time, Docker-command, source, output, memory, CPU, PID,
   and file-descriptor limits.
7. The controller records exit metadata and stdout/stderr byte counts, SHA-256
   digests, and truncation state. Raw target output is omitted because it may
   contain secrets, PII, or PHI.
8. Cleanup owns one unpredictable, controller-labeled container at a time. It
   kills and removes that exact container and verifies absence. Ambiguous setup,
   execution, or teardown fails closed; there is no host-process fallback.
9. Public proof rejects `patch_files`. Vulnerability reproduction and
   remediation are separate workflows. Remediation must be named by the accepted
   operator statement and use safe implementation, verification, and a new
   audit; no audit bundle or finding is rewritten.
10. T2 remains technically unavailable through this public route. It does not boot applications,
    databases, emulators, local registries, testcontainers, or other services and
    provides no loopback or external network. Provider, remote, database-lab,
    evidence-import, bounty/OOB, transparency, and generic live/L3 routes remain
    technically unavailable. If the statement named T2, service boots, controller-referenced
    credentials, or external services, retain that authority and report the
    missing matching route as an authorized-but-unavailable gap.

## Consequences

An authorized local dynamic-test request now produces executed T1 evidence when
its proof and worker prerequisites are satisfied, without a second authorization
conversation. Source bytes and dependencies are bound to the receipt, and
attack/control isolation prevents one proof command from contaminating the
other.

Docker and the prebuilt worker image are part of the trusted computing base. OCI
is a shared-kernel boundary, not proof that arbitrary native code is perfectly
isolated. `--network=none` and no host mounts intentionally exclude test suites
that need sockets, nested containers, services, credentials, or downloads; those
remain an explicit coverage gap rather than a reason to weaken T1.

Omitting raw output reduces PHI and secret persistence but means debugging uses
bounded metadata and a separately scoped, suitably protected workflow.
Source sealing itself grants no provider, remote, or network authority.

## Alternatives considered

### Ask for confirmation immediately before every test

Rejected. The authenticated operator already named the repository and requested
dynamic tests. A repeat prompt adds friction without changing target, scope, or
capability; the controller should instead enforce the sealed T1 boundary.

### Execute in a host-side disposable copy

Rejected. A copy protects the original tree but does not deny ambient
credentials, network, host paths, or descendant processes and cannot reliably
prove cleanup.

### Bind-mount the repository read-only

Rejected. It exposes live state, weakens exact-byte provenance, and unnecessarily
adds a host path to target-code authority.

### Allow service boots or loopback in the same route

Rejected. That is T2 and requires a different controller, lifecycle, destination
policy, health model, and cleanup proof. The operator statement remains the sole
authorization fact, but this route remains technically unavailable.

### Apply a candidate patch in the proof worker

Rejected. Vulnerability existence must not depend on a fix, and the T1 proof
route must not silently become a remediation route. If remediation was named,
use its separate implemented workflow.

## Validation

- Public `plan --seal-source` creates a runner-ready test bundle only outside the
  target.
- Public `run-proof` requires v2 proof and external worker configurations and
  rejects `patch_files`.
- Worker schema, immutable-image, dependency-manifest, effective-container,
  source-transfer, output-omission, timeout, and cleanup tests fail closed.
- Attack and control each receive a fresh container from identical sealed input.
- Skill, lens, release-wiring, and full platform tests preserve the T1/T2 and
  remediation boundaries.
