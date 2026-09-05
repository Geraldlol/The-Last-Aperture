# ADR 0024: Public sealed T2 loopback service proof

- Status: Accepted
- Date: 2026-09-04
- Owners: Red Team Audit platform
- Extends: ADR 0022's sealed Docker proof boundary
- Applies: ADR 0023's operator-authority rule to one implemented T2 route

## Context

Public `run-proof` can execute repository tests in sealed T1 containers, but it
deliberately has no socket, service lifecycle, or loopback capability. Some
findings require the application to be running while a proof client makes a real
local connection. Treating those recipes as T1 would misstate the evidence;
starting them on the host would abandon the source, credential, network, and
cleanup boundary.

An authenticated operator statement naming the repository, target scope, and
local dynamic testing already supplies authority for that work. Asking for another consent,
RoE, ownership assertion, or legal certification would add no authority. The
missing piece is a narrowly implemented transport with truthful T2 evidence.

## Decision

Add public `audit run-service-proof` for one constrained local-service shape.

1. The authenticated operator target/scope statement accepted at ingress is the
   sole authorization fact. If it names local dynamic testing, the controller proceeds without another
   authorization prompt. The controller still enforces the sealed scope,
   commands, port, limits, and current proof job.
2. The route accepts only a `LOCAL_DYNAMIC` run created with `--seal-source`, a
   strict v3 proof configuration, and the same external, immutable-image,
   dependency-manifest-bound worker configuration used by sealed proof.
   Configuration files remain outside both the target and run bundle.
3. The service, attack command, and control command are exact `node` or `npm`
   argv arrays. They are launched without host-shell interpolation. The service
   must remain in the foreground and honor the fixed
   `RTA_SERVICE_HOST=127.0.0.1` and sealed unprivileged port.
4. Each command runs beside its service in one fresh Linux container. Attack
   and control use different containers reconstructed from the same sealed
   source, immutable image, dependency manifest, policy, and service contract.
   They share no service state, volume, mount, or container identity.
5. Docker remains fixed to the controller-owned executable, local default
   context, immutable image ID, and `--pull=never`. The container has
   `--network=none`, no host mounts or published ports, a read-only root,
   bounded tmpfs/resources, a non-root identity, dropped capabilities,
   no-new-privileges, seccomp, private namespaces, no Docker healthcheck or log
   driver, and no ambient or proxy credentials.
   Source staging uses UID 65532; the controller then seals the copied tree
   read-only and runs the service, attack, and control as UID 65534. Only the
   separate `/work/runtime` scratch directory is writable by target code.
6. Docker init and an immutable controller supervisor own the lifecycle. The
   supervisor waits until sealed source transfer and dependency checks finish,
   then starts the foreground service. Its independent TTL bounds the service
   even if the controlling Docker client disappears.
7. Readiness uses a fixed controller-owned TCP probe against literal
   `127.0.0.1:<sealed-port>` inside the same network-none container. The port
   must be proven closed before boot, ready before the proof command, and ready
   again afterward. Target stdout and image-defined healthchecks never establish
   readiness or proof.
8. The controller re-inspects the exact immutable container identity and
   effective running/network/port state around service execution. Any identity,
   isolation, source, image, dependency, readiness, timeout, or output-bound
   drift fails closed. It verifies a full copied-tree digest before boot,
   immediately before the proof command, and immediately afterward. There is no
   host-process or weaker-container fallback.
9. One monotonic controller-session deadline begins before the first Docker
   operation. It includes bounded setup and target execution plus a teardown
   reserve. Every Docker call, archive transfer, target process, readiness poll,
   and sleep is shortened to the remaining budget. Exhaustion stops further
   dispatch with `SERVICE_PROOF_WALL_TIMEOUT`; teardown uses only the reserved
   remainder, and teardown exhaustion remains cleanup-unverified.
10. Before Docker is reachable, a hash-chained `SERVICE_PROOF_CONTAINER`
    attempt lease durably binds the packet, source/control provenance, v3 proof
    config, worker config, both fresh container names, both controller-session
    budgets, capture grace, and expiry. The controller persists `LEASED`, then
    `STARTED`, captures the exact receipt as `RESULT_CAPTURED`, validates it,
    and commits it. A process-owned command lock fences a live controller even
    after lease expiry and is stale-recovered only after its PID is dead. An
    unexpired attempt cannot be stolen. Expired `LEASED` work can retry
    directly; expired `STARTED` work can retry only after both
    bound identities are authenticated, removed by immutable container ID, and
    proven absent. Cleanup ambiguity is terminal. Captured or validated work
    resumes without launching another container.
11. Cleanup kills and removes the exact container and verifies absence on every
   terminal path. An ambiguous create or teardown is not successful T2 proof.
12. Public v3 proof rejects candidate patches. Remediation remains a separately
    directed workflow followed by a new audit.
13. Receipts retain controller-derived lifecycle facts, exit metadata, byte
    counts, SHA-256 digests, truncation state, immutable bindings, and cleanup
    status. Raw service, attack, and control output is omitted because source
    fixtures and output may contain secrets, PII, or PHI.
14. This route resolves no live credentials and contacts no host, external
    service, production system, emulator, database, registry, nested container,
    or other supporting infrastructure. Those T2/live shapes remain
    authorized-but-unavailable unless a separate matching controller is
    implemented.

## Evidence semantics

`proof_tier: T2` means both fresh service sessions completed through this route,
not merely that a service command was attempted. This release has no enrolled,
controller-authenticated semantic oracle. The proof configuration and its exit
classes are provider-authored, so even a complete attack/control differential
records `proof_tier: T2` with `verification_status: UNPROVEN`; it cannot produce
`CONFIRMED`, `NOT_REPRODUCED`, or `FIX_VERIFIED`. Receipts preserve the exact
controller-observed lifecycle and exit facts for review. A missing session,
readiness failure, undeclared exit, timeout, truncation, isolation drift, or
cleanup ambiguity is likewise never a clean result. Definitive status requires
a future hard-enrolled controller-owned semantic-oracle adapter whose receipt is
bound to the same source, worker, service, attack, and control observations.

## Consequences

The platform can now execute the common Node/npm "boot locally, probe over
loopback" recipe without a second consent gate and without exposing a host
socket or live target. Attack/control separation prevents one proof's service
state from validating the other.

This is not general T2. It cannot launch multi-container stacks, browsers,
mobile emulators, LocalStack, registries, databases, Docker-in-Docker, arbitrary
native programs, or a service that needs external dependencies. Such recipes
remain explicit coverage gaps until their own lifecycle controllers exist.

Docker, its daemon, the immutable worker image, and the shared kernel remain in
the trusted computing base. The route does not claim containment from a hostile
Docker administrator or a kernel/runtime escape; stronger adversary models need
a disposable VM or comparable boundary.

Controller or host failure is recoverable without replay ambiguity. A durable
lease records whether Docker was reachable and names both possible containers.
Recovery never rewinds `RUNNING`: a live process-owned command lock prevents
takeover, while a dead owner's lock is atomically reclaimed. Recovery then waits
for lease expiry, authenticates the local default context and any present container against the
pinned image, worker digest, service command, port, labels, network, mounts, and
hardening, then proves both names absent before issuing a fresh lease. A receipt
captured before the stop is committed directly. A same-name replacement is not
deleted. Legacy `RUNNING` service jobs created before these identities were
recorded remain fail-closed because their cleanup targets are unknowable; start
a new audit under the operator authority already supplied, without asking for
authorization again.

## Alternatives considered

### Add loopback to the T1 worker

Rejected. A booted service with a real socket is T2 evidence and needs lifecycle,
readiness, differential-session, and teardown claims that T1 does not make.

### Boot the service on the host

Rejected. A disposable directory does not deny ambient credentials, network,
host paths, descendants, or leftover processes.

### Put attack and control against one service instance

Rejected. Attack mutation, caches, sessions, timing, and process state could
contaminate the control and manufacture a differential result.

### Trust application health output

Rejected. Target-controlled stdout and health scripts can say "ready" without
the sealed loopback endpoint being available.

## Validation

- The public CLI exposes `run-service-proof` without a repeated authorization
  input and refuses non-`LOCAL_DYNAMIC`, unsealed, or non-v3 runs before boot.
- Contract tests reject unsupported programs, ports, protocols, extra fields,
  patches, and policy-unbound service/proof commands.
- Container tests mutate isolation, identity, network, state, readiness,
  manifests, output, timing, and cleanup and require fail-closed results.
- `npm.cmd run test:service-proof:docker` exercises the real Docker lifecycle
  only as an explicit trusted-checkout conformance launcher; ordinary tests do
  not auto-discover it.
- Attack and control must have distinct container IDs and equal immutable worker
  bindings before evidence may report T2.
- Deadline tests consume setup time, execution time, polling time, and teardown
  reserve and prove no operation is dispatched after the cumulative budget.
- Recovery tests cover expired `LEASED`, expired `STARTED`, cleanup ambiguity,
  same-name replacement, and `RESULT_CAPTURED` restart without a second launch.
- Skill, harness, release-wiring, lens lint, and full platform tests preserve
  this narrow route and all remaining unavailable capability boundaries.
