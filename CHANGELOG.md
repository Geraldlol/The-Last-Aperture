# Changelog

## 0.16.0 - 2026-09-16

### Added

- A protocol-v2 BORG lifecycle behind the existing target-only command. After
  the verified HTTPS observation, the controller can run five attacker roles,
  an exploit falsifier, and a skeptic through controller-configured reasoning
  adapters, then deterministically merge their attributed hypotheses.
- A self-bound swarm basis, bounded two-round and fourteen-call budget,
  four-call parallel waves, durable provider-attempt ledger, reviewer
  challenges, and one final merged proposal admission.
- A protocol-v2 campaign snapshot that reports live or sealed swarm progress,
  usage, candidates, challenges, gaps, Stop/Resume state, and exact artifact
  bindings without promoting provider output to a verified finding.
- Crash-safe sealing and recovery across final candidate admission, frontier
  publication, swarm completion, the terminal campaign event, and the
  basis-publication window before the SWARMING state revision.
- A modular, versioned action-risk catalog and immutable pre-flight receipt for
  every dispatchable Unleash target action. The verified status snapshot exposes the
  selected profile, selection rationale, relative control exposure, likely
  impact, residual uncertainty, stable generic detection-pattern matches, and
  any required confirmation. The unified CLI surfaces that summary on stderr
  before dispatch, including as a structured warning in JSON mode.
- Context-selected `AUTO`, plus explicit aggressive, balanced, and cautious
  profiles. Immutable Pause/owner-bound Resume cycles, a Stop kill switch, and
  bounded local rollback are available through the unified CLI.

### Security

- Bound every provider request, byte capture, transport receipt, ledger event,
  response, merge, admission, and completion to the exact campaign, target,
  policy, registry, evidence packet, role, round, and adapter identity.
- Captured bounded provider bytes before interpretation, prohibited replay
  after ambiguous dispatch, resumed captured responses locally, and rejected
  expired leases, identity drift, computed inputs, partial artifact chains, and
  non-UTF-8 captures.
- Bounded every retained merge to 262,144 canonical JSON bytes and made the
  role-ordered fold reject a whole response as an explicit gap whenever it
  would violate any aggregate merge invariant, while continuing later roles.
- Required every inert `tool:https-recon` proposal to carry the exact
  `{ "method": "HEAD" }` parameter contract at response, merge, snapshot, and
  admission validation boundaries.
- Kept action-risk scores explicitly uncalibrated and distinct from alert
  probability. Telemetry coverage and collection preconditions remain unknown;
  profile volume violations fail closed, and high-risk or high-noise actions
  require confirmation bound to the exact assessment and receipt. Stealth,
  evasive, and bypass profile names are rejected.
- Added immutable Pause and owner-bound Resume artifacts. Pause drains in-flight
  work, closes later dispatch, and never permits replay of ambiguous delivery.
  Rollback cancels only future local work and inert proposals, records that
  target-side effects were not reversed, and invokes the terminal Stop path.
- Rechecked Stop, authority, and deadline immediately around every durable
  STARTED publication and provider invocation. Immutable confirmation, Pause,
  rollback, and Stop records are the bounded external control inputs, while an
  active swarm remains the only writer of campaign state and swarm artifacts.
  Resume must win an atomic
  exclusive-owner claim, cannot displace a live owner after any elapsed time,
  and can reclaim only an exact identity-bound lock from a dead process. Every
  campaign-state or swarm-artifact mutation and provider invocation revalidates
  that owner token.
- Linearized Stop and Seal through one immutable, self-bound terminal fence so
  only one decision can win, including across a crash between fence publication
  and the remaining terminal artifacts.
- Recovered the exact POSIX two-link tail left by a crash during create-only
  publication, while leaving unrelated hard links untouched and failing closed.
- Made the swarm owner lock a permanent private container with create-only
  `owner.json` claims, exact dead-stage recovery, and unique actor-bound
  retirement barriers that prevent stale reclaimers from deleting successors.
- Made protocol-v2 Status verification-only. A proven stale mutable projection
  is repaired only after Resume acquires the exact campaign owner.
- Recovered and verified the exact provider-attempt event chain, mutable head,
  merge filename/body sequence, committed-attempt bindings, and terminal usage
  before accepting public campaign status.
- Kept provider hypotheses as candidates and provider actions as inert typed
  proposals. Findings remain empty until a separate proof controller verifies
  evidence, and an empty provider result cannot claim a clean target.

### Current boundary

- The default CLI ships with no configured reasoning adapters, so all seven
  BORG roles settle as explicit coverage gaps while the campaign still seals a
  deterministic empty admission. Credential-free HTTPS reconnaissance remains
  the only active default target action. Crawling, exploit execution and proof
  oracles, authenticated techniques, repair loops, additional target families,
  and the graphical cockpit remain unavailable. Detection estimates do not prove
  an alert will or will not fire, and no profile suppresses target telemetry. A
  Stop racing a live BORG run
  first reports `STOP_REQUESTED`; the active owner then seals the terminal
  `STOPPED` state without a competing dispatch or replay.

## 0.15.0 - 2026-09-15

### Added

- A target-only `engage unleash <https-target>` entry point whose runtime input
  contains no authority, profile, provider, repository, credential, or output
  fields.
- Controller-owned deployment policy and restart-safe revocation state with
  strict owner, permission, link, and Windows ACL validation.
- A frozen route registry and self-bound campaign plan that enumerate every
  packaged route as ready, waiting, unavailable, blocked, or not applicable.
- Append-only campaign state, safe Status/Stop/Resume commands, typed HTTPS
  completion receipts, and metadata-only evidence packets.

### Security

- Bound the first remote route to an exact controller-policy authority record,
  one credential-free HTTPS `HEAD`, fixed limits, no caller-selected,
  diagnostic-profile, or credential headers, and fail-closed revalidation before
  execution, lease, and dispatch. The native client uses fixed transport
  defaults.
- Bound completion to the exact adapter, verifier, execution contract, target,
  policy, revocation check, HTTP-recon plan, event-chain head, evidence packet,
  and completion-receipt digests.
- Prevented automatic replay after ambiguous delivery, partial publication,
  registry drift, missing evidence, or failed recovery.
- Required CVE-candidate affected-product and disclosure claims to carry a
  separate authenticated review bound to proof-receipt evidence. Cleanup now
  binds the exact proof receipt and cannot predate proof execution. Proof and
  cleanup receipts bind their full evidence manifests, including locators, and
  positive `NOT_REQUIRED` cleanup decisions require authentication.
- Restricted the initial vulnerability contract to canonical HTTPS targets and
  rejected portable-path aliases, including Windows console and superscript
  device names. HTTPS target intake rejects percent-encoded path aliases and
  trailing-dot hosts until an explicit equivalence canonicalizer ships.
- Preserved revoked policy identifiers across deployment-policy digest
  rotations so policy edits cannot clear a durable revocation tombstone.

### Current boundary

- The shipped Unleash route performs one bounded HTTPS observation and reports
  all other registered work as explicit gaps. Provider hypothesis execution,
  crawling, authenticated techniques, exploit oracles, repair loops, additional
  target families, and a graphical cockpit remain future work.

## 0.14.1 - 2026-09-12

### Added

- A complete, deterministic full-engagement route inventory with explicit
  dispatchable and unavailable outcomes.
- Installed-package readiness checks for Ghidra, Frida, Burp/Montoya, Java,
  OCI tooling, and the required browser-bridge assets.
- Pull-request validation on the supported Node 20 and Node 24 runtimes.

### Fixed

- Bound evidence metadata, acquisition plans, adapters, roots, executable
  identities, and registry image identities to verified durable state.
- Enforced evidence, command, registry, archive, and decompression limits with
  bounded preflight and streaming enforcement; normalized supported GNU, PAX,
  gzip, repeated-layer,
  directory, and large OCI archive forms without uncaught failures.
- Made HTTP recon and authenticated campaign locks, stop markers, reports,
  finalization, reopen timing, redirect handling, and delivery classification
  crash-safe and deterministic.
- Erased transient HTTP, browser, mutation, observer, credential, and connector
  buffers across success, rejection, timeout, cancellation, and recovery paths.
- Redacted credential carriers in HAR, Burp, browser-session, and generated
  connector flows while preserving exact credential-free request bytes.
- Preserved passive capture behavior, bounded browser observations, mutation
  settlement, response-read failures, and connector callback deadlines.
- Rejected repeatedly encoded traversal and ambiguous authority statements, and
  bound resumed repository and artifact targets to their original identities.
- Pinned the patched `fast-uri` 3.1.7 release for clean artifact installs; the
  prior 3.1.6 override was ignored downstream and is affected by
  `GHSA-qw65-cvwx-89v3` and `GHSA-58mr-gqgx-xq4g`.

### Packaging

- Added a publishable shrinkwrap, a packaged changelog, deterministic installed
  doctor checks, and a uniquely versioned upload artifact workflow.
