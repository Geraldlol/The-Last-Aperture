# Changelog

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
