# ADR 0028: Unified engagement control plane

- Status: Accepted
- Date: 2026-09-11
- Owners: The Last Aperture platform
- Extends: ADR 0023

## Context

The platform accepts one operator statement as authority for a named target, but
its repository, HTTP, browser, Burp, Ghidra, Frida, and connector workflows use
separate entrypoints and state. Agents can compose them, yet there is no durable
engagement object that preserves the original statement, selects routes, reports
combined progress, or stops all later work. Authorization friction was removed;
execution friction remained.

## Decision

Add one outer engagement controller as the normal operator-facing entrypoint.
It accepts a target, one bounded ordinary-language authorization statement, and
one explicit machine-readable authority profile. It persists that authority
once and binds it to a canonical target and objective. Restrictive statement
language cannot be expanded by selecting a broader profile.
The engagement remains authoritative across Codex/Claude handoffs and resumes.
It never asks the operator to repeat unchanged authority.

The controller owns a canonical append-only ledger plus an external sibling head
chain. It selects applicable routes from a frozen registry, records a durable
dispatch permit before target I/O, and records every result, gap, cleanup state,
stop, and terminal outcome. Successful route outputs are bound by canonical
file-tree manifests and reverified before status, resume, or dependent dispatch.
Existing route controllers retain their own validation and evidence contracts.
Mutable child ledgers are checkpointed into the outer ledger; they are not
competing authority sources.

A technically missing installed tool or already named host adapter produces
`WAITING_FOR_MATERIAL` or `AUTHORIZED_BUT_UNAVAILABLE`. It does not trigger
another authorization question and does not stop independent routes. Intake is
immutable: an omitted capture, configuration, credential reference, target, or
scope fact requires a successor engagement rather than a resume.
Once the authenticated browser route is dispatched, selected-tab attachment
failure is recorded as a settled route outcome rather than resumable waiting.

The controller may derive short-lived route grants from the durable engagement
authority. Those grants bind the engagement, authority, target, route, and
invocation digests. They are controller implementation records, not new operator
statements.

After a successful HTTPS-recon dependency, the controller can derive the
authenticated browser route from exactly one
`browser:<32-character-lowercase-a-p-extension-id>` credential reference. An
optional content-bound `last-aperture/page-session-adapter` configuration names
the browser storage source and request carrier without exposing the session
value. The derived short-lived scope, campaign grant, campaign ledger, and
materials directory stay under the route directory and are bound into its
terminal output manifest. Named browser references with other forms require a
host-injected credential resolver and otherwise remain waiting material.

After verified HTTPS reconnaissance, a fixed offline route projects its bound
method, URL, status, header-name, complete-body size-bucket, and timing metadata
into value-free web evidence. When the authenticated route succeeded, it selects
the exact scope named by that route's permit-bound invocation from the retained
scope history and projects only settled sealed-plan seed status plus a
page-session request-header carrier explicitly named by that scope. Historical
scope verification remains structural and digest-bound after expiry; live sends
still require current validity. The projection does not claim response-discovered
endpoint inventory, complete auth flow, response shape, redirect or write
semantics, replay, pagination, credential values, or coverage.

The public workflow is `engage run`, `engage resume`, `engage status`, and
`engage stop`. Repository engagements also expose `engage work next`, `status`,
`submit`, `finalize`, and `validate`; their persisted envelopes, staged results,
and child-ledger checkpoints are bound into the outer engagement ledger.
Compatibility entrypoints remain available and are invoked only through fixed
public adapters without a shell. Host-tool work without a registered route stays
outside the public engagement record.

## Consequences

The user can name a target once and let the agent run the complete applicable
toolchain. Status and stop are unified. The original statement survives process
restart, while target or scope changes still require a successor engagement.

The outer controller does not turn reverse observations into vulnerability
verdicts, manufacture unavailable credentials or runtimes, or override operating
system and hosting-platform capability controls. It records those conditions
honestly and continues other work.

## Rejected alternatives

### Keep orchestration only in prompt text

Rejected because prompt continuity alone cannot provide durable target binding,
at-most-once dispatch, combined status, or a shared stop state.

### Merge every child protocol into one schema and ledger

Rejected because route-specific recovery and evidence semantics would be lost.
The engagement ledger anchors child state while preserving each protocol.

### Synthesize a fresh operator statement on every route

Rejected because it recreates the permission friction the platform is designed
to remove and obscures the actual original authority.

## Validation

- One varied natural-language statement drives multiple routes and resumes.
- Every route grant references the original authority digest.
- Tampered authority, target, ledger, or route binding is rejected before I/O.
- Missing material is recorded and independent work continues.
- Stop is durable and prevents all subsequent dispatch.
- Existing route compatibility tests remain green.
