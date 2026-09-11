# Reverse engineering and protocol reconstruction

Use `npm.cmd run audit:reverse -- ...` only for the artifact, executable,
HAR/Burp capture, origins, and workflow named by the operator. The existing
operator statement is the authorization fact; do not ask again. A missing tool
or unsupported launch shape is a technical gap, not an authorization denial.

## Routes

- `ghidra analyze` copies one contained artifact into controller scratch and
  runs the bundled fixed static exporter. It records bounded program, function,
  supported network-API, reference-kind/source-offset, call-site-offset, static
  endpoint-shape, and auth-hint observations. It never executes the target or
  treats a static candidate as reachable behavior. Invoke native launchers
  directly; on Windows, run `.bat` and `.cmd` launchers only through the bundled
  fixed bridge and kill-on-close Job Object supervisor.
- `frida trace` spawns one exact contained local-lab executable and observes one
  named symbol with the bundled fixed agent. Never attach to a PID, process
  name, device, or remote host. Never accept caller script, target arguments,
  raw Frida arguments, or ambient secrets. This host route is not a sandbox;
  run only artifacts trusted for host execution. Treat the emitted
  module-relative symbol offset as opaque metadata, not a stable address or
  semantic result.
- `frida trace-plan` validates one strict `native-call-trace-v2` JSON plan and
  runs only the bundled agent. A plan may name at most 256 exact export,
  module-offset, absolute-address, or module-scoped debug-symbol hooks. It may
  select local spawn, local PID/name attach, USB PID/name/application attach,
  or explicit-device PID/name/application attach using Frida's fixed
  `-f`/`-p`/`-n`/`-N` and `-U`/`-D` selectors. It never accepts a remote host,
  token, caller script, evaluated code, target arguments, or raw Frida
  arguments.
- A v2 hook may retain bounded pointer metadata, signed or unsigned integers,
  booleans, UTF-8 bytes, UTF-16 bytes, and opaque bytes from arguments on entry
  or exit, or from a return value. Memory lengths are fixed or derived from one named argument and
  capped by the descriptor, frame, session, record, event, and duration limits.
  `raw` string and byte values are base64; `sha256` retains only a digest;
  `metadata` retains no value. Read failures and truncation reasons remain
  explicit. Captured values stay only in the standalone local reverse evidence
  and are never copied into a native interaction contract.
- Every v2 mode binds observations to the supplied local artifact copy. Local
  spawn can succeed only when the complete trace has no capture failure or
  truncation. Attach and device modes remain `PARTIAL` with
  `RUNTIME_ARTIFACT_IDENTITY_UNVERIFIED`, because a local copy does not prove
  which bytes the existing process or device loaded.
- `web import-har` reads one bounded local HAR offline. Require every retained
  HTTP(S) origin through `--origin`. Unknown path segments are masked; use
  `--path-literal` only for an operator-reviewed structural route segment.
- `web import-burp` reads one bounded Burp Save Items XML file offline and feeds
  its exact raw HTTP request/response messages through the same value-redacted
  web evidence projection. XML declarations/entities, malformed or inconsistent
  messages, and resource-bound violations are refused. The source retains
  `BURP_XML` provenance.
- `web import-live-metadata` reads a structurally and digest-verified HTTP
  reconnaissance bundle offline and can also read the matching historical
  authenticated scope and append-only campaign ledger. Reconnaissance supplies
  method, URL, status, response-header names, observation time/timing, a coarse
  body-size bucket, and source/hash metadata. It supplies no header/body values,
  response shape, or redirect semantics. Authenticated evidence includes only a
  settled `SEALED_PLAN` probe seed and status; it adds a request-header carrier
  only when the sealed page-session adapter explicitly names that carrier.
  Response-discovered actions and ambient credential names or values are never
  projected.
- The optional `integrations/burp-montoya` extension reads existing Proxy history
  with `finalRequest()` and emits a create-only sanitized HAR under one exact
  origin, path prefix, route-literal set, and item limit. It uses no Scanner,
  traffic dispatch, or traffic modification API. Import its `WEB_HAR` output
  with `web import-har`.
- `protocol build` digest-links one or more sanitized web, Ghidra, or Frida
  evidence files into `native-interaction-contract-v1`; reverse evidence alone
  is valid and preserves explicit missing-web gaps.
- `protocol generate` validates that contract offline and writes a new,
  deterministic Node connector package labeled `GENERATED_REVIEWABLE`. Its
  runtime accepts endpoint IDs rather than arbitrary URLs and is bound to the
  observed origins, methods, shapes, redirects, and retry evidence.
- `protocol verify` checks that package's exact file inventory and digests
  against the manifest SHA-256 retained outside the package.

Write outputs outside the target and refuse replacement. Hash inputs before and
after tool execution. Keep Ghidra scratch and Frida processes bounded, and treat
cleanup uncertainty as failure or an explicit gap.

The live metadata import does not prove a complete authentication flow,
response-discovered endpoint inventory, write semantics, replay safety,
pagination, coverage, or credential availability. Historical import accepts an
expired scope only after structural and digest verification against its ledger;
that offline acceptance does not renew it. Live dispatch still requires a
current scope. Engagement inputs, captures, and credential references are
immutable: an omitted one requires a successor engagement. Resume can unblock
only an already named host adapter or tool that has become available.

## Web protocol evidence

A raw HAR or Burp XML capture can hold live credentials and PHI. Keep it local
and ephemeral. The sanitized evidence retains methods, explicitly scoped
origins, path templates,
query and body field names, coarse types, content types, header and cookie
names, status codes, sequence, redirect metadata, response-body destination
field paths, byte buckets, and timing. It removes query, header, cookie, and
  body values. Obvious value-shaped names are replaced with fixed placeholders.
  Action-like values become only `READ_ACTION`, `WRITE_ACTION`, or
  `OTHER_ACTION` classes.

Field, header, cookie, and explicitly approved path-literal names are protocol
metadata but can themselves contain sensitive data in unusual applications.
Capture synthetic non-PHI workflows and review sanitized output before sharing.
Off-scope destinations are omitted. A response-body destination is retained
only as its field path, in-scope origin, templated path, and query-name shape.

## Connector contract and generated runtime

The source contract stays `DRAFT_OBSERVED`; generate the runtime with
`protocol generate --contract <absolute.json> --out <absolute-new-directory>`.
The emitted package is `GENERATED_REVIEWABLE` and implements these parts of a
native client:

- separate auth request actions and response transitions, plus credential-carrier names;
- per-observation endpoint exchanges binding an evidence reference, capture,
  sequence, exact request action and basis, request carriers, response status,
  response carriers, and response destinations;
- origin-specific cookie jars and response-supplied destinations;
- endpoint method, path template, parameter locations, encoding, and response
  shape;
- pagination and adjacent retry observations;
- `READ_CANDIDATE`, `WRITE_CANDIDATE`, or `UNKNOWN` side-effect assessments;
- all redacted destination candidates and unique correlation within the next
  three same-capture observations only for an exact, untemplated origin and
  path; and
- `FOLLOWUP_READ_SAME_TEMPLATE_OBSERVED` when a later read uses the same path
  template after a write candidate.

The generated runtime enforces endpoint IDs, exact contract origins and methods,
path placeholders, observed query/body shapes and content types, per-origin
in-memory cookies, observed redirect destinations, and observed retry routes.
It accepts a credential-provider callback and never writes returned credential
values. Declared response-body credential fields are redacted from ordinary
results and use a separate optional transient receiver. Automatic retry
additionally requires a `READ_CANDIDATE`; writes and unknown operations run
once. Retain the returned manifest digest outside the
package when coordinated file-and-manifest modification is in scope. Review at
least two synthetic captures and add application-specific
token refresh, pagination termination, idempotency, success, failure, rollback,
and drift behavior in the consuming integration. A same-template follow-up read does not prove record identity
or a state change. `CREDENTIAL_CARRIER_OBSERVED` records a response carrier name
and location; it does not prove session establishment or authentication success.
A redacted destination path remains unlinked because removed path values cannot
be compared. A `2xx` response is not write success. Require a designated
test resource, one bounded dispatch, application-specific positive and negative
predicates, a post-read when available, and rollback evidence for mutations.

The `http-authed campaign-attested` browser-held session route can validate
sealed actions and admit policy-bounded response-derived candidates inside the
same origin, path, method, category, substitution, and action budgets.
For one application-managed Web Storage string, planning may seal a declarative
page-session adapter with an exact area/key, raw or strict JSON Pointer
extraction, lower-case request-header carrier, target constraints, validity, and
value-size bound. The value is reacquired and applied inside the isolated fetch;
it never crosses the extension worker, controller, ledger, evidence, or logs.
Generated connectors receive credentials only from their caller at runtime.

All reverse outputs use `security_verdict: NOT_ASSESSED` and remain outside the
repository audit evidence bundle. Link Ghidra, Frida, and web observations only
by their digests and explicit correlation metadata; never claim that nearby
timestamps prove the same logical operation.
