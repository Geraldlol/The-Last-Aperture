# ADR 0026: Bounded reverse engineering and protocol reconstruction

Date: 2026-09-11
Status: Accepted for this implementation slice

Amended by ADR 0027. Its Windows Ghidra, broader Frida targeting, active Chrome
bridge, public adaptive-discovery, and operational generated-connector decisions
supersede the narrower release statements recorded below.

## Context

Some operator-authorized web applications expose the data and operations needed
for an ecosystem integration only through browser-facing or otherwise internal
endpoints. A useful integration workflow must recover more than a list of URLs.
It must describe authentication as a sequence, preserve redirect and cookie
transitions, separate reads from writes, capture pagination and retry behavior,
and define how a write is verified.

The Credible integration provides the relevant design pattern: canonical
token-free endpoint records; an ordered priming, login, session-transfer, and
cookie-establishment flow; strict allowlisting before credentials follow a
response-supplied destination; per-origin cookie state; and writes implemented
as read, guarded mutation, submit, and read-back verification. Copying a browser
request or treating a 2xx response as application success is insufficient.

The repository previously had source review and bounded HTTP controllers, but no
standalone contract for native static/dynamic observations or offline web
session reconstruction. Adding those observations directly to the audit bundle
would overstate their meaning: an observed call, path, or response shape is not
a vulnerability finding or proof that a connector is correct.

## Decision

Add a separate `last-aperture-reverse` workflow with three evidence inputs, one
observed integration contract, and an offline generator for a runnable,
contract-bound Node connector.

### Native reverse profiles

The Ghidra profile `ghidra-headless-fixed-export-v1` statically imports one
staged native executable, shared library, or firmware image. It runs the bundled
Java post-script through Ghidra's documented
[`analyzeHeadless`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md)
interface with a fixed read-only, delete-project, CPU, timeout, script, and log
argument vector. The current export includes bounded program and function
metadata, supported network API matches, reference kinds and source offsets,
call-site offsets, sanitized static endpoint candidates, and authentication
hints. It does not execute the target, retain raw scanned strings or payloads,
or claim decompilation, reachability, endpoint behavior, or an auth flow.

Native Ghidra launchers are invoked directly. On Windows, `.bat` and `.cmd`
launchers, including stock `analyzeHeadless.bat`, run through the bundled fixed
bridge and a PowerShell Job Object with kill-on-close supervision. The bridge
receives only the controller-built argument vector in a sanitized environment;
it does not interpolate caller command text. Combined output and Ghidra logs
remain bounded, and accepted evidence requires confirmed process-tree cleanup.

The legacy Frida profile `native-call-trace-v1` uses Frida's
[`Interceptor`](https://frida.re/docs/javascript-api/#interceptor) through one
bundled agent. It spawns the exact native executable from the local lab, selects
one named export in one named module, and records bounded enter/leave events,
thread IDs, timestamps, readiness, an opaque module-relative symbol offset, and
truncation. The offset is metadata rather than a stable address or semantic
claim. The profile does not retain arguments, returns, memory, payloads, or
credentials.

The `native-call-trace-v2` plan adds multiple hooks; export, module-offset,
absolute-address, and unambiguous module debug-symbol resolution; and local
spawn, local PID/name attach, USB PID/name/application attach, or explicit-device
PID/name/application attach. A hook may capture declared arguments on entry or
exit and its return value as bounded pointer, signed or unsigned integer,
boolean, UTF-8, UTF-16, or byte data. Each capture declares raw, SHA-256, or
metadata retention, and all frames are reconciled against event, record,
per-frame, aggregate-byte, duration, and output budgets. Raw byte and string
captures are base64 values and can contain credentials or application data, so
the plan and output require the same sensitive-material handling as the target.

Both profiles use bundled agents and controller-built arguments. They do not
accept caller scripts, evaluation strings, raw Frida arguments, arbitrary target
arguments, remote-server tokens, or automatic privilege, `frida-server`, ptrace,
code-signing, or SIP changes. Local spawn evidence can be `SUCCEEDED` only after
complete lifecycle and cleanup reconciliation. Attach and device evidence is
always `PARTIAL` because the supplied local artifact copy does not prove which
bytes the existing runtime loaded.

All native profiles hash the supplied artifact and bind the tool invocation,
limits, timestamps, status, gaps, and cleanup into `reverse-evidence-v1`. Ghidra
records `target_execution: NOT_PERFORMED`; Frida records the exact local-spawn,
local-attach, USB-attach, or explicit-device-attach execution class.

### Offline web-session evidence

`web-session-evidence-v1` is built by importing an operator-provided HAR offline.
The importer makes no target request and accepts only entries on explicitly
declared canonical origins. It retains protocol structure and order: methods,
origins, templated paths, field/header/cookie names, credential carrier
locations, content types and formats, coarse body sizes, inferred types,
statuses, timings, in-scope redirects, and source/observation digests.

It removes raw URL values, header values, cookie values, raw bodies, and general
   body/response values. It also masks obvious value-shaped protocol names and
   replaces common identifier-like path segments. For a
narrow set of action-naming fields, a short value is reduced to
   `WRITE_ACTION`, `READ_ACTION`, or `OTHER_ACTION`; the original value is not
   retained. An absolute or relative HTTP(S) response-field value can contribute only its field
path, explicitly in-scope origin, templated path, and query parameter names.
Unknown and off-scope destinations are omitted, and the raw URL is removed. The
source HAR is neither rewritten nor deleted and remains sensitive. Unknown
textual path segments are masked; only built-in structural route words,
version segments, placeholders, and explicit operator-reviewed path literals
are retained. Synthetic captures are required for PHI-minimizing use; field,
header, cookie, and approved path-literal names still require human review.

### Native interaction contract

`native-interaction-contract-v1` combines validated web evidence and optional
native reverse evidence by canonical digest. Endpoints are currently derived
only from HAR observations and carry `discovered_via: WEB_HAR`. Native evidence
is provenance-linked but not automatically correlated to endpoint call sites or
time windows.

The builder aggregates endpoint shapes, statuses, credential carriers, cookie
transitions, redirects, pagination indicators, retry sequences, and later reads
of the same path template. Each endpoint also retains bounded per-observation
exchanges that bind the evidence reference, capture and sequence to the exact
request action, action basis, request credential carriers, response status,
response credential carriers, and response destinations. Each side-effect
assessment is `READ_CANDIDATE`, `WRITE_CANDIDATE`, or `UNKNOWN`. It uses auth
paths and value-redacted semantic action classes before using conventional
mutation methods as write candidates. This allows a GET-shaped semantic action
to become `WRITE_CANDIDATE`; a passive method without a read-action signal
remains `UNKNOWN`.

Authentication is represented as ordered steps with separate request actions and
response facets. A step can therefore record credential submission and an
observed response credential-carrier location at the same time.
`CREDENTIAL_CARRIER_OBSERVED` does not prove that a session was established or
that authentication succeeded. Credential and cookie values are absent; only
their carrier or cookie names remain.

All redacted response destination candidates are retained. Redirect correlation
is bounded to the next three observations in the same capture and is emitted only
for one unique candidate/observation match with an exact, untemplated origin and
path. A destination or request path containing a redaction placeholder remains
unlinked because path-template equality cannot establish equality of the removed
concrete segments. Ambiguity and redacted paths are reported as gaps. The builder
does not infer a cross-capture transition or choose a live destination.

Pagination is an observation based on recognized parameter names. Retry is an
observation of a repeated endpoint after a 429 or 5xx.
`FOLLOWUP_READ_SAME_TEMPLATE_OBSERVED` means only that a later GET or HEAD used
the same path template after a `WRITE_CANDIDATE`. It does not prove record
identity or a state change. None of these states proves server semantics. Every
contract remains `DRAFT_OBSERVED`, `CONTRACT_ONLY`, and `NOT_ASSESSED`, with
gaps requiring operator review, multiple-session comparison, native correlation,
and explicit write success, failure, rollback, and verification predicates.

### Generated connector runtime

`protocol generate` strictly validates a `native-interaction-contract-v1` and
projects it into a deterministic Node package labeled `GENERATED_REVIEWABLE`.
The package manifest binds the canonical source-contract digest, generated file
digests, and aggregate content digest. Generation is offline and writes only to
a new output directory.

The runtime accepts endpoint IDs rather than caller URLs or methods. It fills
templated path segments from caller values, accepts only observed query and body
field shapes, supports safe headers and observed content types, and returns
parsed response data. Response cookies stay in per-origin in-memory jars.
Redirects must match an observed source destination and exactly one contract
endpoint; retries occur only for an endpoint with observed retry evidence. A
credential-provider callback can supply declared header, cookie, or body
carriers per attempt, and the runtime never writes those values.
`protocol verify` gives the caller-retained manifest digest an operational
verification path: it checks the exact generated inventory and each file digest
without importing the generated code or contacting a target.

### Browser-held validation and adaptive expansion

The packaged Chrome companion can use the authenticated campaign bridge to
execute sealed same-origin requests in the operator-selected tab. When the
scope enables discovery, response-derived candidates can extend the campaign
inside its origin, path, method, category, substitution, action, depth, and
candidate budgets. Each candidate receives the same immediate scope,
authorization, ledger, and stop checks as an initially sealed action. Generated
connectors remain a separate runtime library, but the bridge and adaptive
controller can validate additional observed operations before the contract is
rebuilt and regenerated.

The operator's explicit reverse invocation directs work for artifacts and
captures within their authority. Connector generation performs no network I/O;
the consuming application initiates each later contract-bound runtime request.

## Alternatives considered

### Generate a client directly from unvalidated HAR bytes

Rejected. Direct generation would invite credentials and data values into code
and skip canonical shape and identity validation. The accepted generator reads
only the validated, value-redacted contract and digest-binds its projection.

### Replay the HAR to discover more endpoints

Rejected. HAR replay would turn an offline redaction step into live authenticated
execution, repeat writes, and send stale credentials or person-specific data.
Live expansion instead starts from a sealed campaign and admits only bounded,
scope-checked candidates from current response structure. It does not resend
the captured HAR sequence or its stale values.

### Accept arbitrary Ghidra or Frida scripts and arguments

Rejected. Arbitrary scripts and target arguments are general code execution and
make output, side effects, credentials, network access, and cleanup impossible
to characterize as one capability. Add a new reviewed fixed profile when a new
observation is needed.

### Infer side effects from HTTP verbs alone

Rejected. Browser applications commonly encode operations in paths or form
values, and GET endpoints can still mutate state. The classifier combines
multiple observable signals and preserves `UNKNOWN` when they are insufficient.

### Feed reverse observations into audit findings

Rejected. These outputs describe program and protocol shape. They have no
semantic finding oracle and cannot justify a vulnerability verdict or clean
bill of health.

## Consequences and validation

The platform gains a path from owned or operator-authorized application
observations to a reviewable, runnable connector. Authentication steps,
endpoint shapes, redirects, cookie transitions, and write evidence can be used
without retaining secret values in the derived artifacts.

The connector can run observed login and session-bootstrap calls with values
supplied at runtime. The packaged browser bridge supports current-session
validation and scope-bounded response-driven expansion. Ghidra emits sanitized
static endpoint candidates and bounded network references, not a complete call
graph or proven protocol. Frida v1 provides its minimal one-export trace, while
v2 provides typed multi-hook capture and local or device attachment under an
exact plan. Native-to-web correlation and application-specific write semantics
still require explicit evidence. The generated runtime implements destination
allowlists, per-origin cookie isolation, encoding checks, and bounded retries;
consuming code supplies application-specific success, failure, rollback, and
post-read behavior.

Contract tests cover exact argument profiles, output bounds, evidence shapes,
HAR origin filtering and value removal, endpoint aggregation, auth states,
side-effect assessment, pagination, retries, and same-template follow-up-read
labels. Generator tests also cover deterministic output, strict schemas,
file-drift detection against the bundled manifest, credential non-persistence,
and a real loopback login, redirect, cookie transition, and JSON read. A caller
must retain the returned manifest digest as an external anchor to detect a
coordinated rewrite of both files and bundled manifest. No real Ghidra or Frida
conformance session has been completed on the current workstation, so runtime
compatibility and tool cleanup remain unverified until a controlled lab run
produces reviewed evidence.

The new evidence remains separate from existing audit bundles. Removing the
standalone command and contract modules withdraws the feature without migrating
stored audit runs; retained reverse artifacts continue to describe only the
versioned contracts under which they were created.
