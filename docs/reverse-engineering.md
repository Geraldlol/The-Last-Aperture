# Reverse engineering and application interaction contracts

Last Aperture can turn bounded observations from an owned or otherwise
operator-authorized application into a reviewable protocol map. The intended
result is enough structure to implement a native connector when the application
has no supported public API: endpoint templates, request and response shapes,
authentication state transitions, cookie and redirect names, and the evidence
behind each observation.

This workflow produces observations, a draft contract, and an optional runnable
Node connector generated from that contract. It does not export a browser
credential or declare an application secure. Its evidence outputs use
`security_verdict: NOT_ASSESSED` and are not applied to an audit evidence bundle.

## Unified target workflow

`engage run` is the normal entrypoint. It binds the exact operator statement,
target, supplied captures/plans, tool discovery, route grants, results, and later
connector work to one engagement:

```powershell
npm.cmd run audit -- engage run C:\reverse-lab\application.exe `
  --target-kind artifact `
  --attestation-file C:\engagement-inputs\authority.txt `
  --profile full `
  --out C:\engagements\application

npm.cmd run audit -- engage run https://portal.example/app `
  --attestation-file C:\engagement-inputs\authority.txt `
  --profile full `
  --input capture=C:\captures\portal.har `
  --input capture=C:\captures\portal-burp.xml `
  --out C:\engagements\portal
```

The controller runs ready routes in dependency order. `engage resume` can
unblock only host availability for a tool or adapter already named by the
engagement; the original authority remains bound and is not requested again.
The intake, capture list, and credential references are immutable. If an input,
capture, or credential reference was omitted, add it in a successor engagement
instead of trying to extend the existing one. A selected-tab attachment is
attempted only after authenticated dispatch. Failure or timeout is a settled
route outcome and is not retried in that engagement. The route-specific
commands below remain useful for direct compatibility and diagnosis.

## Evidence sources

### Ghidra static profile

`ghidra-headless-fixed-export-v1` imports one staged native executable, shared
library, or firmware image into [Ghidra's headless analyzer](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md).
The controller selects the bundled `LastApertureExport.java` post-script and a
fixed argument shape that includes read-only analysis, a per-file timeout, a CPU
limit, bounded logs, and project deletion. Caller-provided scripts, raw Ghidra
arguments, processor overrides, and target execution are outside the profile.

The current exporter records program metadata and a bounded function inventory:
executable format and digest, language and compiler-spec IDs, address bounds,
function names and entry points, external/thunk flags, and body address counts.
It also records bounded matches for supported network APIs, reference kinds and
source offsets, call-site offsets, sanitized static HTTP(S) endpoint candidates,
and authentication hints. Static endpoints retain only scheme, canonical
origin, host, port, a masked path template, query names, bounded source offsets,
and truncation or user-info indicators. The exporter does not retain raw scanned
strings, decompiled bodies, payloads, or credential values, and these candidates
do not prove reachability or application behavior.

```powershell
npm.cmd run audit:reverse -- ghidra analyze `
  --lab-root C:\reverse-lab `
  --binary bin\application.exe `
  --artifact-kind native-executable `
  --ghidra C:\tools\ghidra\support\analyzeHeadless.bat `
  --out C:\reverse-output\ghidra-001
```

The Ghidra launcher must be an absolute local path. Native launchers are invoked
directly without compiling or injecting the compatibility agent; their
`tool.components` bind only the launcher and fixed exporter. On Windows, stock
`.bat` and `.cmd` launchers require `javac.exe` and
`jar.exe` from `JAVA_HOME`, `JDK_HOME`, or `PATH`. The controller copies and
compiles its bundled fixed compatibility agent only inside owned scratch, then
runs the launcher through the fixed bridge inside a kill-on-close Job Object.
It resolves and hashes the exact `javac.exe` and `jar.exe` files before and
after the build, hashes the generated agent JAR before and after analysis, and
records those content digests in `tool.components` and the sealed invocation
digest. Absolute tool paths remain local and are not written to evidence. The
controller validates those inputs, supplies the fixed argument vector
through a sanitized environment, enforces combined build, process-output, and
Ghidra-log budgets, and confirms tree termination before accepting evidence. It
never interpolates a caller command line or enables a general shell-execution
route.

Content-addressed Ghidra evidence emits reverse-evidence schema `1.1.0` and
requires `tool.components`. The reader continues to accept legacy `1.0.0`
evidence without that field; `1.0.0` cannot be used to carry the new provenance.

### Frida call-trace profiles

`native-call-trace-v1` remains the minimal local-spawn profile. It starts one
exact native executable from the declared lab root under the
[Frida JavaScript API](https://frida.re/docs/javascript-api/), attaches the
bundled agent to one named exported symbol in one named module, and records
readiness, enter/leave sequence, thread ID, observation time, an opaque
module-relative offset, and event truncation. It does not capture arguments,
returns, or memory.

```powershell
npm.cmd run audit:reverse -- frida trace `
  --lab-root C:\reverse-lab `
  --binary bin\application.exe `
  --frida C:\tools\frida.exe `
  --module application.exe `
  --symbol send_request `
  --out C:\reverse-output\frida-001
```

`native-call-trace-v2` accepts a strict JSON plan through `frida trace-plan`.
It supports multiple hooks resolved by export, module-relative offset, absolute
address, or one unambiguous module debug symbol. The target can be a local
spawn, local PID/name attach, USB PID/name/application attach, or
explicit-device PID/name/application attach. The controller maps those choices
to exact Frida `-f`, `-p`, `-n`, or `-N` selectors with `-U` or `-D`; it does not
accept caller-provided Frida arguments.

A hook can capture declared arguments on entry or exit and its return value as
pointer metadata, signed or unsigned integers, booleans, UTF-8, UTF-16, or
bytes. Memory lengths are fixed or derived from a declared argument and capped
by descriptor, frame, session-byte, record, event, duration, and process-output
budgets. Retention is declared per capture: `raw` stores string and byte data as
base64, `sha256` stores a digest, and `metadata` stores no value. Read failures,
truncation reasons, lifecycle order, call pairing, and aggregate counters are
validated before evidence is accepted.

```powershell
npm.cmd run audit:reverse -- frida trace-plan `
  --plan C:\reverse-plans\portal-trace.json `
  --frida C:\tools\frida.exe `
  --out C:\reverse-output\frida-typed-001
```

The plan schema is `schemas/frida-trace-plan.schema.json`. Both profiles use
only their bundled agent, quiet mode, bounded execution, and supervised cleanup.
They do not accept caller scripts, evaluation strings, arbitrary target
arguments, remote-host tokens, or automatic `frida-server`, privilege, ptrace,
code-signing, or SIP changes. Frida executes or attaches to native code, so use
a suitable lab and treat raw capture output as sensitive: declared payloads may
contain credentials or application data.

All native controllers hash the supplied artifact and bundled script immediately
before and after execution and discard observations on drift. The exact bytes
are digest-bound; `tool.version` remains `null` because the profiles do not run a
separate version probe, and the evidence records that gap. V2 local-spawn
evidence can be `SUCCEEDED` only when hooks, captures, counters, lifecycle, and
cleanup are complete. Existing-process and device attachment remains `PARTIAL`
with `RUNTIME_ARTIFACT_IDENTITY_UNVERIFIED`, because a supplied local copy cannot
prove the bytes loaded by that runtime.

### Verified live metadata import

`web import-live-metadata` is an offline projection over an already verified
HTTP reconnaissance bundle and, optionally, the exact scope and append-only
ledger from an authenticated campaign. The import itself sends no target
request and acquires no browser credential:

```powershell
npm.cmd run audit:reverse -- web import-live-metadata `
  --recon-bundle C:\engagements\portal\routes\https-recon\http-recon `
  --auth-scope C:\engagements\portal\routes\authenticated-http-browser\scopes\scope.json `
  --auth-ledger C:\engagements\portal\routes\authenticated-http-browser\campaign-ledger `
  --origin https://portal.example `
  --path-prefix /app `
  --path-literal app `
  --out C:\reverse-output\live-metadata-001 `
  --json
```

The reconnaissance projection contributes the verified method, URL, response
status, response-header names, observation time, timing, and a coarse response
body-size bucket. Its source SHA-256 binds the verified reconnaissance document,
including the bounded response hash metadata recorded there. Header and body
values, response-field shape, and redirect semantics are not projected into
the web-session evidence.

The optional authenticated projection considers only settled probe seeds whose
campaign-ledger provenance is exactly `SEALED_PLAN`. It retains that sealed
method/URL seed and settled response status. A request-header credential carrier
is present only when the sealed page-session adapter explicitly named that
carrier. It does not import response-discovered candidates or ambient browser
credential names or values.

These `HTTP_RECON` and `HTTP_AUTHED_CAMPAIGN` records are metadata-only evidence.
They do not establish a complete authentication flow, a response-discovered
endpoint inventory, write behavior or success, replay safety, pagination,
coverage, or credential availability. Each output carries an explicit
metadata-only gap and remains `security_verdict: NOT_ASSESSED`.

Historical authenticated import verifies the scope structure, its digest
bindings, and the matching append-only campaign ledger without requiring the
scope validity window to remain current. This allows offline import after
expiry; it does not renew authority or authorize target I/O. Any live campaign
dispatch still requires the scope to be current at the dispatch boundary.

### Offline HAR and Burp HTTP-items import

The web profile imports a HAR file or Burp Suite Save Items XML already captured
by the operator. Both routes are offline: they read one local file and perform
no browser automation, login, replay, or target request. Every retained request
must match one of the explicit canonical HTTP or HTTPS origins. Entries for
other origins are counted and omitted.

```powershell
npm.cmd run audit:reverse -- web import-har `
  --har C:\captures\synthetic-session.har `
  --origin https://app.example `
  --origin https://login.example `
  --path-prefix / `
  --path-literal resources `
  --out C:\reverse-output\web-session-001.json

npm.cmd run audit:reverse -- web import-burp `
  --burp C:\captures\synthetic-saved-items.xml `
  --origin https://app.example `
  --origin https://login.example `
  --path-prefix / `
  --path-literal resources `
  --out C:\reverse-output\web-session-002.json
```

`--path-prefix` is required and filters raw capture URLs before templating;
`/app` admits `/app` and `/app/...` while excluding `/application`. Repeat
`--path-literal` only for operator-reviewed application route segments
that are safe to retain. It is not a declaration that an arbitrary identifier
or record value is public.

The resulting `web-session-evidence-v1` records `source.kind: HAR` or
`source.kind: BURP_XML` and keeps:

New HAR and Burp XML imports emit schema `1.1.0`. The reader retains schema
`1.0.0` compatibility for historical HAR evidence by applying the frozen 1.0
carrier classifier only while validating those records. Current `1.1.0`
evidence must match the current target-neutral carrier derivation exactly; a
Burp source mislabeled as `1.0.0` is rejected.

- the source-file SHA-256, declared origins, stable observation IDs, order,
  timestamps,
  bounded total timings, and malformed/non-HTTP/off-scope counts;
- origin, method, a templated path, query parameter names and inferred types;
- request and response header names, cookie names, and credential carrier
  locations such as `header:authorization`, `cookie:SessionId`, or
  `body:password`. Generic `Cookie` and `Set-Cookie` headers are not credential
  carriers by themselves; only qualified credential-like cookie names are;
- body format, media type, coarse byte bucket, JSON/form field names and paths,
  inferred value types, a sensitive-name flag, a shape status, and an explicit
  field-truncation flag;
- response status and in-scope redirect origin, path template, and parameter
  names; and
- a value-redacted semantic class for fields named `action`, `command`, `event`,
  `method`, `mode`, `op`, `operation`, `submit`, `task`, or `view`. A short
  action-like value becomes `WRITE_ACTION`, `READ_ACTION`, or `OTHER_ACTION`;
  the source value itself is removed; and
- sanitized destination metadata derived from absolute or RFC-relative URL
  references in URL-named JSON response fields. Relative references are
  resolved against the observed request URL. For an explicitly in-scope HTTP(S)
  origin, this keeps only the field path, origin, templated path, and query
  parameter names. Unknown or off-scope destinations are omitted, the raw URL
  is removed, and a per-response flag records destination truncation.

It removes query, header, cookie, body, and response values and raw bodies.
Obvious value-shaped field, query, cookie, and header names are replaced with
fixed placeholders before evidence is written.
Integer, UUID, long hexadecimal, email-like, and opaque path segments are
replaced with typed placeholders. Unknown textual segments become `{segment}`;
only built-in structural route words, version segments, existing placeholders,
and explicitly reviewed `--path-literal` declarations remain literal. The
importer does not modify or delete its source capture, which can still contain
the original secrets and application data. Use synthetic sessions; treat the
source capture as sensitive material. Field, header, cookie, and approved path-literal
names can themselves reveal business or person-specific information, so the
sanitized output still requires review before sharing.

Per-entry arrays and the whole capture have fixed bounds. Body shape status
distinguishes observed structure from a missing body, malformed JSON, and a
body omitted above the 1 MiB inspection limit. `fields_truncated` and
`destinations_truncated` identify structural traversal or item caps, and the
capture repeats each observed omission as a deterministic review gap. The
runtime also rejects evidence above 100,000 aggregate metadata items. The Burp
XML parser additionally refuses declarations/entities, unsupported nesting,
inconsistent URL/request metadata, malformed HTTP messages, and oversized
documents, messages, headers, nodes, fields, or item counts.

### Optional Burp Montoya exporter

`integrations/burp-montoya` is an optional read-only Burp extension. It reads
existing Proxy history through the
[Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/index.html),
uses each item's `finalRequest()`, applies one exact canonical origin, one path
prefix, reviewed path literals, and an item limit, then writes a new sanitized
HAR 1.2 file. It does not invoke Scanner, dispatch traffic, or modify traffic.

Build from the trusted checkout with a caller-supplied local Montoya API JAR;
the build does not download dependencies and supports JDK 17 through 21:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File integrations\burp-montoya\build.ps1 `
  -MontoyaApiJar C:\tools\montoya-api.jar `
  -OutJar C:\reverse-output\last-aperture-burp.jar
```

Load that JAR as a Burp extension, open its **Last Aperture** tab, and export to
a new absolute local `.har` path. The extension removes header, cookie, query,
and body values before writing; it preserves bounded names, methods, statuses,
coarse body sizes, structural content type, and templated paths. Its
`_lastAperture` metadata records the Burp name, version, build, edition,
capabilities, scope, omissions, and `core_evidence_provenance: WEB_HAR`.
Import that output with `web import-har`. Direct Save Items XML uses
`web import-burp` and retains `BURP_XML` provenance.

## Build a native interaction contract

`protocol build` combines one or more web-session, Ghidra, or Frida evidence
files. Either evidence family can stand alone. It verifies each input's
strict contract, records its canonical digest, and emits
`native-interaction-contract-v1`.

New contracts emit schema `1.1.0` and require endpoint and per-exchange source
provenance. The reader accepts the released schema `1.0.0` shape without
rewriting it: every endpoint must retain `discovered_via: ["WEB_HAR"]`, while
its exchanges must omit the later `provenance` field. Historical `1.0.0`
route, action, role, and side-effect fields are checked with the frozen 1.0
classifier. That classifier is never used to build a new `1.1.0` contract;
new contracts use only the current target-neutral rules.

```powershell
npm.cmd run audit:reverse -- protocol build `
  --web-evidence C:\reverse-output\web-session-001.json `
  --web-evidence C:\reverse-output\web-session-002.json `
  --reverse-evidence C:\reverse-output\ghidra-001\evidence.json `
  --out C:\reverse-output\native-interaction-001.json
```

The contract uses a target-neutral interaction pattern: model authentication as
an ordered state machine; keep endpoints token-free;
track credential carriers, per-origin cookie transitions, and redirect targets;
and describe reads and writes with request/response shapes and evidence links.
Connector code can then implement the reviewed state machine with explicit
destination allowlists and per-origin cookie jars instead of copying browser
requests with embedded credentials.

Each endpoint includes its canonical origin, templated path, method, observation
count, request/response fields and content types, statuses, auth carrier and
cookie names, in-scope redirects, pagination evidence, retry evidence,
same-template follow-up-read evidence, and source observation IDs. Its
per-observation exchanges bind each source observation ID to its capture and
sequence, exact request action, action basis, request credential carriers,
response status, response credential carriers, and response destinations. Its
side-effect assessment is one of `READ_CANDIDATE`, `WRITE_CANDIDATE`, or `UNKNOWN`:

1. authentication paths keep `protocol_role: AUTH` and a side-effect assessment
   of `UNKNOWN` with an `AUTH_FLOW` basis;
2. an observed `WRITE_ACTION` semantic class produces `WRITE_CANDIDATE`;
3. conventional mutation methods provide a `WRITE_CANDIDATE` fallback, while a
   passive method without a redacted read-action signal remains `UNKNOWN`; and
4. anything else remains `UNKNOWN`.

Auth-flow steps separate the request action from response transitions. Request
actions include auth requests, credential submissions, token exchanges,
authenticated requests, session termination, and ordinary application requests.
Response facets independently record an observed challenge, credential-carrier
location, or destination. `CREDENTIAL_CARRIER_OBSERVED` means only that the
response exposed a carrier name and location; it does not prove that a session
was established or authentication succeeded. Cookie and credential values never
enter the contract.
All response destination candidates remain visible as redacted structure. A
transition link is inferred only when exactly one candidate matches exactly one
of the next three observations in the same capture by an exact, untemplated
origin and path. Candidates with redacted path placeholders remain visible but
unlinked because the removed concrete segment cannot be compared safely;
ambiguous and redacted candidates create explicit review gaps.

Pagination is reported only when recognized cursor, page, offset, or limit
parameter names were observed. A retry is reported only when the same endpoint
appears again after an observed 429 or 5xx response. For a write, a later GET or
HEAD to the same path records `FOLLOWUP_READ_SAME_TEMPLATE_OBSERVED`; that
sequence is not proof that the same record was read or that the intended state
change succeeded. A native connector still needs record-specific before,
success, failure, rollback, and post-read predicates.

Ghidra and Frida evidence is digest-linked to the contract. The current builder
does not correlate native call sites or time windows to web observations.
Endpoint and per-exchange provenance remains the exact source set: `WEB_HAR`,
`BURP_XML`, `HTTP_RECON`, or `HTTP_AUTHED_CAMPAIGN`. The two live-metadata source
kinds retain the metadata-only limits above; combining them with other evidence
does not fill their omitted auth-flow, response-shape, write, replay,
pagination, or coverage semantics. Static or dynamic evidence therefore cannot
upgrade an inferred web behavior into a confirmed implementation fact.
The contract remains `DRAFT_OBSERVED` with
`generated_client_status: CONTRACT_ONLY` and explicit gaps for operator review,
write semantics, capture variance, and native correlation.

## Generate an ecosystem connector

`protocol generate` validates the complete contract and creates a new,
self-contained Node package without contacting any origin:

```powershell
npm.cmd run audit:reverse -- protocol generate `
  --contract C:\reverse-output\native-interaction-001.json `
  --out C:\reverse-output\application-connector `
  --name @example/application-connector

npm.cmd run audit:reverse -- protocol verify `
  --package C:\reverse-output\application-connector `
  --manifest-sha256 <digest-returned-by-generate>
```

The output directory must not exist. Repeating generation from the same
contract, package name, and Last Aperture runtime template produces identical
files. `manifest.json` binds the package name, source contract ID and canonical
SHA-256, generated file digests, and aggregate content digest. The generated
`connector.json` is labeled `GENERATED_REVIEWABLE` with
`runtime_mode: CONTRACT_BOUND`; it carries the endpoint and auth-flow metadata
derived from the source without carrying the source contract's former
client-generation status.

The generated package exports `createConnector`, `endpointIds`, `authFlows`,
`metadata`, `manifest`, and `contractId`. `connector.request(endpointId,
options)` accepts path placeholder values, observed query names, safe headers,
observed request cookies, and a body matching the observed field paths and
content type. It selects the method, origin, and path template from the
contract, so callers cannot supply an arbitrary URL or method. It returns the
final endpoint ID, contract origin and path template, status, non-credential
response headers, parsed response data, attempt count, redirect count, and
retry count. Concrete URLs are not returned because redirect query values can
carry credentials or application data.

Supply credentials at runtime through an asynchronous callback:

```js
import { createConnector } from '@example/application-connector'

const connector = createConnector({
  credentialReceiver: async ({ credentials }) => retainTokensInMemory(credentials),
  credentialProvider: async ({ endpointId, requestCarriers }) => {
    if (!requestCarriers.includes('header:authorization')) return {}
    return { headers: { authorization: await acquireToken(endpointId) } }
  },
})

const result = await connector.request('endpoint:0123456789abcdef0123456789abcdef', {
  path: { integer: 42 },
  query: { limit: 100 },
})
```

The provider can return only credential locations declared for that endpoint.
Its values are used for the current attempt and are never written by the
connector. JSON response fields declared as credential carriers are replaced by
`null` in ordinary result data; when configured, the credential receiver gets
those values through an explicit in-memory callback so a later provider call
can use them. Observed response cookies stay in an in-memory jar isolated by
origin and can be erased with `clearCookies(origin)` or `clearCookies()`.
Cross-origin redirects drop caller headers and cookies, invoke the credential
provider for the destination endpoint, and must resolve to one observed
destination shape and one contract endpoint. Automatic retries occur only when
the evidence records `RETRY_SEQUENCE_OBSERVED` and the endpoint is classified
`READ_CANDIDATE`; writes and unknown operations are never automatically
retried. Redirect, retry, request-body, response-body, and timeout bounds are
fixed in the runtime, and the timeout remains active while the response body is
read. Any error after the transport is invoked carries
`request_may_have_been_sent: true`; consumers must treat writes and unknown
operations with that flag as ambiguous and must not replay them automatically.

The runtime verifies every generated package file against `manifest.json`
before exposing the client. Preserve the generator result's manifest digest as
the external anchor when moving or reviewing the package, and run `protocol
verify` with that digest before packaging or use. Verification rejects extra,
missing, linked, changed, or digest-mismatched files and performs no network
request.

## Review observed behavior

Review at least two synthetic sessions so variable paths, optional fields, and
cardinality are less likely to be mistaken for constants. Review the generated
connector's endpoint table and authentication state machine, then add
application-specific read and write success predicates in the consuming
integration. A 2xx response is transport evidence, not an application success
predicate.

When live confirmation is needed, the authenticated HTTP campaign can use the
packaged Chrome bridge to send sealed requests in the operator-selected tab.
When discovery is enabled, bounded Link, Location, HTML, JSON, OpenAPI, sitemap,
and Allow projections can add same-origin candidates within the sealed path,
method, category, substitution, depth, candidate, and total-action budgets.
Every candidate is canonicalized and reauthorized immediately before dispatch.
Chrome applies supported browser-managed credentials without exporting their
values. For applications that keep a short-lived string in Web Storage, the
scope may also seal a target-neutral page-session adapter. The descriptor names
one exact `LOCAL` or `SESSION` area and key, `RAW` or strict `JSON_POINTER`
extraction, one lower-case non-routing request-header carrier and optional prefix, exact
HTTPS origin/method/path-prefix constraints, an exact validity interval, and a
maximum value size. The value is acquired anew and applied inside the same
isolated dispatch. Only the adapter and its digest cross the extension worker
and controller; the value does not enter those processes, retained evidence, or
logs. See the [browser bridge guide](../browser/http-authed-chrome/README.md).

That route keeps its own operator statement, origin scope,
mutation permit, ledger, result projection, and stop/cleanup rules; see
[Authorized authenticated HTTP campaign](../README.md#authorized-authenticated-http-campaign)
and [ADR 0016](adr/0016-authenticated-mutation-actions.md). The generated
connector remains a separate runtime library; after validation, rebuild the
contract from reviewed observations before regenerating it.

The generated connector can implement observed login and session bootstrap
through contract endpoint IDs and a credential provider. No credential is
copied from a HAR or Burp capture into generated code, configuration, chat,
argv, evidence, or logs.

## Authorization and evidence boundaries

Run these profiles only for artifacts, applications, accounts, and data within
the operator's declared authority. Connector generation performs no network
I/O; importing and calling the generated package performs the contract-bound
runtime request selected by the application.

`reverse-evidence-v1`, `web-session-evidence-v1`, and
`native-interaction-contract-v1` are standalone evidence classes. They do not
feed findings into `npm.cmd run audit`, confirm a vulnerability, prove endpoint
stability, establish data ownership, or establish the legal basis of a live
integration. Their digests preserve provenance; their labels preserve the
limits of what was observed.

The contract tests exercise controller-built argument vectors, typed Frida
capture parsing and lifecycle, bounded Ghidra export, process supervision,
redaction, connector runtime, and protocol inference rules. Maintainer
validation on 2026-09-11 ran Ghidra 12.1.2 against a 4,096-byte synthetic PE.
The controller exited zero, reported `SUCCEEDED` with four observations, and
verified cleanup; its only gaps were `STATIC_ANALYSIS_ONLY` and
`TOOL_VERSION_UNRECORDED`. The fixture SHA-256 was
`49a35e55808a8f9bf5e658b21cbb7a87af62d98df6344002c2f89080f74fe8aa` and the
content-addressed schema `1.1.0` validation run was
`reverse:971d25da105e844a9966c4350ddb04c0`,
with invocation SHA-256
`1705fcc86ca3b32295c2a35e4f960d6b7dd37fa5bcd38e3174ba68739e968c25` and
evidence SHA-256
`c5629b17d535fd5d9c879284838745aeb112c1a803b225c04a75b7d3de52021d`.
Its seven tool components bind the launcher, exporter, agent source and
manifest, `javac.exe`, `jar.exe`, and the generated compatibility-agent JAR.

The same validation ran official Frida 17.18.0/frida-tools 14.10.4 against a
synthetic local PE fixture: v1 hooked `kernel32.dll!Sleep` with 41 observations,
and v2 hooked `kernel32.dll!GetCurrentProcessId` with 43 observations. Both
controllers reported `SUCCEEDED` with verified cleanup. Burp Suite 2026.8
launcher help/version checks and the Montoya build, mock export, deterministic
HAR, and core-import conformance also passed.

Official Chrome for Testing 153.0.8010.36 loaded and enabled the real unpacked
v0.13.0 extension, Manifest V3 worker, and popup. Exact originless binding,
preview, and attach passed. A full synthetic page-adapter campaign completed one
action with zero failed, rejected, or uncertain actions and seven ledger
records; the server observed one authorized request and no unauthorized request,
and the session value remained browser-side. These fixture results establish
only the tested routes and versions; they do not establish compatibility with
another binary, device, browser profile, Burp project, or application.
