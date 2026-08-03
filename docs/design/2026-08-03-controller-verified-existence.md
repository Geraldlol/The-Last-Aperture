# Controller-verified existence

- Status: Proposed
- Date: 2026-08-03
- Owners: Red Team Audit platform
- Extends: ADR 0001 (executable audit platform), ADR 0003 (deterministic coverage closure)

## The gap

A finding names a location and quotes evidence. On the manual ingest path the
controller checks three things about that location and stops:

```
job-protocol.mjs:388  ensureFindingLocations
  - the cited path is in run.coverage.inventory
  - the cited path is inside the job's scope
  - the cited path was reported examined
```

It never opens the file. The line number is unchecked and the quoted evidence is
unchecked. `source_anchors` — the field that would bind a finding to exact bytes —
is optional in `finding.schema.json`, and `assertBoundSourceAnchors` is reached
only from `assertObservedSourceAnchors` (sealed Docker runner) and
`assertRemoteSourceAnchors` (signed gateway). Neither runs on `ingest`.

`existence_check` is free text the provider writes about itself: *"located —
src/routes/invoices.ts:88 read; the quoted line is present verbatim"*. The
platform that refuses to accept a provider's word on coverage authority accepts
it without challenge on whether the cited code exists.

### What the corpus shows

Measured against `peerstar-audit-run/run_2026-08-02T22-39-37-802Z_39ed224a0cbd`,
31 findings, schema 6.0.0:

| Property | Count |
|---|---:|
| findings carrying `source_anchors` | 0 / 31 |
| findings carrying `existence_check` | 0 / 31 |

And `evidence` is prose, not quoted code:

> `cand:cicd:002` — "The npm entries list 13 directory patterns including the
> /react-apps/* glob, but /apploi-mcp, /chart-audit-react, /hours-funnel-react
> and /rd-scorecard-react match none of them."

`_schema.md:146` already forbids exactly this: *"A paraphrase is not evidence —
it is the reader having to take the auditor's word for the thing most worth
checking, and it is where a hallucinated finding hides."* Nothing enforces it.

This is the failure class the field notes recorded after the PeerStar run: *"The
fan-out is good at locating defects and unreliable about their details."* Two
file labels inverted so a fix would have landed on the already-correct file. A
helper claimed absent that exists three files over.

### Why the fix is cheap

`ingest` already calls `verifyRepositorySnapshot` (`audit.mjs:2056`), which
re-inventories `run.repository.root` and throws unless the full security view —
tree digest, entries, errors, limits — is byte-identical to the committed
snapshot.

It costs nothing beyond that. `inventory.mjs:521` decodes every non-binary file
during that pass (`const content = binary ? null : bytes.toString('utf8')`) and
holds it on the entry; `serializeInventory` strips `content` and `absolutePath`
only when writing to disk. So by the time a finding is applied, **the controller
already holds in memory the decoded text of every text file in the target, read
under handle-bound no-follow semantics and proven unchanged since planning.**

Quote matching and absence search are therefore pure in-memory operations over
data already loaded and already hashed: no second read, no extra I/O, no
time-of-check/time-of-use window, and no dependency on a sealed snapshot. The
only plumbing required is to stop discarding that live inventory —
`verifyRepositorySnapshot` currently computes it, compares it, and returns only
`control`.

## Design

Three parts: a provider claim the provider can actually produce, a
controller-derived verdict the provider cannot forge, and a gate that is off
until you have seen the numbers.

### 1. `quotes` — a machine-checkable provider claim

New Stage-One field on a finding. `evidence` keeps its prose role; `quotes`
carries the verbatim span.

```json
"quotes": [
  {
    "path": "meetingbot/infra/modules/postgres.bicep",
    "line": 27,
    "text": "publicNetworkAccess: 'Enabled'"
  }
]
```

- `path` must already appear among the paths in `location`. No new scope surface.
- `line` is the provider's claimed 1-based line. For a multi-line quote it is the
  line of the quote's **first** line.
- `text` is verbatim and may span lines.

The field is optional and bounded at 32 quotes per finding, each at most 4 KiB of
text. It is a Stage-One claim field, immutable across transitions like `evidence`.

The provider supplies a path, a line, and text it is reading off the screen.
It computes no offsets and no digests — an LLM cannot do either reliably, which
is why requiring provider-supplied `source_anchors` was rejected.

### 2. `absence_claims` — the mirror for "X is not there"

A quote matcher cannot check an absence, and absence is where the sharpest
PeerStar error landed: *"TwilioInboundReceiver.cls does define
constantTimeEquals (line 446). The crypto auditor said it did not."*

```json
"absence_claims": [
  {
    "pattern": "constantTimeEquals",
    "kind": "literal",
    "scope": ["force-app/main/default/classes"]
  }
]
```

- `kind` is `literal` or `literal_ci`. **`regex` is deliberately excluded** —
  Node's `RegExp` backtracks, and a provider-supplied pattern run across a whole
  inventory is a ReDoS surface inside the controller. Token absences
  (`WITH SECURITY_ENFORCED`, `EncryptedText`, `constantTimeEquals`) are literal
  in practice. Regex can be added later behind a bounded engine.
- `scope` entries are inventory-relative file or directory paths and must fall
  inside the job's scope. An empty `scope` is a schema error — an unscoped
  absence claim is not checkable against a sharded run.

Also optional, also a Stage-One claim field, bounded at 16 claims per finding
with patterns of at most 512 bytes.

### 3. `run.existence_verifications` — the controller's verdict

Controller-owned, computed at ingest, **re-derived during `validate`**. It does
not live on the finding: `source_anchors` and every other claim field is in
`STAGE_ONE_FIELDS` (`contracts.mjs:107`) and therefore immutable across
transitions, so stamping a derived verdict onto a finding would break
`isExactStageOneReplay` on closure retries. Keeping provider claims and
controller facts in separate structures is the pattern `database_discovery`,
`coverage` and `store_profiles` already follow.

```json
{
  "candidate_id": "cand:cloud-and-iac:001",
  "quote_results": [
    {
      "index": 0,
      "outcome": "LOCATED",
      "file_id": "file_<sha256>",
      "claimed_line": 27,
      "found_line": 27,
      "match_count": 1,
      "start_byte": 812,
      "end_byte": 843,
      "excerpt_sha256": "<sha256>"
    }
  ],
  "absence_results": [
    { "index": 0, "outcome": "ABSENCE_HOLDS", "match_count": 0, "searched_files": 214 }
  ],
  "outcome": "VERIFIED"
}
```

Per quote: `LOCATED`, `LOCATED_OFF_LINE`, `NOT_LOCATED`. `found_line` is the line
of the first matched line, in the same frame of reference as `claimed_line`.

Per absence claim: `ABSENCE_HOLDS`, `ABSENCE_CONTRADICTED`, `ABSENCE_UNCHECKABLE`.
A contradiction carries `match_count` in full plus the first 16 hits as
`{path, line}`, ordered canonically, so the record stays bounded on a pattern
that hits everywhere.

`ABSENCE_UNCHECKABLE` is load-bearing and covers `searched_files == 0`. A
mistyped or since-moved scope path matches no inventory entry, and reporting that
as `ABSENCE_HOLDS` would manufacture a clean result out of a search that ran
against nothing — the precise inversion this design exists to prevent, and the
rule already stated at `_harness.md:11`: *"A sweep that finds nothing and a sweep
that ran against nothing look identical."* An uncheckable claim counts as
`UNVERIFIED` at the finding level.

Finding-level `outcome`:

| Outcome | Meaning |
|---|---|
| `VERIFIED` | every quote located at its claimed line, every absence claim holds |
| `DRIFTED` | every quote located, at least one at a different line |
| `UNVERIFIED` | at least one quote not located, or at least one absence contradicted or uncheckable |
| `NOT_APPLICABLE` | the finding carries neither quotes nor absence claims |

`start_byte`/`end_byte`/`excerpt_sha256` are exactly the existing `sourceAnchor`
shape, so manual mode converges on the same anchor representation the sealed and
remote paths already verify. One anchor model, controller-derived here and
adapter-supplied there.

### 4. The matcher

Per-line trimmed, contiguous. Applied to both the quote and the candidate file:

1. Take the inventory entry's already-decoded `content`. Binary entries carry
   `content: null` and `kind: "binary"` and are never candidates, so no encoding
   fallback is needed here — the inventory has already made that call.
2. Split on `\r\n`, `\n`, or `\r`.
3. Trim leading and trailing horizontal whitespace (space, tab) from each line.
4. Drop wholly empty leading and trailing lines from the quote.
5. Require the quote's normalized line sequence to appear as a **contiguous** run
   of the file's normalized lines.

A quote that normalizes to nothing is a schema error, not a match. Where a quote
matches more than once, the occurrence nearest `claimed_line` is recorded along
with `match_count`.

This tolerates the re-indentation agents routinely introduce while still
demanding the real tokens in the real order, contiguously. Exact-byte matching
was rejected because it would reject correct findings often enough that providers
would stop quoting real code; whitespace-stripped token matching was rejected
because it can match across unrelated lines and would let a plausible fabricated
quote pass.

Byte offsets are mapped back from the match: `start_byte` at the first
non-whitespace character of the first matched line, `end_byte` after the last
non-whitespace character of the last. The span is real even though the match was
normalized.

### 5. Absence search

Literal search over the controller's own inventory entries, restricted to the
claim's `scope` and to entries the inventory already classified `kind: "text"` —
binary entries are neither searched nor counted, and `searched_files` reports the
number actually searched so a scope that matched nothing is visible rather than
indistinguishable from a clean result. Bounded by the inventory ceilings already
in force. A hit contradicts the claim and records where.

### 6. `--require-verified-existence`

An opt-in gate mirroring `--require-source-closure`, and mirroring it precisely:
that flag is set at **`plan`** time (`audit.mjs:270`), recorded immutably in the
run as `coverage.closure.required_source_closure`, and enforced inside
`buildFinalizedRun` (`job-protocol.mjs:1613`). This gate follows the same shape —
a `plan` flag, a recorded policy field, enforcement at finalization.

Plan-time matters. A finalize-time flag is omitted by whoever runs finalize; a
plan-time policy is bound into the run and cannot be dropped later by the party
whose work it constrains.

Off by default. It refuses finalization while any active finding's outcome is
`UNVERIFIED` **or `NOT_APPLICABLE`**.

`NOT_APPLICABLE` has to fail the gate, or the gate is trivially bypassed: a
provider that simply omits `quotes` offers nothing to check, lands at
`NOT_APPLICABLE`, and sails through a flag named for requiring verified
existence. Under the gate, a finding that supplies nothing checkable is not
finalizable. Without the gate it is merely reported as such.

That is also why the gate is opt-in rather than default. Every finding in the
current corpus lands at `NOT_APPLICABLE` on day one, because none carries quotes,
so a default-on gate would refuse to finalize any existing run. The verdict is
computed and reported from the start; the gate waits until a fresh run has shown
the real pass rate.

### 7. Report

- Executive summary gains `### Existence verification`: counts by outcome, and a
  table of `UNVERIFIED` findings with the reason.
- Each finding shows the controller verdict beside the provider's
  `existence_check`.
- **Contradictions are listed separately.** Where a provider wrote an
  `existence_check` claiming `located` and the controller returns `NOT_LOCATED`,
  that is a provider-integrity signal, not a data-quality note. This is the
  property that makes the feature more than a lint: it measures whether a
  provider's self-attestations are true.

### 8. Schema 7.0.0

`run.schema.json` is `additionalProperties: false` and its `schema_version` enum
caps at `6.0.0`, so a new top-level `existence_verifications` key requires a
version bump. Existing 6.0.0 runs stay readable; the new key is produced only for
7.0.0 runs.

### 9. Re-derivation during `validate`

`validate` recomputes every verdict and fails closed on mismatch, the same
principle as coverage and store synthesis. This is what makes a verdict
non-forgeable: an actor editing `run.json` to flip `UNVERIFIED` to `VERIFIED` is
caught when the controller re-runs the match.

Historical bundles need care. Where the target root is absent, or present but no
longer matching its tree digest, verdicts are re-derived from the sealed source
snapshot if one exists. Where neither is available the block is reported
`NOT_REDERIVABLE` — never silently trusted.

### 10. Relationship to `proof-existence` jobs

`proofExistenceJobs` (`job-protocol.mjs:1151`) dispatches an existence check to a
provider, which self-reports the answer. The controller verdict is authoritative
for its own narrow question — is the quoted text at the cited location, does the
claimed-absent token appear — and needs no job, no round-trip, and no trust. The
job kind stays for what the controller cannot decide. Where the controller
returns `NOT_LOCATED`, invariant 14's consequence (`NOT_REPRODUCED`) is applied
by the gate, visibly, rather than silently.

## Constraints

- `skills/red-team-audit/SKILL.md` is **7,995 of 8,000 bytes**. All prose
  documentation goes to `_schema.md` and `_harness.md`.
- Lint gates R1–R8, slug ownership at 174 slugs, `gen --check` and
  `gen:benchmarks --check` must stay green.
- Baseline before this work: **778 tests, 775 pass, 1 skipped, 2 failing**. The
  two failures are environmental — `cloud-iac-fixtures.test.mjs` needs ripgrep
  and this machine has none. They are not to be counted as regressions.

## Testing

**Matcher units.** CRLF and CR line endings; re-indented quote; tabs against
spaces; multi-line quote; correct content at a wrong line; fabricated content;
multiple matches; quote that normalizes to nothing; invalid UTF-8 falling back to
latin1.

**Absence units.** Hit; no hit; scope restriction excluding a file that would
otherwise hit; `literal_ci` matching a differently-cased occurrence; a scope path
matching zero inventory entries yielding `ABSENCE_UNCHECKABLE` and never
`ABSENCE_HOLDS`; a scope containing only binary entries yielding the same.

**Ingest integration.** Correct quote yields `VERIFIED`; fabricated quote yields
`UNVERIFIED`; re-indented quote yields `VERIFIED`; correct content at a wrong
line yields `DRIFTED` and records both lines.

**Gate integration.** A run planned with `--require-verified-existence` refuses
to finalize while one finding is `UNVERIFIED`, and succeeds once it is not. It
also refuses a finding at `NOT_APPLICABLE`, so omitting `quotes` cannot buy
passage. A run planned without the flag finalizes in both cases and reports the
outcome.

**Forgery.** A hand-edited verdict in `run.json` fails `validate`.

**Backward compatibility.** The 31-finding PeerStar corpus ingests unchanged
under 7.0.0, every finding landing at `NOT_APPLICABLE`, and finalizes normally
so long as the gate is not requested.

## Acceptance

A finding that quotes real code at the line it cites reports `VERIFIED` without
the provider computing an offset or a digest. The same finding with one
identifier altered in the quote reports `UNVERIFIED`, and
`finalize --require-verified-existence` refuses to close the run. A finding
claiming a token is absent from a directory where the controller finds it reports
`ABSENCE_CONTRADICTED`, naming the file and line. Every verdict survives
re-derivation under `validate`, and every verdict in a hand-edited `run.json`
does not.

## Not in this design

Making `evidence` itself verbatim, or enforcing `_schema.md:146` directly.
`quotes` gives that rule a machine-checkable home; tightening the prose field is
a separate decision with a separate blast radius.

`regex` absence claims. Excluded above on ReDoS grounds.

Retiring the `proof-existence` job kind. The controller verdict makes it
redundant for findings that carry quotes, but retiring it is a separate change
against a different set of tests.
