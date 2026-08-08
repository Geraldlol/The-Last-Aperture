# ADR 0012: Locale-independent ordering for attested bytes

- Status: Accepted for the v0.10 build
- Date: 2026-08-01
- Owners: Red Team Audit platform
- Extends: ADR 0001 and ADR 0004

## Context

Every claim this platform makes rests on a digest being reproducible: an
inventory digest, a plan digest, a coverage measurement, a sealed snapshot
index, a signed root attestation. A digest over a sorted collection is only
reproducible if the sort is.

The codebase carried two orderings at once. `compareCanonicalStrings` compares
UTF-16 code units and is a pure function of the strings. Alongside it, 58 call
sites ordered identities with `String.prototype.localeCompare`, which is neither:

- 51 passed `'en'`, which pins the locale but not the collation tables. Those
  ship with ICU, and Node links against system ICU on many builds. A host with a
  different ICU version can order the same inputs differently. A build compiled
  `--without-intl` ignores the locale argument entirely.
- 7 passed no locale at all, so ordering followed the host's default locale.
- Collation is not a total order on distinct strings. It reports `0` for pairs
  separated only by a zero-width joiner, a soft hyphen, or a variation selector.
  `Array.prototype.sort` is stable, so those pairs were ordered by object
  insertion order — that is, by input parse order rather than by content.

Three consequences followed. Digests computed on one host could fail to
reproduce on another, which is indistinguishable from tampering. Two sorted
identity lists compared for equality could differ in order while holding the
same members, rejecting a valid result. And a lower-bound binary search over
sorted paths silently lost its precondition: collation ranks case below the
separator, so `src/x.js` sorts ahead of `SRC/x.js` and the bound for `SRC/`
lands on a non-match. On a case-sensitive filesystem those are different
directories. A brute-force sweep of 200,000 generated path sets returned the
wrong answer 917 times under collation and never under code-unit ordering.

## Decision

One ordering governs every byte the platform hashes, signs, or searches:
`compareCanonicalStrings` from `scripts/lib/canonical-order.mjs`.

Locale collation is confined to `scripts/lib/report.mjs`. Reports are rendered
from an already-sealed bundle and are never themselves attested, so ordering
there is a presentation choice and case-insensitive grouping reads better.

Seven modules define a canonical serializer of their own — `benchmark-contracts`,
`contracts`, `coverage-model`, `database-discovery`, `lifecycle`, `run-engine`,
and `sealed-snapshot`. All seven now order keys by code unit. Six call
`compareCanonicalStrings`; `database-discovery` uses a bare `.sort()`, which for
an array of strings is the same comparison.

`sealed-snapshot` keeps a private, byte-identical copy of the comparator rather
than importing it. That module imports only `node:crypto` by design, so the
seal's trusted computing base stays minimal. The test `run-engine and
sealed-snapshot agree on one canonical ordering` is what holds those two
definitions together; the `localeCompare` ban below covers the rest.

## Consequences

Canonical bytes changed. Re-planning the `fixtures/vulnerable` corpus moved 81
of 155 digest fields, including shard identities — file ordering within a shard
determines shard composition, so the work partition itself shifts.

No released version is affected. The repository carries no tags, `HEAD` is
`0.8.0`, and 0.9 and 0.10 have never been committed. The change lands inside an
unreleased version, so there is no published bundle whose digests it
invalidates and no re-attestation migration to perform. `RUN_SCHEMA_VERSION`
stays at `6.0.0` for that reason: the accepted-version lists it appears in are
capability gates recording unrelated protocol history, and widening them would
assert a compatibility boundary that this change does not cross.

Any bundle produced locally by the uncommitted 0.9 or 0.10 code will not
re-validate and should be re-planned. Runs record `tool.version`, so such a
bundle is identifiable.

## Enforcement

`test/canonical-ordering.test.mjs` holds the invariant:

- canonical serialization orders keys by code unit, and stays fixed under key
  permutation, including for pairs collation calls equal;
- `run-engine` and `sealed-snapshot` produce identical bytes;
- a directory gap stays attributable when a case-variant sibling exists;
- no module outside `report.mjs` mentions `localeCompare`;
- no shipped schema reorders between the two orderings.
