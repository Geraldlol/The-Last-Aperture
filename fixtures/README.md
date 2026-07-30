# `fixtures/` — the evaluation corpus

**Nothing in this directory runs, and nothing in it is meant to.**

This is how anyone — including the author — finds out whether the `red-team-audit`
skill works. A skill made of ten prose lenses can be graded only against code
whose answer is known in advance, so this directory holds that code and
`EXPECTED.md` holds the answers.

- `vulnerable/` — one file per bug class, each with a stated lens, topic,
  severity and CWE. A lens that does not find its own fixture has a gap, and the
  gap is recorded rather than tuned away.
- `clean/` — code that pattern-matches as vulnerable and is not. These exist
  because a lens that fires on everything is as useless as one that fires on
  nothing, and false-positive rate is not measurable without them.
- `EXPECTED.md` — the manifest, and the per-fixture record of whether the owning
  lens's own sweep or detector actually fires.

## Nothing here is runnable, and that is a hard rule

Every vulnerable fixture demonstrates the **shape** of a defect. None of them
contains a working payload, a live endpoint, a gadget chain, a resolvable
dependency or an entry point.

- No `main()`, no `app.listen`, no server construction, no deploy target. The Go
  fixture has no `main`; the Terraform has no provider or backend; the Apex has
  no `sfdx-project.json` and no `meta.xml`; the workflow is nested under
  `fixtures/` where GitHub Actions never looks.
- Imports point at packages this repository does not vendor, so the files do not
  even compile in place.
- Where a fixture would need an exploit to be interesting — the deserialization
  sink, for instance — the exploit is deliberately **not written**. The sink is
  the finding; building the gadget chain would make this repository a malware
  sample and would teach the reader nothing the sink does not.

## No realistic credentials, for two reasons

Every credential-shaped string in this corpus is **structurally invalid**: wrong
length, wrong character class, wrong encoding, or a placeholder that states its
own invalidity (`REPLACE-ME-BEFORE-ANY-USE`, `placeholder-not-a-key`, forty
zeroes where a commit digest goes).

The first reason is obvious: a real secret in a public repository is an incident.

The second is the one people miss, and it cuts the other way. **A
secret-scanner-shaped string is itself a hazard.** A fixture containing a
well-formed provider token trips every scanner that ever looks at the repository,
forever, and each alert costs a human a triage cycle to close as "test data" —
which is also exactly what a real leaked key looks like when it is dismissed. So
the strings here are shaped to be *unmatchable* by a secret scanner, not merely
fake. `EXPECTED.md` records the cost of that choice honestly: it makes one
detection path untestable, and it says which one.

## Written from scratch

Not reduced from real code — not from this repository, not from any product, not
from any customer. Every file was written for this corpus, which is why each one
carries exactly one defect and a header saying which. Code reduced from a real
system carries the rest of that system with it: its structure, its naming, its
residue, and sometimes its actual bug.

## Scanner noise

`.gitattributes` marks `fixtures/**` as `linguist-vendored`, which keeps the
corpus out of language statistics and out of GitHub's rendered diffs and
code-search results by default. That is the limit of what a `.gitattributes` can
express.

**It does not suppress a code scanner.** CodeQL, Semgrep, Snyk and Dependabot
each read their own configuration. Anyone wiring one of those into this
repository must exclude `fixtures/**` there too, or the scanner will report the
purpose-built vulnerable cases as true positives and drown every real finding
in the repository.

## Adding a fixture

1. One bug class per file. If it needs two defects to be interesting, it is two
   fixtures or it is a chain fixture, and a chain fixture says so.
2. Name the owning lens, its topic slug, the expected severity and the CWE in a
   header comment, and add the row to `EXPECTED.md`.
3. Extract the sweep or detector from that lens and run it against the file.
   Record what happened — including "it did not fire". **Do not adjust the fixture
   to make a lens look good.** A fixture quietly tuned until it matches measures
   nothing; a fixture the lens misses is the most valuable row in the table.
4. Keep it inert. If you can run it, it does not belong here.
