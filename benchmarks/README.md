# Evaluation metrics

The standalone [passive source checker](../docs/passive-source-checks.md) has a
separate 24-case synthetic corpus in `source-check-cases.json`, evaluated with
`npm run evaluate:source-check`. It is not part of the 84-case generated lens
corpus below. Its labels were authored separately from the checker, then used
for development feedback; they are regression data, not independent validation.

This directory defines deterministic scoring primitives for future model-driven
evaluation. It does not call a model and it does not claim a detection rate.
Metrics are meaningful only when accompanied by the corpus name, corpus version,
model and harness configuration, run count, and raw normalized records.

The repository's own fixtures are a development and regression corpus. Results
on them are not evidence of real-world performance because the fixtures and
lenses were authored together.

The current generated corpus contains 84 cases: 32 vulnerable and 52 clean.
Every one of the 18 topic-owning domain lenses has at least one vulnerable and
one clean fixture. The four cross-cutting lenses remain outside the lens-count
denominator because they own no topics; any benchmark exercise of their
normalization, challenge, chaining, or measurement uses the underlying domain
expectations.

`cases.json` is the machine-readable ground truth generated from
[`fixtures/EXPECTED.md`](../fixtures/EXPECTED.md) and
[`fixtures/OWNERSHIP.tsv`](../fixtures/OWNERSHIP.tsv). Every case is bound to one
or more ownership selectors, and generation fails if a selector escapes the
fixture root or matches no file/directory. Regenerate it with
`npm run gen:benchmarks`; CI uses
`npm run gen:benchmarks -- --check` so the denominator cannot silently drift.
Chain fixtures keep one primary topic for recall scoring and list their other
declared topics under `also_acceptable_topics`.

## CLI evaluation envelope

The CLI does not accept a caller-supplied denominator or schema-invalid count.
It loads `cases.json` (or an explicit `--cases` manifest), validates every
canonical finding itself, derives invalid-record debt, and records SHA-256
provenance for the evaluation input, case manifest, and thresholds.
The envelope is defined by
[`schemas/benchmark-input.schema.json`](../schemas/benchmark-input.schema.json).
`primary_run_id` must identify exactly one repeated run, and the normalized
`observedFindings` set must exactly equal that run's normalized finding set.
This prevents capability and stability gates from being assembled from
different observations.

```json
{
  "primary_run_id": "repeat:1",
  "measurement": {
    "model": { "name": "example-model", "version": "pinned-version" },
    "harness": { "name": "example-harness", "version": "1.0.0" },
    "corpus": { "name": "development-regression-fixtures", "version": "1" }
  },
  "observedFindings": [
    {
      "case_id": "V-001",
      "finding": {
        "candidate_id": "authz-object-level:a3f19c2e",
        "...": "a complete final finding record"
      }
    }
  ],
  "caseOutcomes": [],
  "repeatedRuns": [
    {
      "run_id": "repeat:1",
      "findings": [
        {
          "case_id": "V-001",
          "finding": {
            "candidate_id": "authz-object-level:a3f19c2e",
            "...": "the complete final record"
          }
        }
      ]
    }
  ]
}
```

`expectedCases` and `schemaInvalidCount` in a CLI input are rejected. The
lower-level scoring functions below still accept normalized values so test
harnesses can exercise the mathematics independently.

`measurement` is optional for compatibility. When present it requires named,
versioned model, harness, and corpus records; unknown properties are rejected.
Names and versions are limited to 160 characters and reject control characters
and surrounding whitespace. Model and harness records may additionally include
a lowercase SHA-256 `configuration_sha256`; do not put credentials or private
configuration in this metadata. These fields are caller-declared provenance,
not authentication, independent corpus review, or evidence of detection accuracy.
The controller's computed input and case-manifest hashes remain the content
binding even when descriptive metadata is supplied.

Each repeat can declare its own `caseOutcomes`. Legacy top-level outcomes bind
only to the primary run. If both locations declare primary outcomes, their
normalized sets must match. Other repeats never inherit the primary run's
verdicts. Invalid finding counts are derived by the controller separately for
each repeat; an input cannot choose its own invalid-record debt.

Benchmark inputs are bounded before parsing: evaluation JSON is limited to
16 MiB, case manifests to 8 MiB, and threshold files to 1 MiB. One evaluation
may contain at most 4,096 observed findings, 4,096 case outcomes, 64 repeated
runs, and 4,096 findings per repeated run. Case manifests are limited to 4,096
cases and threshold profiles to 256 requirements. The 64-run ceiling bounds
pairwise stability output to 2,016 pairs.

## Normalized inputs

`scoreEvaluation` in `scripts/lib/evaluation.mjs` accepts:

```js
scoreEvaluation({
  expectedCases: [
    {
      case_id: 'V-001',
      expectation: 'vulnerable',
      topic: 'authz-object-level',
      expected_severity: 'High',
      also_acceptable_topics: [],
      must_not_report_topics: [],
    },
    {
      case_id: 'C-001',
      expectation: 'clean',
      topic: 'jwt-jws-and-jwks-verification',
    },
  ],
  observedFindings: [
    {
      case_id: 'V-001',
      candidate_id: 'authz-object-level:a3f19c2e',
      fingerprint: 'optional-stable-run-fingerprint',
      topic: 'authz-object-level',
      effective_severity: 'High',
      triage_disposition: 'queued',
      verification_status: 'CONFIRMED',
    },
  ],
  caseOutcomes: [
    { case_id: 'C-001', verdict: 'clear' },
  ],
  schemaInvalidCount: 0,
})
```

The caller is responsible for parsing a benchmark manifest and validating
finding records against the canonical finding schema. The scorer receives the
number rejected by that validator as `schemaInvalidCount`; it never silently
drops malformed records from the release result.

`caseOutcomes` is optional. Its verdict is one of `finding`, `clear`,
`incomplete`, or `not_assessed`. A vulnerable case explicitly reported `clear`
is a false clear. An ordinary miss remains an FN but is not relabeled a false
clear unless the audit actually claimed a clean result.

Every case additionally has an `assessment_status`. Explicit `finding` or
`clear` verdicts count as `assessed`; `incomplete` and `not_assessed` remain
separate, and no final verdict means `unspecified`, even when a finding exists.
The corresponding `assessed_cases`, `incomplete_cases`, `not_assessed_cases`,
and `unspecified_cases` counts partition the entire case manifest. `abstentions`
counts explicit incomplete or not-assessed outcomes; silence is counted under
unspecified instead of being interpreted as a decision to abstain.

## Metric semantics

The confusion matrix is case-based:

- **TP**: a vulnerable case has a reportable finding on its required topic.
- **FN**: a vulnerable case has no reportable finding on its required topic.
- **FP**: a clean case has one or more findings at Low or above.
- **TN**: a clean case has no findings at Low or above.

These established matrix semantics are unchanged: a TN means no reportable
finding, not that the case was assessed and declared clean. `accuracy` is
`(TP + TN) / cases`; read it alongside assessment coverage. `assessed_accuracy`
counts correct matrix classifications only among cases with explicit assessed
verdicts and is null when that denominator is zero. `assessment_rate`,
`abstention_rate`, and `unspecified_rate` expose how much of the corpus each
measurement covers. A high score on a small assessed subset is not a score for
the unassessed remainder.

Info observations do not count as vulnerability findings. A `dropped`, `merged`,
`DISPROVED`, or `NOT_REPRODUCED` assertion excludes a record only when its triage
or verification authority is authenticated. No such authority is currently
enrolled, so these assertions alone leave the record reportable.

The case matrix keeps TPR and FPR mathematically coherent. It is not allowed to
hide noisy output on a vulnerable case: duplicate primary findings and every
unlisted finding are counted separately under `unexpected_findings`, and
`finding_precision` uses that count. `also_acceptable_topics` prevents an
explicitly allowed secondary observation from becoming precision debt, but it
does not satisfy recall for the primary bug.

Severity accuracy is exact-match accuracy over true-positive cases. The report
also separates overclassification and underclassification. When duplicate
primary findings exist, the highest reported severity is scored; an inflated
duplicate cannot be hidden behind a correctly graded copy.

Per-topic metrics group cases by the expected case topic. This makes the table
diagnostic rather than additive when future manifests intentionally reuse one
case across several separately scored views.

Per-lens metrics group vulnerable cases by their expected authoring lens and
credit a TP only when the selected finding names that lens. A cross-cutting
lens that finds the right domain topic still credits system/topic recall, but
cannot stand in for the expected domain lens's own benchmark gate. The output
publishes `minimum_vulnerable_lens_recall` alongside each lens's TP/FN counts
and recall. The minimum is deliberately a release gate: strong results in
common or cross-cutting lenses cannot compensate for an entirely missed
domain. The companion `counts.vulnerable_lenses` gate also prevents a missing
lens from disappearing from that minimum's denominator.

## Repeated-run stability

`scoreRepeatedEvaluations(runs, expectedCases)` first produces a separate
accuracy, severity, false-clear, invalid-record, and assessment scorecard for
every repeat. It accepts the same normalized finding records as the other
scorers, plus optional `caseOutcomes` and controller-derived
`schemaInvalidCount` on each run. Its output contains sorted `runs` with
`counts` and `rates`, and `aggregate.counts` / `aggregate.rates` ranges for
every metric. Each range reports `minimum`, `maximum`, `mean`, `assessed_runs`,
and `unassessed_runs`. Means weight runs equally and omit null metrics while
retaining their unassessed count; all-null ranges remain null. These are
descriptive ranges, not confidence intervals or evidence that runs are
statistically independent. No primary-run verdict substitutes for a repeat's
missing measurement.

`scoreFingerprintStability` accepts one to 64 run objects; at least two with a
non-empty reportable fingerprint union are required for an assessable score:

```js
scoreFingerprintStability([
  { run_id: 'run-1', findings: normalizedFindings1 },
  { run_id: 'run-2', findings: normalizedFindings2 },
  { run_id: 'run-3', findings: normalizedFindings3 },
], expectedCases)
```

It calculates every pairwise Jaccard score and an all-run
intersection-over-union score. The explicit `fingerprint` is preferred, with
`candidate_id` as the fallback. Case id is included in the comparison key.
One run, or repeated runs whose reportable fingerprint union is empty, is
`assessable: false` and returns null stability values. A required null metric
fails the release threshold rather than becoming a perfect empty-set score.

## Release threshold profile

`thresholds.json` is the initial configurable release profile. Its choices
follow the existing roadmap:

- clean fixtures are a regression gate with a zero-FP budget;
- false clears and schema-invalid records have zero tolerance;
- vulnerable recall is a separately reported capability and is not represented
  as perfect before it has been measured;
- severity calibration is scored, not inferred from detection;
- at least three runs are required because a single nondeterministic run is not
  a publishable measurement.

The initial global recall, minimum per-vulnerable-topic recall, minimum
per-vulnerable-lens recall, and severity floors are 0.80. The profile also
requires every domain lens to have at least one vulnerable case. The per-topic
and per-lens floors prevent a strong common topic or lens from hiding an
entirely missed area. Fingerprint overlap starts at 0.75 across all runs,
with mean pairwise Jaccard at 0.80 and no pair below 0.70.
These are release gates for this development corpus, not external performance
claims. Tighten them as measured runs stabilize; do not loosen them to make one
release green without recording the decision.

Use:

```js
const score = scoreEvaluation(input)
const repeated = scoreRepeatedEvaluations(repeatedRuns, expectedCases)
const stability = scoreFingerprintStability(repeatedRuns, expectedCases)
const result = evaluateThresholds(
  { ...score, repeated, stability },
  thresholds,
)
```

Threshold configuration or metric errors are fail-closed: `passed` is false,
and `errors` names the missing, malformed, or non-finite value.
