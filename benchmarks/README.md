# Evaluation metrics

This directory defines deterministic scoring primitives for future model-driven
evaluation. It does not call a model and it does not claim a detection rate.
Metrics are meaningful only when accompanied by the corpus name, corpus version,
model and harness configuration, run count, and raw normalized records.

The repository's own fixtures are a development and regression corpus. Results
on them are not evidence of real-world performance because the fixtures and
lenses were authored together.

`cases.json` is the machine-readable ground truth generated from
`fixtures/EXPECTED.md` and `fixtures/OWNERSHIP.tsv`. Every case is bound to one
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

## Metric semantics

The confusion matrix is case-based:

- **TP**: a vulnerable case has a reportable finding on its required topic.
- **FN**: a vulnerable case has no reportable finding on its required topic.
- **FP**: a clean case has one or more findings at Low or above.
- **TN**: a clean case has no findings at Low or above.

Info observations do not count as vulnerability findings. Records withdrawn as
`dropped`, `merged`, `DISPROVED`, or `NOT_REPRODUCED` do not count as reported
findings.

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

## Repeated-run stability

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

The initial global recall, minimum per-vulnerable-topic recall, and severity
floors are 0.80. The per-topic floor prevents a strong common topic from hiding
an entirely missed topic. Fingerprint overlap starts at 0.75 across all runs,
with mean pairwise Jaccard at 0.80 and no pair below 0.70.
These are release gates for this development corpus, not external performance
claims. Tighten them as measured runs stabilize; do not loosen them to make one
release green without recording the decision.

Use:

```js
const score = scoreEvaluation(input)
const stability = scoreFingerprintStability(repeatedRuns, expectedCases)
const result = evaluateThresholds(
  { ...score, stability },
  thresholds,
)
```

Threshold configuration or metric errors are fail-closed: `passed` is false,
and `errors` names the missing, malformed, or non-finite value.
