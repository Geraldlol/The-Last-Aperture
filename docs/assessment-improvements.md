# Assessment improvements

The new commands make saved audit evidence, review handoffs, measurement gaps,
and installation prerequisites easier to inspect. They provide supporting
pieces for the six recommendations; independent verdict verification, measured
analysis quality, a semantic source analyzer, and broader runtime execution
remain unfinished. [Delivery status](delivery-status.md) records that boundary
for each recommendation.

## 1. Inspect the support for a recorded verdict

```text
node scripts/audit.mjs verdict <bundle> [--candidate <candidate-id>] --json
```

The report shows the recorded verification and triage status, whether those
claims have authenticated authority, source-anchor counts, proof-job states,
and unmet requirements. It labels an unauthenticated fix claim rather than
promoting it. Output is bounded to 100 findings and 20 proof jobs per finding,
with explicit omitted counts.

The current semantic verifier is `NOT_AVAILABLE`. A source anchor, receipt
reference, or completed job may help a reviewer understand the record but does
not independently establish the security conclusion. Bundle integrity checks
also do not establish independent root authenticity: this view reports
`root_authenticity: UNANCHORED`.

No finding or historical evidence is changed. Raw evidence and provider
narratives are omitted from this projection. The implementation is
[`verdict-assessment.mjs`](../scripts/lib/verdict-assessment.mjs).

## 2. Measure each submitted benchmark repeat

```text
node scripts/audit.mjs benchmark <evaluation.json> --cases <cases.json> --thresholds <thresholds.json> --out <scorecard.json>
```

The scorecard now includes separate counts and rates for each repeat and
aggregate minimum, maximum, and mean values. Null metrics retain explicit
assessed/unassessed run counts; an unmeasured severity or assessed-accuracy
denominator never becomes a perfect score. Repeat outcomes are evaluated
against the same case manifest. Top-level outcomes bind only to the primary
run, and conflicting primary declarations are rejected.

Cases with explicit `finding` or `clear` verdicts count as assessed. Incomplete,
not-assessed, and unspecified cases are counted separately. Missing final
outcomes remain unspecified even if findings exist. The established confusion
matrix is preserved: a clean fixture with no reportable finding is still a TN,
so matrix accuracy must be read alongside assessment coverage. Absence of a
finding is not evidence that a clean assessment was performed.

Optional `measurement` metadata records named versions of the model, harness,
and corpus, with optional model/harness configuration hashes. It is
`CALLER_DECLARED`; it does not authenticate those identities or establish corpus
independence. Computed hashes still bind the evaluation input, case manifest,
and threshold file. Invalid records remain visible in both release debt and
their own repeat scorecard.

This pass introduces no independently vetted corpus, model execution, or
real-world quality result. The repository fixtures remain a development and
regression corpus. See [benchmark documentation](../benchmarks/README.md),
[`evaluation.mjs`](../scripts/lib/evaluation.mjs), and the
[input contract](../schemas/benchmark-input.schema.json).

## 3. Prepare and validate a source-review submission

```text
node scripts/audit.mjs review-template <bundle> --job <job-id>
node scripts/audit.mjs check-result <bundle> <job-result.json> --json
```

`review-template` accepts a pending source-review LENS job in the current
phase. It emits the run/job identity, packet digest, topic obligations, and an
inert result template. Its `analysis_status` is `NOT_PERFORMED`. Producer and
result-state placeholders are null so an untouched template cannot be mistaken
for completed analysis. Topic outcomes start as not assessed.

A reviewer must inspect the matching complete packet and supply the actual
analysis. `check-result` checks a supplied result against the saved run,
snapshot, and ingestion contract. Its result has `applied: false`; successful
validation does not ingest the submission or authenticate its semantic claims.
Ingestion remains a separate operation.

These commands improve the integration handoff but do not implement a bundled
semantic source analyzer or run a provider. The template projection is in
[`review-handoff.mjs`](../scripts/lib/review-handoff.mjs); command validation is
in [`audit.mjs`](../scripts/audit.mjs).

## 4. Prepare a repair and retest handoff

```text
node scripts/audit.mjs repair-brief <bundle> [--candidate <candidate-id>] [--baseline <baseline-bundle>] --json
```

The handoff contains finding and run references, inventory-backed source
coordinates, claim authority, and acceptance requirements for reviewing the
premise, recording a repair, checking expected behavior, reviewing the security
invariant, and linking retest evidence. With a baseline, it includes comparison
links and findings absent from the current run so history is not lost.

These checklist entries are requirements, not completed checks. The current
finding contract has no structured repair recommendation for this projection,
so `recommended_change.status` is `UNKNOWN`. A maintainer still needs to record
the reviewed change and patch/test evidence. Comparison absence and provider
assertions never turn into independently verified remediation;
`fix_verified` remains false.

The command creates no patch and executes no retest. Sensitive free-text
narratives and evidence-locator values are withheld by default, while saved
run/candidate references preserve access for controlled review. Repository paths
and identifiers remain metadata to consider before sharing. The implementation
is [`repair-brief.mjs`](../scripts/lib/repair-brief.mjs).

## 5. Discover capabilities and inspect installation prerequisites

```text
node scripts/audit.mjs capabilities --json
node scripts/audit.mjs doctor [--worker <proof-worker.json>] --json
node scripts/doctor.mjs [--worker <proof-worker.json>] --json
```

The shared registry lists each public capability as available, narrowly
available, or unavailable, with its behavior and limitations. The generated
[capability documentation](capabilities.md) uses the same declarations. Static
availability is not a security verdict or a guarantee of runtime readiness.

Doctor inspects the controller installation, Node version, required regular
files, pinned dependency metadata, fixed runtime-path presence, and optionally
the structure of a proof-worker configuration. The standalone entry point has
no external package dependencies and can report missing dependencies before
the main CLI is usable. It does not install or execute them.

Read the individual check and workflow status fields. `STATIC_CHECKS_PASSED`
does not establish Docker daemon availability, executable identity, image
compatibility, or target compatibility; those remain `NOT_CHECKED`. Neither
doctor entry point executes Docker, target code, or network requests. See
[`doctor.mjs`](../scripts/lib/doctor.mjs) and
[`capabilities.mjs`](../scripts/lib/capabilities.mjs).

## 6. Make environment gaps visible

```text
node scripts/audit.mjs doctor --bundle <bundle> --json
```

For a validated saved bundle, doctor matches recorded filenames against the
registry's environment profiles and reports source-review availability,
execution support, matched-path counts, and bounded example paths. Profiles
cover Node/npm, Python, .NET, JVM, Go, Rust/native, browser configuration,
database stacks, and deployment configuration.

The basis is explicitly `RECORDED_FILENAMES_ONLY`. These are heuristic
indicators, not proof that a technology is present, was reviewed completely, or
can execute. No matching indicator leaves runtime coverage unknown; it does not
prove a technology is absent. This inspection uses the saved inventory rather
than opening current target files or deployment endpoints.

Deployment evidence remains `NOT_ASSESSED`. This pass adds no executable
runtime, browser runner, multi-service/database target stack, or deployment
acquisition route. The existing narrow Node/npm execution profiles retain
their existing contracts. Environment reporting is implemented in
[`capabilities.mjs`](../scripts/lib/capabilities.mjs).
