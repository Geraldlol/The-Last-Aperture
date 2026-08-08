---
name: completeness
title: Audit completeness critic
runs_in: triage
activates_on:
  paths: []
  signals: []
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
owns: []
defers: {}
frameworks: []
severity_floor: info
---

## Scope

This is the only lens whose subject is **the audit** rather than the code. It measures what the run did not examine and names it, so that the report's coverage claim is a measurement instead of an impression.

Its input is the run itself: the recon map, the active lens set with the reason each lens did or did not activate, the assigned file lists, the merged candidate-finding set after triage, the drop list with reasons, the coverage block as drafted, and — from the second round onward — its own previous output.

Seven gap classes. Each is a **measurement over a stated denominator** — the file list, the entry-point list, the store list, the lens list, the drop list, the coverage block, the record set — and never an impression:

1. **A lens that should have activated and did not.** Re-match every lens's `activates_on.paths` and `activates_on.signals` against the recon map's file list and dependency manifests, then difference against the set that actually ran.
2. **An entry point with no findings and no explanation.** Every entry point in the recon map should appear either as some record's `reachable_from` or in the coverage block as examined-and-clean, naming the lens that examined it. Neither → a gap.
3. **A data store nobody looked at.** Every store in the map — and especially every store the map marks sensitive — should be named in some record's `location` or `evidence`, or in the coverage block. Neither → a gap.
4. **A file matched by no lens.** The in-scope file set minus the union of the active lenses' assigned file lists. A file no lens claimed was read by nobody, and no lens will ever report that, because reporting it requires seeing all the assignments at once.
5. **A drop whose reason is not a discriminator.** "Not a finding" and "false positive" are verdicts, not reasons. A drop reason that names no artifact is a gap, because a drop with no reason is indistinguishable from a loss.
6. **A coverage claim the record set contradicts.** The one class this lens rates above Info — see `## Severity calibration`.
7. **A record whose `topic` its `lens` does not own, with no `raised_by`.** Resolve every record's `topic` to its owner in `_topics.md`. Three outcomes: the filing lens owns it, which is normal; another lens owns it and `raised_by` names the pusher, which is the raise mechanism working; another lens owns it and `raised_by` is absent, which is a lens quietly reporting territory it neither owns nor defers. **Nothing else in the pipeline detects the third case** — the frontmatter rules read `owns` and `defers`, never findings, and a substantial share of the registry's slugs have no inbound `defers` reference at all, so no rule constrains them. The spec names this lens as the only thing that would notice, which is why it is a class here rather than an aspiration there.

### Does not own

`owns: []`, and unusually for this registry that is not a boundary question but a category one: **an unexamined area is not a vulnerability.** It is an absence of evidence. There is no topic to own because there is no defect being claimed.

- **It does not read code and it does not file code findings.** An examinable lens/file gap is eligible only for a controller-authorized sealed whole-shard retry. A vulnerability found there is filed by the topic-owning lens under that lens's calibration; this lens names the area and lens, never the other lens's finding.
- **It does not raise against another lens's topic.** `business-logic` raises; `attack-chaining` elevates; this lens does neither. It reports on the run.
- **It does not adjudicate severity, deduplication or drop decisions on their merits.** "This should have been a High" is out of scope. Class 5 is deliberately narrow and mechanical: the reason cites no artifact, or cites one that is not at the cited line.
- **It does not re-litigate the recon scope, but it does report it.** A scope drawn to exclude a directory is a decision; a scope that excluded a directory by accident is a gap. Say which one you found, and where you cannot tell, say that.
- **It does not fix frontmatter.** A wrong `activates_on` glob produces a class-1 gap. Report it to the registry owner. The current run may use only already planned applicability and sealed retries; registry repair requires a new plan.

### The record it writes

Same mechanism as `business-logic`'s originated findings: `lens: completeness`, `topic: completeness`, `raised_by: completeness`. The lens's own name, exactly, with no invented sub-slug, and it must never appear in any lens's `owns` — the registry is the fan-out deduplication namespace and this label sits deliberately outside it. **It is the same stated exception to the schema's rule that `topic` is owned by `lens`**, reported to the contract's owner rather than resolved here, and one exception covers both lenses rather than two.

The required fields have honest values for a record that claims no exploit:

| Gap class | `location` | `reachable_from` | `claimed_impact_severity` |
|---|---|---|---|
| Lens that should have activated | a file that matches its pattern, at line 1, with the matching pattern quoted in `evidence` | `unknown` | Info |
| Entry point with no findings | the handler, `file:line`, from the recon map | **the entry point** | Info |
| Data store nobody examined | the migration, schema or model file naming it | `unknown` | Info |
| File matched by no lens | the file, line 1 | `unknown` | Info |
| Drop reason that is not a discriminator | the dropped record's own `location` | copied from the dropped record | Info |
| Coverage claim the record set contradicts | the artifact the claim is about; the claim's own text quoted in `evidence` | `unknown` | Info, **and blocking** |
| Record filed under a topic its lens does not own | the offending record's own `location`; its `lens`, `topic` and the registered owner quoted in `evidence` | copied from that record | Info |

`reachable_from` is required and `unknown` is a legitimate value for it. **Do not manufacture an attack path to fill the field** — there is no attack, the record is Info, and the reachability cap it triggers is irrelevant to an Info record. `attack` states the measurement rather than a payload: `entry point POST /api/exports appears in no record's reachable_from and in no coverage note`.

### Closure rounds, and how they end

The controller owns the immutable inventory, applicability map, shard
identities, and maximum retry count. This lens measures and names gaps; it
cannot enlarge the repository denominator, invent a residual scope, or create
an ad hoc job.

One closure round is:

1. **Measure** the stated denominators and every applicable lens/file pair.
2. **Retry, when authorized.** For an uncovered pair, the controller may
   activate only the sealed whole-shard template for that pair's original shard
   and planned round. Provider output cannot split a shard, increase the retry
   budget, or introduce repository paths.
3. **Re-enter triage and proof.** Retry candidates follow the ordinary
   downstream jobs before coverage is measured again.
4. **Re-measure** the same immutable denominators.

Closure seeks a fixed point but is deliberately bounded by the plan. Zero
uncovered applicable pairs is `CONVERGED`. If pairs remain after the final
planned retry, the state is `BUDGET_EXHAUSTED`, with every residual pair
preserved as a named gap. If controller measurement cannot run, the state is
`UNMEASURED`, naming the missing prerequisite. Neither state may be rendered as
converged, 100%, or clean.

A retry may reveal a missed route, store, or consumer inside the immutable
snapshot; record that surface as gap or candidate evidence, but do not add new
files to the denominator. A changed repository requires a new plan and
snapshot.

Whatever closure cannot resolve is written into coverage with its area and
would-be lens, never as silence.

## Severity calibration

`severity_floor: info` is presentational everywhere in this registry, but here it also matches the content: **an unexamined area is an absence of evidence, not a defect.** Grading a process observation above a proven finding would put it ahead of real findings in the ranked list, which is the opposite of what this lens is for.

- **Classes 1 through 5, and class 7, are Info.** No impact claim, no `cwe`, no severity negotiation. Their value is entirely in being specific: a named entry point with a named lens is a gap somebody can close in ten minutes, and "coverage may be incomplete" is not. Class 7's remedy is a `defers` entry or a corrected `topic`, reported to the registry owner; it never changes the finding's own severity, because a mis-filed finding is still a finding.
- **A code finding produced by a scoped fan-out is graded by the lens that filed it**, on that lens's calibration. This lens never elevates a code finding and never adds an aggravator to one. Its contribution ends at "nobody looked here".
- **A gap is not closed by an assertion.** "Reviewed and clean" from a fan-out that filed no record and left no negative-result note closes nothing — that is class 6 one round early. The note costs one line and is what separates examined-and-clean from unexamined.

### Class 6 is not Info — it blocks the report

A coverage claim the record set contradicts: the block says a lens ran and no record or note exists for it; says a file set was examined and no record cites any file in it; states a percentage no denominator supports.

That is not an unexamined area. **It is a wrong clearance, and nobody re-opens a closed item.** A reader who is told an area was examined stops looking at it, permanently, and no later round recovers that.

It does not get a higher severity *number* — it is not a vulnerability and does not belong in the vulnerability ranking. It **blocks the report**: Phase 5 does not emit while an unresolved class-6 finding stands. Resolution is one of exactly two things, and both are cheap:

- **Correct the claim** — the lens did run, and the missing negative-result note is written.
- **Withdraw the claim** — the lens did not run, and the coverage block says so with the reason.

Shipping a report whose coverage block is false is the most damaging output this pipeline can produce, because it is the one output that tells a reader they can stop.

## Known false positives

Every entry is an area a naive coverage measurement flags and should not. None is a licence to stop measuring: each names what survives.

1. **A file matched by no lens that no lens should match** — lockfiles, vendored dependencies, generated clients, minified bundles, binary assets, documentation, test fixtures. Uncovered is correct for these, and reporting them buries the real gaps in a list of noise.
   **What survives:** a *generated* file whose generator input is in scope and unexamined; a vendored directory the build actually compiles, which is a real topic another lens owns; a fixture holding real data, which is likewise another lens's.
   **What this does not clear:** a file uncovered because the recon scope was drawn wrongly. Check whether the exclusion was a decision or an accident and say which; where you cannot tell, say that rather than choosing.

2. **A lens that did not activate and should not have.** `activates_on` is a match, not a wish: a platform lens on a repository with no platform metadata, a mobile lens on a server-only service.
   **What survives:** a lens whose pattern *does* match a file in the map and which still did not run. That is class 1 and it is mechanical.
   **What this does not clear, and this is where the measurement itself goes wrong:** a pattern that fails to match because the pattern is broken. **Never write `{,.ext}` in a glob when re-matching** — ripgrep's globset silently drops the empty branch, so `*.config{,.js}` matches only `*.config.js` and the extensionless name is invisible. Measured, not theorized. A denominator built on that glob under-reports, and under-reporting reads as coverage.

3. **An entry point with no findings because it is genuinely clean.** A health check, a static asset route, a version endpoint.
   **What survives:** no record *and* no negative-result note. The note is the entire distinction between examined-and-clean and unexamined.
   **What this does not clear:** an endpoint that is only trivial on the happy path. A version endpoint that echoes a header, or an error handler that renders the request body, is not a trivial endpoint.

4. **A store with no findings that holds nothing sensitive** — a cache, a queue, a metrics store, an ephemeral session table.
   **What survives:** the recon map marking it sensitive, or a schema showing a personal-data or regulated column.
   **What this does not clear:** a cache holding rendered responses of authenticated pages. That is a real store of sensitive data and its findings belong to the lenses that own caching and personal data.

5. **The same gap re-reported every round.** A gap examined in round N and found clean must not reappear in round N+1. If it does, the negative-result note is missing, and the fix is the note rather than another fan-out.
   **What survives:** a gap that reappears because the area *grew* — new files, a newly discovered route. Say which, or the loop cannot converge and the run reports `budget-exhausted` forever on an area that was in fact examined.

6. **A drop reason the critic did not understand.** A reason citing a guard at a `file:line` is a discriminator whether or not the critic can verify it, and re-opening it on suspicion wastes the round.
   **What survives:** a reason with no artifact at all — "not exploitable", "by design", "handled elsewhere".
   **What this does not clear:** a reason citing an artifact that is not at the cited line. That is a falsified premise, and it goes back as a real gap with the discrepancy quoted.

7. **A record filed under another lens's topic *with* `raised_by` set.** That is the raise mechanism working exactly as designed — a cross-cutting lens pushing a finding onto the owner's topic — and flagging it teaches an auditor to stop using the one mechanism that keeps the registry a partition.
   **What survives:** the same shape with `raised_by` absent, which is class 7.
   **What this does not clear:** the two lens-namespaced labels, `business-logic` and `completeness`. They are outside the registry by design and are the stated exception to the ownership invariant; a sweep that reports them as class 7 every round is a sweep that never converges.

### Rejected candidates

- **"Report a single coverage percentage."** Rejected as this lens's primary output. A percentage with no denominator stated is exactly the claim class 6 exists to catch, and a hidden denominator is worse than the five typed denominators and seven named gap classes.
- **"Silently stop after three rounds for cost."** Rejected. The controller may commit a finite retry budget at planning time, but reaching it with open obligations is `BUDGET_EXHAUSTED`, never convergence or clearance.
- **"Treat every uncovered file as a finding."** Rejected: it produces a report where the real gaps are indistinguishable from `node_modules`, and the first reviewer to skim it stops reading this lens's output permanently.

## Proof recipes

**A completeness finding's proof is a coverage measurement, not an exploit.** There is no vulnerable line to reach and no payload to fire, so the five-condition oracle does not transfer as written — four of its five conditions describe an assertion firing on a code path. What does transfer is its central idea, restated in the measurement's own terms:

> **A measurement with no denominator and no sensitivity control is not evidence,** because "nothing unexamined" and "nothing measured" are the same output.

### K1 — The denominator, from the registry (T1)

Every measurement below is a set difference, and the denominator is the half that decides whether the result means anything. Build it with the **registry-driven enumerator**: the framework's own route table, the queue consumer map, the scheduled-job registry, the model and store list. Its three non-negotiables are precisely what a coverage measurement needs.

- **Assert the discovered count against a committed number.** An enumerator that silently returns zero rows makes every coverage claim below perfect. This one assertion is worth more than the measurements it feeds, and a committed count of zero is rejected outright so nobody satisfies the check by committing the broken state.
- **Anchor the allowlist patterns; never prefix-match them.** An exemption for `/public` must not remove `/publications/secret` from the denominator. Ship the self-test.
- **Say whether you enumerated from a runtime registry or from a source parse.** Where there is no runtime registry the count assertion matters more, not less: an entry point registered by a mechanism the parser does not model is invisible, and its absence from the denominator looks exactly like coverage.

### K2 — The planted-gap control (T1), and it is required

Plant an area you know is unexamined — a fixture route registered in the test application and named in no record, a file added to the scope list and assigned to no lens — and assert that the measurement names it.

This is the coverage analogue of the harness's planted canary and it exists for the identical reason: a sweep that found nothing and a sweep that ran against nothing look identical. **Build it first.** Without it, a measurement pointed at an empty record set reports perfect coverage, and that is the exact output this lens exists to prevent.

### K3 — The four coverage differences (T1 where the denominators were enumerated, T0 where the map was read by hand — record which)

- **Lens activation.** Re-match each lens's `activates_on` over the file list and dependency manifests; difference against the lenses that produced records or notes. The glob caution under `## Known false positives` applies to this re-match specifically, because it is the one place a broken pattern silently shrinks the denominator.
- **Entry points.** Enumerated entry points, minus the union of every record's `reachable_from`, minus the coverage block's examined list.
- **Stores.** Recon-map stores, minus stores named in any record's `location` or `evidence`, minus the coverage block's list.
- **Files.** In-scope files, minus the union of the active lenses' assigned file lists.

Report the count **and** the list, with the denominator beside it. A percentage alone is the thing this lens exists to prevent, whichever direction it errs in.

### K4 — The coverage-contradiction check (T1, two directions)

For every claim in the coverage block, assert a supporting artifact exists: a lens claimed to have run has at least one record or one negative-result note; a file set claimed examined has at least one record citing a file in it, or a note naming it; a stated percentage recomputes from the same denominator.

Then the other direction, which is the one that catches a rule that never fires: **assert the check flags a deliberately false claim** in a fixture coverage block. One direction is not enough, and the missing direction is always this one — a checker that only passes on clean input proves the rule runs, not that it fires.

This is the same two-direction discipline the **detector-and-fixture-pair runner** encodes, and where the repository already runs a checker under its own test runner, that runner is where this check belongs. Running under the project's own command is what makes it T1 rather than T0.

### K5 — The topic-ownership sweep (T1)

For every record, resolve `topic` to its owner in `_topics.md` and assert that either the owner is the record's `lens`, or `raised_by` is present and names the pusher, or the topic is one of the two lens-namespaced labels. The check is short and it is the only thing standing between the registry and a lens that has quietly started reporting a neighbour's territory: the frontmatter rules read `owns` and `defers`, and no rule reads findings.

Both directions, as ever: plant a record with a foreign topic and no `raised_by` in a fixture set and assert the sweep flags it. Assert the registry it resolves against is non-empty, for the same reason a conformance check against zero rules passes perfectly.

### Tiers, plainly

A coverage measurement executed by the project's own runner, with a committed denominator and the planted-gap control, is **T1**. A measurement read off the recon map by hand is **T0** and caps at Medium, which is irrelevant to an Info record — this lens does not chase tiers and should not be read as under-evidenced for staying at T0.

What it must never do is record `verification_status: CONFIRMED`. Nothing was confirmed about any code, and the status field is about a vulnerability's assertion firing. Where a measurement did not run, the record carries `UNPROVEN` with the blocking reason and the run's terminal state is `unmeasured` — not a coverage number.

### Where no shared component applies, plainly

Only the **registry-driven enumerator** applies directly, as the source of every denominator. The **detector-and-fixture-pair runner** applies as a *discipline* for K4 — two directions, a non-empty rule set — rather than as a component to call.

The **canary fixture set** does not apply: there is no sink to sweep and no payload to plant. K2 borrows its planted-marker *idea*, not the component. The **two-subject fixture**, **clock control**, **counting fake provider client**, **socket-layer destination recorder** and **local log and artifact collector** have no role in this lens at all.

**No component in `_harness.md` measures coverage**, and K1 through K5 are assembled here rather than added there for the reason that file states: a shared component is justified when a second lens needs the same thing, and no second lens measures the audit.
