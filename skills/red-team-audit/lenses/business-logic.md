---
name: business-logic
title: Business logic and workflow abuse
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

This lens reads the merged candidate-finding set — after structural dedup, semantic dedup, the reachability gate and the false-positive sweep — together with the recon map, and asks the one question no other lens can ask: **does this system permit a sequence of legal operations that reaches a state the business would not accept?**

Its bug classes are the ones with no bad input and no bad call. A negative quantity that credits the buyer, coupons that compose below the floor the code itself states, an integer overflow that wraps a total, a multi-step approval that can be re-entered or skipped, a charge endpoint with no idempotency, two concurrent requests that spend one balance twice. Every one of those is well-formed traffic that a validator has no reason to reject.

**`frameworks: []` is correct and deliberate.** No catalogue enumerates the rules of a particular product, so a framework claim here would cite a document that cannot decide a single finding. What frameworks *do* supply is a name for the mechanism, and `cwe` should carry it where one fits — `CWE-841` improper enforcement of behavioral workflow, `CWE-837` improper enforcement of a single unique action, `CWE-190` integer overflow or wraparound, `CWE-367` time-of-check to time-of-use. The mechanism comes from the catalogue; **the rule comes from the product**, and the rule is what makes it a finding.

### Where the intent comes from, and what happens when it is absent

In priority order, the rule must be established from:

1. **The repository stating it** — a validation constant, a schema or migration `CHECK`, a unique index, a domain type or value object, a documented invariant, or an existing test asserting it.
2. **The code's own second enforcement point** — the mobile client refuses it, the admin path refuses it, an earlier version refused it. Two enforcement points that disagree establish the rule *and* the defect at once.
3. **A comment or design document**, quoted with its path. Intent, dated, and cited as such.
4. **The user, asked.**

**Where none of those exists, there is no finding.** It becomes a question in the run's assumptions output — "is a negative line quantity intended to credit the buyer?" — never a Low. An opinion about somebody else's business, written as a finding, is how this lens loses the credibility its unfalsifiable half depends on.

**But absence of a rule is not absence of a finding, and the distinction is mechanical: name the state the code reaches, not the input it accepted.** "The endpoint does not reject a negative quantity" is a mechanism and is nobody's finding. "A negative line quantity reaches `order.total` at `billing/total.py:88` and the ledger writes a negative charge, crediting the buyer" is a finding, and it is anchored without asking anyone, because the code's own money path decided what the value means. Every entry in `## Severity calibration` is written against a reached state for this reason.

### Does not own

`owns: []`, and two of this lens's most frequent findings are topics `web-and-api` owns outright: **`client-trusted-business-rules`** and **`race-conditions-and-toctou`**. This lens **raises** against them; it never claims them.

**The boundary from this side.** A raised record is written with `lens: web-and-api`, `topic: <that slug>`, `raised_by: business-logic`. The topic still belongs to its owner and `lens` still names the owner; `raised_by` records who pushed. Ownership is declared, never inferred from which pass emitted the record — any rule that infers it from the emitter misfires precisely here, which is why the emitter is recorded in a separate field.

**The boundary from the other side.** `web-and-api` files both of those topics on its own, without this lens, on the *mechanism*: a rule enforced only in the browser, a check-then-act window with no lock. It does not need this lens's permission and its findings are complete without it. What this lens contributes is the **product-intent half** — which rule is being broken, and what the resulting state costs — and that half goes into the raised record's `impact` and `attack`. It does not become a new topic, and it does not become a second finding.

Consequences, stated so neither side double-files:

- **Where `web-and-api` already filed the same defect at the same location, this lens's record is `merged`**, keeping its own `candidate_id` so that any chain or report line that cited it still resolves, and the intent half is added to the survivor's `impact`.
- **Never restate a `web-and-api` finding under a business-logic label to make it look new.** One race, one record.
- **Never file the mechanism twice under two names.** If the finding is "there is no lock", it is `race-conditions-and-toctou` and it is raised. If the finding is "the approval step can be re-entered", that is a sequence defect with no owning slug — see below.

Other slugs this lens raises against rather than claims, each with its owner:

- **`authz-object-level`, `authz-property-level`, `tenant-isolation-enforcement`** (`web-and-api`) — when the workflow step is missing an ownership or tenancy check, the finding is an authorization finding. A workflow framing does not convert it.
- **`mass-assignment-and-parameter-binding`** (`web-and-api`) — when the illegal value arrives by over-posting a field the client should not control.
- **`rate-limiting-and-request-quotas`** (`web-and-api`) — when the abuse is *volume* rather than *sequence*: mass account creation, coupon farming, ticket scalping, inventory hoarding. The limit these need is a workflow-level limit rather than a per-endpoint one, and it is that lens's finding either way.
- **`webhook-handler-integrity`** (`web-and-api`) — replay and duplicate processing of an *inbound* webhook. Idempotency on a first-party charge endpoint is a different thing and has no slug; see route 2 below. This distinction decides which route a duplicate-charge finding takes, so make it before writing the record.
- **`denial-of-wallet-controls`** (`llm-and-ai`) — when the resource being abused is model spend.
- **`flow-run-context-and-authz`, `apex-crud-fls-enforcement`** (`salesforce-platform`) — when the workflow is a platform Flow or an Apex entry point.
- **`pci-scope-and-cardholder-data`** (`privacy-and-data-protection`) — when the money path touches cardholder data.

**It does not own severity for anything it raises**, and it never edits a component's `claimed_impact_severity`. It also does not compose chains: a business-logic defect that supplies a precondition for another finding is `attack-chaining`'s to compose, and this lens's contribution is filing the component so that a chain can cite it.

### What it originates, and exactly how those records are tagged

Unlike `attack-chaining`, **this lens may originate a finding** rather than only elevating one. That is the whole reason it runs at triage rather than being folded into a domain lens: a double-spend nobody filed, a re-entrant approval nobody filed, are visible only once the merged set shows that nobody filed them.

Two routes, and the choice between them is not stylistic:

**Route 1 — a registry topic covers it.** Raise under the owner, as above. This is the default. The topic slug is the deduplication boundary the whole registry exists to provide, so a defect landing on an owned topic must carry that owner's slug or it will be reported twice.

**Route 2 — no registry slug covers it.** Originate under this lens's own name: `lens: business-logic`, `topic: business-logic`, `raised_by: business-logic`. **That exact label — the lens's own name, no invented sub-slug.** A shadow registry of pseudo-slugs nobody partitions is worse than one honest label, because R1 and R2 cannot see it and nothing keeps it consistent between runs.

Four consequences of route 2, stated so nobody is surprised by them later:

- **`business-logic` must never appear in any lens's `owns`.** The registry is the fan-out deduplication namespace; this label is deliberately outside it. Adding it would make the ownership rules assert a partition over a namespace that has none.
- **The label does not discriminate.** Because it is one string rather than a slug per defect, deduplication for these records falls to the normalized `location` and `title` inside the content-addressed `candidate_id`. Give distinct defects distinct titles, or two of them at one location collapse into one.
- **This is a stated exception to the schema's rule that `topic` is owned by `lens`.** As written, that invariant admits no triage-originated record at all. The exception is **reported to the contract's owner rather than resolved here**, and until the contract carries it a validator will flag these records. `completeness` originates by the same mechanism with its own name, so one exception covers both lenses rather than two.
- **Stretching an owned slug to avoid the exception is the thing not to do.** Filing a negative-quantity credit under `client-trusted-business-rules` because it is the nearest available slug corrupts the deduplication boundary for a topic another lens owns, and a wrong topic is not cosmetic — it merges a finding against the wrong finding. A flagged record is recoverable; a wrong merge is not.

Route 2 is for these, and this list is the intended extent of it: **quantities and prices that reach the money path** with a value the code's own arithmetic mishandles; **pricing arithmetic** — overflow, wraparound, rounding order, floating-point money; **discount and coupon composition**; **re-entrant, skippable or reversible multi-step workflows**; **missing idempotency on a first-party charge or transfer endpoint**; and **two enforcement points of one rule that disagree**. Everything else goes through route 1, and where both routes could apply, route 1 wins.

## Severity calibration

`severity_floor: info` is presentational; it orders this lens's findings and suppresses nothing.

### The oracle gate, applied before any severity is written

Every finding names two things or it is not a finding:

1. **The rule**, quoted from wherever the repository states it, or from the user's answer. Missing → the assumptions output, no severity, no `candidate_id`.
2. **The state the code reaches**, quoted at a `file:line`. Missing → not a finding at all: an absent validator is a mechanism, and the mechanism belongs to `web-and-api` if it belongs to anyone.

This gate is a router, not a discount. A finding that fails it does not get written at Low; it gets written somewhere else, or asked as a question.

### Severity table

The claim is `claimed_impact_severity`: what the impact is if the finding is real and reachable. Reachability capping and the tier caps apply afterwards, unchanged.

| Finding | Claimed impact | The condition, and what must be cited |
|---|---|---|
| A path that moves value the actor did not have — a negative quantity or unit price that the total computation multiplies, a total or amount computed from a client-supplied figure, coupon composition below a floor the code states, an overflow that wraps a total to a small or negative number | **High**; **Critical** where the path is unauthenticated or self-service *and* the value moved per attempt is unbounded | The reached state, quoted: the persisted total, the balance, the ledger row. Never the accepted input |
| A charge, transfer or grant executed more than once for one intent | **High** | The call site with no key derived from the request — or a key minted per attempt, which is the same defect wearing a key — **plus** the retry path that reaches it: a client retry, a queue redelivery, a provider re-send, a double-submit |
| A multi-step workflow that can be re-entered, skipped, or run backwards | **High** where the bypassed step is the authorization or the payment; **Medium** where it is a notification, an audit write, or a UX gate | The transition site with no guard on the current state, quoted, plus the sequence written out as requests |
| Double-spend under concurrency — check-then-act on a balance, quota, seat, or one-per-customer grant | **High** | **Raised under `web-and-api`'s `race-conditions-and-toctou`.** The window quoted: the read, the write, and the absence of a lock, a conditional update, a unique constraint and a transaction boundary — all four, because any one of them closes it |
| A rule enforced on the client and not on the server | **High** where the rule guards money or authority; **Medium** where it guards a display invariant | **Raised under `web-and-api`'s `client-trusted-business-rules`.** Both sides cited: the client's enforcement and the server's acceptance |
| Abuse at volume rather than by sequence | **Medium** | **Raised under `web-and-api`'s `rate-limiting-and-request-quotas`**, at the workflow level. Cite the workflow and its per-actor economics; a per-endpoint limit is not a workflow limit |
| Two enforcement points of one rule that disagree | **Medium** | Both quoted, with a concrete value that passes one and fails the other |
| An input a validator does not reject, with no reached state named | — | **Not a finding.** Name the state or write the question |
| A rule with no stated source | — | **Not a finding.** Assumptions output, as a question |
| A reached state the product documents as intended | — | **Withdrawn**, with the citation. Not downgraded |

### Three rules that override the table

- **Never grade on a number you invented.** "An attacker could order two billion items" is not an impact. The impact is what the code does with the number, quoted: if the total wraps to a negative value and the ledger writes it, say that, with the line.
- **The tier caps apply and most originations start below them.** An originated finding whose only evidence is a cited path is T0 and caps at Medium however obvious the arithmetic is. The recipes below are mostly executable, which is the argument for running them rather than for arguing the cap.
- **A severity that does not survive the product owner saying "yes, we allow that" was never a severity.** Write every finding so that answer withdraws it cleanly, with the citation, rather than leaving a downgraded remnant nobody can close.

## Known false positives

Each entry is a pattern a competent reviewer flags and should not. None of them is a licence to drop a finding: every one names the narrower finding that survives, and what it does not clear.

1. **Negative amounts in a ledger.** Double-entry bookkeeping, refunds, chargebacks, credits and adjustments are negative by design; a `CHECK (amount > 0)` on a ledger table would itself be the bug.
   **What survives:** a negative *quantity* or *unit price* on an order line that the total computation multiplies; or a refund path the payer can call without the approval the code requires elsewhere.
   **What this does not clear:** a negative crossing out of the ledger into an availability, balance or entitlement check written for non-negative values.

2. **Inventory going negative, or overselling.** Backorder, oversell-with-waitlist and just-in-time fulfilment are deliberate in many products, and a negative `on_hand` may be exactly the design.
   **What survives:** the code's own stated invariant broken — a `CHECK`, a domain type, a test — or a reservation the product's flow says is exclusive being granted twice.
   **What this does not clear:** a seat, a licence, a slot or a one-per-customer grant. There, uniqueness usually *is* the product, and the same negative count is the finding.

3. **A "duplicate" charge that is a legitimate retry.** Two provider calls carrying the same idempotency key are one charge; the provider deduplicates them.
   **What survives:** no key at all; a key derived from a timestamp, a random value or the attempt rather than the intent; or a key scoped so that a retry produces a new one.
   **What this does not clear:** a correct key sent to the provider while the local ledger writes two rows. The provider charged once and the system now believes two things.

4. **A missing application lock where the database already closes the window.** A unique index, `INSERT ... ON CONFLICT`, `SELECT ... FOR UPDATE`, a serializable transaction, or an atomic `UPDATE ... WHERE balance >= :amount` whose row count is checked — each of these makes a TOCTOU finding a false positive, and filing against them is the most common way this lens misfires.
   **What survives:** naming which mechanism is absent. Quote the write and show there is no constraint, no conditional update, no row-count check and no transaction boundary.
   **What this does not clear:** a constraint that exists in a migration but not on the path taken — a different table, a partial index that excludes soft-deleted rows, a unique index on a nullable column where `NULL`s do not collide.

5. **A coupon stack the product sells.** Stackability is a feature in many catalogues, and there is frequently a `stackable` column saying so.
   **What survives:** composition below a floor the code states — a minimum price, a maximum discount, an `applies_once` flag — or a coupon reusable past the limit its own record declares.
   **What this does not clear:** the *order* of application. Applying a percentage after a fixed amount when the code's stated order is the reverse changes the total, and the total is the reached state.

6. **Floating-point or integer money flagged on sight.** Storing cents in integers and formatting through floats at the edge is normal, and a `float` column alone is a design observation.
   **What survives:** arithmetic on the float that reaches persistence or the charge, with the specific value that loses precision named; or an integer width the code's own stated maximum exceeds.
   **What this does not clear:** rounding applied per line where the product states it is applied per order, or the reverse. That changes the total.

7. **A transition guard that lives somewhere the reviewer did not look.** Middleware, a database constraint, a transition table, a state-machine library.
   **What survives:** the reached state demonstrated, or the guard shown absent on **one entry point among several** — the HTTP path guarded and the queue consumer, CLI command or admin action not. Enumerating entry points is how that is found, and it is the highest-yield variant of every recipe below.
   **What this does not clear:** a guard present in code that the observed path does not execute.

### Rejected candidates

- **"Any missing input validation is a business-logic finding."** Rejected: as a mechanism it is `web-and-api`'s, and with no reached state named it is nothing at all. Adopting it would drown the report in items whose only content is that a validator is absent.
- **"Grade every money defect Critical."** Rejected: value loss that is bounded per attempt and recoverable is a High at most, and the inflation costs this lens exactly the credibility its product-intent claims depend on.
- **"Treat any workflow with no state machine as a finding."** Rejected: plenty of correct systems enforce sequence with a unique constraint and a status column. The finding is a reachable illegal state, never an architectural preference.

## Proof recipes

**The assertion is the invariant, on the persisted state — never the response.** A handler that returns 400 after writing the row has still written the row; a charge that errors after the provider recorded it has still charged. Assert on the row, the ledger, the recorded provider call, the resulting state. Every one of the five oracle conditions applies, and the one most often skipped here is the control.

### B1 — Boundary-value invariant test (T1)

Submit each value through the real entry point and assert the money or quantity invariant on what was persisted: the total equals the sum of line totals, the balance moved by exactly the amount charged, no row violates a rule the code states.

The corpus, which is numeric and is **not** in the shared harness: `-1`, `0`, `-0.0`, `0.005`, `1e309`, `2**31`, `2**53 + 1`, `9223372036854775808`, `NaN`, `Infinity`, a 30-digit integer, and the same values **as strings**, because a query parameter or form field delivers them that way and a parser may coerce `"1e2"` or `"0x10"` where the JSON body would not.

**The canary fixture set does not cover this** — its hostile corpus is markup and injection payloads — so the numeric corpus lives in this recipe. If a second lens ever needs it, that is when it earns a section in `_harness.md`; one citing lens is not enough to justify shared indirection.

### B2 — Sequence and re-entry test (T1)

Enumerate the workflow's steps or transitions with the **registry-driven enumerator** — a state-machine definition, a workflow registry, or the route table for the steps — and keep its committed-count assertion, because an enumerator returning zero rows makes this whole sweep pass vacuously.

Then, per step: replay it twice; run it out of order; run it after the terminal state; run it on a record another principal owns. Assert **refusal and unchanged state**, both halves — a refusal that already wrote the row is the finding.

The positive control is required: the legitimate sequence must succeed. Without it, a handler that refuses everything passes the entire sweep.

### B3 — Idempotency test (T1)

Put the **counting fake client** in front of the charge or transfer, submit the identical request twice — same key, same body — and assert three things: the recorded call count is exactly one, the second response returns the first result, and exactly one ledger row exists. **The count is the assertion.** Response equality alone passes on a double charge that returns a cached body.

Then the retry shapes the enumerator finds, because each reaches the handler differently: a client retry, a queue redelivery, a provider re-send, a browser double-submit, two application instances processing one message.

Rail 2 applies without exception: the fake *is* the payment. No recipe here calls a real provider, and a recipe that can only be shown by moving money is written and left unexecuted at T3.

### B4 — Concurrency and double-spend (T1 where the runner can genuinely overlap requests; T3 where it cannot)

**No component in `_harness.md` covers concurrency.** Build it here: N clients released by one barrier against the same balance, seat, quota or one-per-customer grant, then assert the invariant on the persisted row — the sum of debits does not exceed the starting balance, the seat count does not exceed capacity, the grant exists once.

Five traps, each of which produces a pass on vulnerable code:

- **A test client that serializes requests in-process demonstrates nothing.** Check whether the client is synchronous. If it is, and the repository offers no way to overlap requests, this recipe lands at **T3 with `UNPROVEN` and that as the blocking reason** — never at "no race found". The two are opposite results and the second one is a wrong clearance.
- **Firing requests sequentially as fast as possible is not a race.** The barrier is the mechanism; without it the test measures latency.
- **A sensitivity control is required:** the same test against a deliberately unguarded fixture must fail. Without it, a suite whose transactions serialize under an in-memory database reports safety.
- **Run it enough times to be stable and report the observed failure rate.** A one-in-fifty result *is* the finding. Re-running until it passes deletes it.
- **Where the contended state is in process memory rather than in the database**, run under the language's race detector as well; an unsynchronized counter produces a wrong count in the direction that passes.

### B5 — Window and expiry (T1)

Where the rule has a time component — a coupon's validity, an approval that expires, a hold that releases, a trial that ends — use **clock control**, and assert both directions: the case outside the window is refused **and** the case inside it still works. "Refuse everything" is the failure mode a one-directional test rewards.

Back-date the rows rather than freezing the process clock wherever the predicate is evaluated by the database, and say in the finding which you did. Where a monthly or month-end rule is involved, choose the instant to expose it — a rule anchored on 31 January is where the calendar arithmetic breaks.

### Where no shared component applies, plainly

The **socket-layer destination recorder**, the **detector-and-fixture-pair runner** and the **local log and artifact collector** have no role in these recipes: nothing here is about egress, a static rule run in two directions, or build output.

Two components apply only under a condition worth stating rather than leaving to be discovered:

- The **two-subject fixture** is the right tool the moment a workflow step's defect is an *ownership* check — and at that moment the finding is an authorization finding, raised under `web-and-api`, and the recipe is that lens's. Reaching for the fixture is the signal that the route-1 boundary has been crossed.
- The **capturing log handler** applies only where the sole observable form of the invariant is an emitted event. That is a weaker proof than the persisted row and must not be preferred to it; use it when the state is genuinely unobservable, and say so in the finding.
