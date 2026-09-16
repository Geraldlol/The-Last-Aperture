# Unleash deployment setup

`engage unleash` accepts one target at runtime. A deployment administrator must
provision controller-owned policy and revocation state before an operator uses
the command. Target content and runtime flags cannot supply or replace this
authority.

## Controller directory

Create one canonical local directory with no symbolic-link or junction ancestor:

- Windows: `%LOCALAPPDATA%\LastAperture\controller`
- Other platforms: `~/.config/last-aperture/controller`

The controller verifies the owner and permissions before it accepts authority.
On POSIX systems, the directory and both JSON files must be owned by the
running account with no group or other permissions. Use mode `0700` for the
directory and `0600` for the files.

On Windows, provision the directory before creating the JSON files so they
inherit its protected ACL. This example grants write-capable rights only to the
current account, `SYSTEM`, and the built-in Administrators group:

```powershell
$root = Join-Path $env:LOCALAPPDATA 'LastAperture\controller'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
icacls $root /grant:r "*$($currentSid):(OI)(CI)F"
icacls $root /inheritance:r
icacls $root /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
```

The loader resolves ACL identities to SIDs and fails closed for a non-canonical
or null DACL, an untrusted owner, or any allow ACE that gives write, delete, or
ACL-control rights to another principal. Inherit-only `CREATOR OWNER` entries
are accepted; an entry that applies directly to the authority endpoint is not.

Create these regular, non-linked UTF-8 JSON files inside it:

- `deployment-policy.json`, matching
  [`unleash-deployment-policy.schema.json`](../schemas/unleash-deployment-policy.schema.json)
- `revocations.json`, matching
  [`unleash-revocations.schema.json`](../schemas/unleash-revocations.schema.json)

The resulting policy paths are
`%LOCALAPPDATA%\LastAperture\controller\deployment-policy.json` on Windows and
`~/.config/last-aperture/controller/deployment-policy.json` elsewhere. Place
`revocations.json` beside the policy.

Each file must be at most 64 KiB. Restrict both files and their parent directory
as described above. The controller creates
`.revocation-high-water.json` and short-lived lock/temporary files in the same
directory. The high-water file contains policy identifiers, hashes,
generations, timestamps, and revocation tombstones; it contains no credentials.
Do not edit or delete it. Every high-water replacement is fsynced and published
with a write-through move on Windows.

## Minimum HTTPS observation policy

Replace the origin, policy identifiers, and UTC validity window for the deployed
environment. The current sealed reconnaissance adapter requires `OBSERVE`, one
action, one worker, `max_duration_ms` of at least `900000`, and
`max_response_bytes` of at least `1048576`.

```json
{
  "schema_version": "1.0.0",
  "kind": "last-aperture/unleash-deployment-policy",
  "policy_id": "policy:local-https-observation",
  "valid_from": "<YYYY-MM-DDTHH:mm:ss.sssZ>",
  "valid_until": "<YYYY-MM-DDTHH:mm:ss.sssZ>",
  "allowed_origins": ["https://target.example"],
  "allowed_target_families": ["https"],
  "allowed_effects": ["OBSERVE"],
  "budgets": {
    "max_actions": 1,
    "max_parallel_actions": 1,
    "max_duration_ms": 900000,
    "max_response_bytes": 1048576
  },
  "credential_references": [],
  "detection": {
    "noise_profile": "AUTO",
    "target_environment": "UNKNOWN",
    "risk_tolerance": "UNSPECIFIED",
    "confirmation_mode": "REQUIRED"
  },
  "revocation": {
    "check_id": "revocation:local-https-observation",
    "fail_mode": "CLOSED"
  }
}
```

Declare the real deployment posture when it is known. `noise_profile` accepts
`AUTO`, `AGGRESSIVE`, `BALANCED`, or `CAUTIOUS`. `AUTO` is a deterministic,
controller-owned choice: `LAB` plus `HIGH` tolerance selects aggressive;
`PRODUCTION` or `LOW` tolerance selects cautious; other declared combinations
select balanced. `UNKNOWN` plus `UNSPECIFIED` selects balanced and records
`AUTO_UNKNOWN_POSTURE_BALANCED`, so missing context is visible. Target content
and runtime options cannot change the selection. `STEALTH`, `EVASIVE`, and
`BYPASS` are rejected rather than interpreted as permission to avoid monitoring.

Create matching revocation state. Replace `updated_at` with a canonical UTC
timestamp, and set `policy_sha256` to the lowercase SHA-256 produced by
`digestUnleashValue` for the exact parsed `deployment-policy.json` object.
From the project root, a Windows provisioning session can calculate it with:

```powershell
$policyPath = Join-Path $root 'deployment-policy.json'
$policySha256 = node --input-type=module -e "import { readFileSync } from 'node:fs'; import { digestUnleashValue } from './scripts/lib/unleash-contracts.mjs'; console.log(digestUnleashValue(JSON.parse(readFileSync(process.argv[1], 'utf8'))))" $policyPath
```

Generation starts at `1`. Every changed snapshot must use a higher
generation and a strictly later timestamp. Adding the policy ID to
`revoked_policy_ids` stops later admissions.

```json
{
  "schema_version": "1.0.0",
  "kind": "last-aperture/unleash-revocations",
  "check_id": "revocation:local-https-observation",
  "policy_sha256": "<64 lowercase hexadecimal characters>",
  "generation": 1,
  "updated_at": "<YYYY-MM-DDTHH:mm:ss.sssZ>",
  "revoked_policy_ids": []
}
```

The placeholders are instructions and are not valid policy values. Replace them
before running the command. The policy origin is an exact HTTPS origin without a
path, query, fragment, wildcard, or credentials.

The loader binds each snapshot to the exact policy digest and records its
highest accepted generation durably. A lower generation, changed content at the
same generation, or a non-increasing timestamp fails closed. Revocation IDs are
kept as tombstones, so a later empty snapshot cannot restore a withdrawn policy,
including after process restart.

## Operator flow

After provisioning, the operator supplies only the target:

```powershell
npm.cmd run audit -- engage unleash https://target.example/app
```

The public v0.16.0 path performs credential-free HTTPS reconnaissance and then
runs the controller-owned BORG lifecycle. It writes the campaign under app-owned
storage and reports the campaign ID, status, run directory, completed-route
count, route counts, and gap count. Detailed route dispositions remain in
`campaign-plan.json` inside that run directory.

Before target dispatch, the controller writes an immutable action-risk preflight
and receipt. Status exposes the exact action, selected profile and reason,
relative exposure across endpoint, SIEM/logging, network, cloud, identity, and
application controls, likely impact, stable matched generic detection-pattern
IDs, confirmation state, and bound digests. Pattern IDs describe possible
telemetry-producing activity, not vendor alert rules or proof that an alert
fired. The CLI prints the same risk/noise, impact, control-exposure, uncertainty,
confirmation, and digest summary to stderr before target dispatch; JSON mode
uses a standalone structured warning record on stderr. The
scores use the `HEURISTIC_UNCALIBRATED` method and mean relative exposure, not
alert probability. Telemetry coverage and collection preconditions stay
`UNKNOWN` unless measured outside this model. Profile request-count, rate,
concurrency, and interval violations remain blocked.

If status returns `detection.state: "CONFIRMATION_REQUIRED"`, inspect the
preflight and confirm only that exact assessment. Confirmation is a technical
dispatch gate under the existing deployment authority; it does not create or
renew target authority. A valid confirmation resumes the campaign automatically:

```powershell
npm.cmd run audit -- engage confirm <absolute-campaign-directory> `
  --action-id <detection.action_id> `
  --assessment-sha256 <detection.assessment_sha256> `
  --reason "reviewed exact action and expected detection impact"
```

The status command returns a self-digested snapshot with progress, the full
route inventory, candidate frontier, verified findings, exact gaps, timeline,
detection state, and Pause/rollback/Stop/Resume control state. The BORG controller can schedule five attacker
roles, an exploit falsifier, and a skeptic for up to two attack/review rounds.
Each attempt is identity-bound and crash-safe; a started attempt with an
ambiguous outcome is retained and never replayed. Captured provider bytes must
decode as strict UTF-8 before JSON parsing. The deterministic role-ordered merge
fold retains at most 262,144 JSON bytes; a whole response that would exceed any
aggregate merge invariant is failed as an explicit gap, and later roles remain
eligible.

Protocol-v2 status is verification-only and never repairs campaign projections.
If a mutable projection is proven stale, Resume must acquire the exclusive owner
before performing the repair.

`pause` writes an immutable dispatch gate. New provider dispatch stops while the
current in-flight wave settles. A started attempt observed across the pause
boundary is retained as ambiguous and is never replayed. Resume acquires the
exclusive swarm owner, revalidates current deployment authority, acknowledges
every active Pause, and only then reopens dispatch. Expired or revoked authority
keeps dispatch closed. `stop` is the terminal kill switch and Seal first contends with it for
one immutable `swarm-terminal-fence.json`.
The self-bound winner is final: a `STOP` fence materializes the exact immutable
stop request and the active owner seals `STOPPED`; a `SEAL` fence prevents a
late Stop from publishing a contradictory request. Stop and Status do not start
a second swarm controller. Resume must first acquire the campaign's atomic
exclusive owner lock and always defers while the recorded owner PID is observed
alive, including after attempt expiry and before a Stop request. Only an
identity-bound lock from a dead process is reclaimed. The replacement owner
recovers locally captured work and marks ambiguous started work without replay.
PID reuse deliberately defers recovery until the observed process exits.

The `swarm-owner-lock` directory remains as a permanent private container.
`owner.json` is its atomic create-only ownership claim, and a stable empty
container means the campaign is available. Acquisition recovers only exact
dead-PID stages and exact two-link publication tails. Unique actor-bound
retirement barriers remain until their one old-owner unlink attempt completes,
which prevents a stale reclaimer from touching a successor. Unexpected or
malformed children fail closed.

Status can expose `swarm.phase: "BASIS_READY"` when the immutable swarm basis
and its independently verified reconnaissance envelope exist but the SWARMING
campaign event was interrupted. Resume continues from that exact basis and
does not send the HTTPS reconnaissance request again.

The packaged CLI enrolls no reasoning adapter by default. A normal installation
therefore completes the BORG lifecycle with seven exact
`REASONING_ADAPTER_UNAVAILABLE` gaps. Controller integrations can provide
identity-bound adapters through the internal controller dependency, but the
operator command has no provider, role, prompt, credential, or budget option.
The final merged proposal is retained as one append-only
`candidate-admission-000001.json` record. Its typed actions remain inert, and a
candidate never appears as a verified finding. A `tool:https-recon` proposal is
valid only with the exact parameters `{ "method": "HEAD" }`.

The generated directory name is `campaign-` followed by 24 lowercase
hexadecimal characters. Pass the reported absolute directory to the shared
management commands; the CLI routes that identity to the Unleash controller:

```powershell
npm.cmd run audit -- engage status <absolute-campaign-directory> --json
npm.cmd run audit -- engage pause <absolute-campaign-directory> --reason "operator pause"
npm.cmd run audit -- engage resume <absolute-campaign-directory>
npm.cmd run audit -- engage rollback <absolute-campaign-directory> --reason "cancel future local work"
npm.cmd run audit -- engage stop <absolute-campaign-directory> --reason "operator stop"
```

Rollback is deliberately bounded. It records cancellation of
`NOT_YET_DISPATCHED` work and `PROPOSED_INERT` actions, then invokes Stop. It does
not attempt target cleanup and always reports `target_side_effects_reversed:
false`. Use an action-specific cleanup controller when an enrolled action has a
verified inverse operation.

The action-risk contract is defined by
[`unleash-action-risk-assessment.schema.json`](../schemas/unleash-action-risk-assessment.schema.json).
The catalog records its review date and primary references from MITRE ATT&CK,
Microsoft Sentinel and Defender XDR, AWS GuardDuty, and Google Security Command
Center. Its intended use is explaining likely defender visibility and operational
impact during an authorized audit. Residual risk remains: product configurations,
custom rules, collection gaps, and observation points can produce different
outcomes from the model.

Campaign state is an append-only chain of `campaign-event-NNNNNN.json` records.
`campaign-state.json` is only a recoverable projection of that chain. The
controller also retains the exact plan, registry, and provider protocol. A
completed HTTPS route retains an independently re-read evidence packet and a
typed completion envelope that binds the route, adapter, verifier, recon run,
event-chain head, target, policy, and registry digests.

The BORG provider loop is controller configuration and does not add provider,
role, prompt, route, or credential fields to the operator command. Missing
reasoning adapters and target-action/proof adapters remain visible as exact gaps.

Campaign storage defaults to `%LOCALAPPDATA%\LastAperture\campaigns` on Windows
and `~/.local/share/LastAperture/campaigns` elsewhere. The root and each campaign
directory are checked for canonical identity and trusted-writer permissions
before every operation. On Windows, only the current account, `SYSTEM`, and the
built-in Administrators group may hold write-capable allow entries. On POSIX,
the running account must own each endpoint and group/other permission bits must
be clear.

If a POSIX process stops after a create-only hard link becomes visible but
before its temporary name is removed, reopening storage repairs only the exact
dead-PID temporary whose named destination is the same unchanged two-link inode.
It removes only the temporary, syncs the directory, and verifies the destination
at one link. A different or unexplained alias fails closed without deletion.
