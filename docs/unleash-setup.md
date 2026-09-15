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
  "revocation": {
    "check_id": "revocation:local-https-observation",
    "fail_mode": "CLOSED"
  }
}
```

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

The current slice performs credential-free bounded HTTPS reconnaissance. It
writes the campaign under app-owned storage and reports the campaign ID, status,
run directory, completed-route count, route counts, and gap count. Detailed
route dispositions remain in `campaign-plan.json` inside that run directory.

The generated directory name is `campaign-` followed by 24 lowercase
hexadecimal characters. Pass the reported absolute directory to the shared
management commands; the CLI routes that identity to the Unleash controller:

```powershell
npm.cmd run audit -- engage status <absolute-campaign-directory> --json
npm.cmd run audit -- engage resume <absolute-campaign-directory>
npm.cmd run audit -- engage stop <absolute-campaign-directory> --reason "operator stop"
```

Campaign state is an append-only chain of `campaign-event-NNNNNN.json` records.
`campaign-state.json` is only a recoverable projection of that chain. The
controller also retains the exact plan, registry, and provider protocol. A
completed HTTPS route retains an independently re-read evidence packet and a
typed completion envelope that binds the route, adapter, verifier, recon run,
event-chain head, target, policy, and registry digests.

Campaign storage defaults to `%LOCALAPPDATA%\LastAperture\campaigns` on Windows
and `~/.local/share/LastAperture/campaigns` elsewhere. The root and each campaign
directory are checked for canonical identity and trusted-writer permissions
before every operation. On Windows, only the current account, `SYSTEM`, and the
built-in Administrators group may hold write-capable allow entries. On POSIX,
the running account must own each endpoint and group/other permission bits must
be clear.
