---
name: ai-model-and-mlops-security
title: AI model and MLOps security
runs_in: fanout
activates_on:
  paths:
    - '**/{ml,mlops,model-training,training,finetuning,fine-tuning,checkpoints}/**'
    - '**/*{train,training,finetun,fine_tun,dataset,lineage,poison}*.{py,ipynb,yml,yaml,json,toml}'
    - '**/{dvc.yaml,dvc.lock,MLproject,model-card.md,model-index.yml,model-index.yaml}'
    - '**/{mlflow,kubeflow,metaflow,flyte,airflow,pipelines}/**'
    - '**/*{model,checkpoint,weights,adapter,tokenizer}*.{safetensors,onnx,pt,pth,ckpt,pkl,pickle,joblib,bin,h5,pb,tflite}'
    - '**/{model-manifest,model_manifest,mlbom,aibom}*.{json,yml,yaml}'
    - '**/*{robust,adversarial,evasion,redteam,red-team}*.{py,ipynb,yml,yaml,json}'
    - '**/{model-evals,ai-evals,ml-evals,adversarial-tests,robustness-tests}/**'
    - '**/*{inference,serving,predictor,prediction}*.{py,ts,js,go,java,kt,cs,yml,yaml,json,toml}'
    - '**/*{drift,rollback,shadow-deploy,canary-deploy}*.{py,ts,js,go,java,kt,cs,yml,yaml,json,toml}'
    - '**/{kserve,seldon,bentoml,triton,vllm,ray-serve,torchserve}/**'
  signals:
    - 'mlflow'
    - 'dvc.yaml'
    - 'dvc.lock'
    - 'kubeflow'
    - 'kfp'
    - 'metaflow'
    - 'flytekit'
    - 'Trainer('
    - 'training_args'
    - 'model.fit('
    - 'fine_tune'
    - 'finetune'
    - 'load_dataset('
    - 'dataset_hash'
    - 'data_lineage'
    - 'training_data_version'
    - 'poisoning_scan('
    - 'clean_label'
    - 'safetensors'
    - 'torch.save('
    - 'torch.load('
    - 'onnx.load('
    - 'joblib.load('
    - 'MLmodel'
    - 'registered_model_name'
    - 'transition_model_version_stage'
    - 'model_checksum'
    - 'model.export'
    - 'export_model'
    - 'rollback.register('
    - 'adversarial_examples'
    - 'robust_accuracy'
    - 'attack_success_rate'
    - 'perturbation_budget'
    - 'AutoAttack'
    - 'adversarial-robustness-toolbox'
    - 'CleverHans'
    - 'Foolbox'
    - 'membership inference'
    - 'model inversion'
    - 'reconstruction attack'
    - 'model extraction'
    - 'model stealing'
    - 'model watermark'
    - 'model fingerprint'
    - 'differential privacy'
    - 'Opacus'
    - 'DP-SGD'
    - 'privacy budget'
    - 'vllm'
    - 'text-generation-inference'
    - 'tritonserver'
    - 'serving.kserve.io'
    - 'SeldonDeployment'
    - 'bentoml'
    - 'torchserve'
    - 'ray.serve'
    - 'max_num_seqs'
    - 'max_batch_total_tokens'
    - 'max_concurrent_requests'
    - 'data drift'
    - 'concept drift'
    - 'population_stability_index'
    - 'embedding drift'
    - 'model rollback'
    - 'champion challenger'
    - 'shadow deployment'
    - 'canary deployment'
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
owns:
  - training-data-provenance-and-integrity
  - training-and-finetuning-poisoning
  - model-artifact-integrity-and-change-control
  - adversarial-input-and-evasion-resilience
  - model-extraction-and-weight-theft
  - model-inversion-and-membership-inference
  - model-serving-resource-exhaustion
  - model-security-monitoring-drift-and-rollback
defers:
  prompt-injection: llm-and-ai
  model-output-taint-propagation: llm-and-ai
  chat-exfiltration-channels: llm-and-ai
  tool-call-authority-and-mediation: llm-and-ai
  multi-agent-trust-propagation: llm-and-ai
  rag-retrieval-authorization: llm-and-ai
  derived-store-data-inheritance: llm-and-ai
  llm-data-flow-inventory: llm-and-ai
  denial-of-wallet-controls: llm-and-ai
  model-artifact-provenance: llm-and-ai
  mcp-server-trust: llm-and-ai
  system-prompt-as-control: llm-and-ai
  rate-limiting-and-request-quotas: web-and-api
  authentication-and-credential-flows: web-and-api
  artifact-signing-and-provenance-emission: cicd-and-supply-chain
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  package-dependency-cves: cicd-and-supply-chain
  pipeline-scanner-gating: cicd-and-supply-chain
  runner-and-build-environment-trust: cicd-and-supply-chain
  sbom-generation-and-attachment: cicd-and-supply-chain
  deploy-time-signature-enforcement: cloud-and-iac
  encryption-at-rest-configuration: cloud-and-iac
  iam-policy-and-privilege-scope: cloud-and-iac
  kms-key-lifecycle-and-policy: cloud-and-iac
  network-exposure-and-segmentation: cloud-and-iac
  hardcoded-credentials-and-key-material: crypto-and-key-management
  key-separation-derivation-and-destruction: crypto-and-key-management
  pii-inventory-and-data-map: privacy-and-data-protection
  personal-data-severity-uplift: privacy-and-data-protection
  pseudonymization-and-reidentification-risk: privacy-and-data-protection
  retention-lawfulness-and-deletion-completeness: privacy-and-data-protection
frameworks:
  - owasp-aisvs-1.0
  - owasp-ai-testing-guide-v1
  - nist-ai-100-2-e2025
  - nist-sp-800-218a
  - cwe
severity_floor: low
---

## Scope

This lens audits the trained-model and training-data security lifecycle visible
in source: dataset admission and lineage, training and fine-tuning controls,
model-artifact integrity and promotion, adversarial-evaluation gates, extraction
and privacy-attack defenses, inference-serving availability controls, and the
security path from monitoring through rollback.

The unit of work is a repository-backed defect with a concrete attacker path and
a named security consequence. A model card, an evaluation report, a dataset
manifest, or a deployment file is evidence only for what it contains. Its
presence does not prove that production uses it or that the represented model or
dataset is safe.

### Owns

| Topic | What that means here |
|---|---|
| `training-data-provenance-and-integrity` | Whether training and fine-tuning inputs have attributable origins, immutable identities, transformation lineage, integrity checks, and controlled admission before a trainer consumes them. |
| `training-and-finetuning-poisoning` | Whether attacker-influenced training, labeling, feedback, preference, reinforcement-learning, or fine-tuning data can alter a promoted model without poisoning detection, quarantine, review, and a fail-closed gate. |
| `model-artifact-integrity-and-change-control` | Whether an internally managed model release set has one immutable identity, binds every component and evaluation, is re-evaluated after material change, passes an authorized promotion gate, and is recoverable as one versioned unit. External-artifact authenticity before interpretation remains `model-artifact-provenance`. |
| `adversarial-input-and-evasion-resilience` | Whether models used for a named security-relevant function have modality-appropriate adversarial tests, acceptance thresholds, regression gates, and input anomaly responses. |
| `model-extraction-and-weight-theft` | API-based model cloning and direct theft or unauthorized export of weights, checkpoints, adapters, tokenizers, or safety models. |
| `model-inversion-and-membership-inference` | Technical controls and tests intended to prevent reconstruction of sensitive training attributes or determination that a record was in a training set. |
| `model-serving-resource-exhaustion` | Availability failure at the inference-serving plane: unbounded admission, shared concurrency, queue, batch, accelerator-memory, or fair-share consumption that lets one principal starve other work. |
| `model-security-monitoring-drift-and-rollback` | AI-specific security telemetry, model and dataset identity in events, security-relevant drift thresholds, alert response, controlled rollout, and complete rollback. |

### Does not own

These boundaries are deliberate. Do not duplicate the existing LLM/application
lens under a model-lifecycle label.

- **llm-and-ai retains prompt, agent, RAG, and application-output security.**
  Direct or indirect prompt injection, tool authority, MCP, multi-agent trust,
  RAG authorization, model-output sinks, and chat exfiltration stay there.
- **`model-artifact-provenance` remains llm-and-ai's.** Origin, hub-reference
  pinning, unsafe deserialization, remote code loading, external-artifact
  authenticity and digest verification before interpretation, and whether the
  repository produced an artifact are filed there. This lens begins after
  admission, at the internally managed complete-release identity,
  change-approval, promotion, and rollback boundary.
- **`derived-store-data-inheritance` remains llm-and-ai's.** Embedding
  reversibility, vector-store tenancy, derived-copy retention, and deletion
  propagation do not become membership-inference findings here.
- **`denial-of-wallet-controls` remains llm-and-ai's.** Token, iteration, agent
  loop, tool fan-out, and per-principal spend bounds are application costs. This
  lens owns starvation and exhaustion of the shared inference-serving plane.
- Training-time poisoning is here. A malicious document entering RAG or agent
  memory at runtime remains `prompt-injection` or the applicable RAG topic.
- Model-level perturbation and evasion are here. Instruction hierarchy,
  jailbreak reachability, and what a compliant model can make the application
  do remain in llm-and-ai.
- General CI artifact signing, SBOM production, scanner enforcement, runner
  trust, and dependency CVEs remain in cicd-and-supply-chain. General cloud IAM,
  KMS, network reachability, storage encryption, and image admission remain in
  cloud-and-iac. This lens records their effect on the model lifecycle as
  aggravating context and hands the underlying defect to its owner.
- Privacy-and-data-protection decides whether a data class is personal,
  sensitive, or regulated and applies any severity uplift. This lens decides
  whether a membership-inference or inversion control is technically present
  and testable.

### Source-only evidence and mandatory nonclaims

This lens consumes `source` and no other evidence class. It may establish
committed code paths, manifests, policy and evaluation gates, local test
behavior, and whether a synthetic adverse result blocks a trainer, loader, or
promoter. It must not claim any of the following from repository evidence:

- the contents, cleanliness, consent status, representativeness, or absence of
  poison in a production training dataset;
- the robustness, fairness, safety, accuracy, hallucination rate, privacy loss,
  or backdoor-free status of a deployed model;
- the identity or bytes of the artifact actually serving in an environment;
- live queue depth, accelerator saturation, request distribution, alert
  delivery, drift value, rollback completion, or operational capacity;
- the success or failure of extraction, inversion, membership-inference,
  poisoning, or evasion against a remote provider model.

An unavailable dataset, model artifact, registry, deployment, telemetry stream,
or vendor control is a named coverage gap. It is never replaced with a claim
about its contents or behavior. A T1 harness built from deterministic fakes
proves the repository's gate, not the real model. A T0 or T3 result remains
capped at Medium under `_schema.md` and `_harness.md`.

**Fairness, hallucination, ordinary accuracy loss, and drift are not security
findings by themselves.** File only when the evidence names a security impact:
for example, evasion of malware detection, bypass of an authorization or fraud
control, activation of a backdoor, sensitive-record inference, cross-tenant
capacity starvation, or continued service of a model after a security
regression crossed an approved threshold.

## Activation coverage

Every activation family is PARTIAL because source signals can locate the
control plane but cannot establish production datasets, models, or runtime
behavior.

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| Training data and fine-tuning pipelines | PARTIAL | `training-data-provenance-and-integrity` | Manifest, lineage, admission, and trainer-gate checks are actionable from source; dataset contents and executed training runs are not consumed |
| Model artifacts, registries and promotion | PARTIAL | `model-artifact-integrity-and-change-control` | Registry identity, complete-set binding, change, promotion, and rollback code is reviewable; external artifact admission, built artifacts, and deployed versions are not consumed |
| Adversarial evaluation, extraction and privacy attacks | PARTIAL | `adversarial-input-and-evasion-resilience` | Evaluation and response gates can be exercised with deterministic fixtures; real model attack success remains unassessed |
| Inference serving, security monitoring and rollback | PARTIAL | `model-security-monitoring-drift-and-rollback` | Source configuration and synthetic control events are testable; live capacity, telemetry, drift, alerts, and rollback state are not consumed |

## Framework mapping and known standard gaps

Use the full versioned AISVS identifier in every report. The normative source is
[OWASP AISVS 1.0](https://github.com/OWASP/AISVS/tree/main/1.0/en); its repository
defines the citation form `v1.0-Cx.y.z`. AISVS 1.0 is the stable source. The
`1.01-dev` tree and the research wiki are not normative inputs to a v1.0 claim.

| Lens topic | Direct AISVS 1.0 requirements | Important limit |
|---|---|---|
| Training provenance and integrity | `v1.0-C1.1.2`, `v1.0-C1.1.3`, `v1.0-C1.1.4`, `v1.0-C6.2.1`, `v1.0-C12.5.1` | An inventory and digest prove traceability and integrity relative to a baseline, not that the source is trustworthy or the data is clean |
| Training and fine-tuning poisoning | `v1.0-C1.3.1`, `v1.0-C1.3.5`, `v1.0-C11.4.3` | AISVS requires detection and defenses but no poisoning simulation or quantitative residual attack-success threshold; `v1.0-C6.1.4` is an adjacent general pre-promotion behavioral acceptance control, not a poisoning-specific requirement |
| Model artifact integrity and change | `v1.0-C3.1.1`, `v1.0-C3.1.2`, `v1.0-C3.1.3`, `v1.0-C3.2.2`, `v1.0-C3.2.3`, `v1.0-C3.5.1`, `v1.0-C3.5.3`, `v1.0-C3.5.4`, `v1.0-C6.1.3`, `v1.0-C6.1.4`, `v1.0-C12.5.3` | `v1.0-C6.1.4` is a general behavioral acceptance gate before promotion; it does not prove poisoning resistance. General artifact origin, loading safety, CI signing, and cloud admission remain with their owning lenses |
| Adversarial input and evasion | `v1.0-C11.1.2`, `v1.0-C11.1.3`, `v1.0-C11.1.4`, `v1.0-C11.4.1`, `v1.0-C11.4.2`, `v1.0-C12.2.1` | No required attack corpus, perturbation budget, robustness metric, or general evasion pass threshold |
| Extraction and weight theft | `v1.0-C4.1.4`, `v1.0-C4.3.4`, `v1.0-C4.3.5`, `v1.0-C5.1.1`, `v1.0-C5.2.6`, `v1.0-C11.2.2`, `v1.0-C11.3.1`, `v1.0-C11.3.2`, `v1.0-C11.3.3`, `v1.0-C11.3.4`, `v1.0-C12.2.4` | No extraction-attack simulation is required, and centrally hosted weights have no general server-side at-rest encryption requirement |
| Model inversion and membership inference | `v1.0-C11.2.1`, `v1.0-C11.2.3`, `v1.0-C11.2.4`, `v1.0-C11.2.5` | `v1.0-C11.2.5` requires membership-inference simulation; no numbered requirement mandates a model-inversion reconstruction test or success threshold. `v1.0-C11.2.2` directly sizes inference rate limits against model extraction and is mapped in the extraction row, not here |
| Serving resource exhaustion | `v1.0-C11.2.2` and `v1.0-C12.2.5` are partial; `v1.0-C7.1.2`, `v1.0-C9.1.1`, and `v1.0-C9.1.2` are adjacent application or agent controls | No explicit non-agent inference concurrency, queue, accelerator, fair-share, backpressure, cost-ceiling, or resource-exhaustion load-test requirement |
| Monitoring, drift, and rollback | `v1.0-C3.3.1`, `v1.0-C3.3.2`, `v1.0-C12.1.1`, `v1.0-C12.1.3`, `v1.0-C12.2.2`, `v1.0-C12.3.1`, `v1.0-C12.3.2`, `v1.0-C12.3.3`, `v1.0-C12.3.4`, `v1.0-C12.5.3` | No requirement connects a drift threshold to halt or rollback, mandates predictive-security performance thresholds, periodically exercises rollback, or validates behavior after rollback |

[OWASP AI Testing Guide v1](https://github.com/OWASP/www-project-ai-testing-guide/blob/main/Document/README.md)
supplies test procedures across application, model, infrastructure, and data
layers; it does not replace AISVS as the versioned verification baseline.
[NIST AI 100-2 E2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
supplies the adversarial-ML taxonomy for evasion, poisoning, privacy, extraction,
and availability attacks. [NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final)
governs secure AI-model development lifecycle practices.
[MITRE ATLAS](https://atlas.mitre.org/) is a useful living adversary taxonomy,
but this lens does not declare it as a pinned framework until a specific data
release or commit is recorded. ATLAS identifiers may inform hypotheses but not
versioned conformance claims in this revision.
Use `cwe` only where the repository shows a conventional weakness: for example,
`CWE-353` or `CWE-494` for missing integrity verification, `CWE-862` for an
unprotected weight export, `CWE-400` or `CWE-770` for uncontrolled resource
consumption, and `CWE-778` for missing security event records. Do not invent a
CWE for an AI attack class that CWE does not model.

## Checklist

### 0. Highest-yield source sweeps

Every command has an explicit `.` path and excludes dependency or environment
trees. A hit is an inventory lead, not a finding. A zero-result sweep is not
clearance until a known literal already observed in the checkout is used as a
positive control.

```text
# Training, fine-tuning, dataset, lineage, and experiment orchestration.
rg -n --hidden --glob '!**/{.git,node_modules,.venv,venv,dist,build}/**' 'mlflow|MLproject|dvc\.ya?ml|kubeflow|kfp|metaflow|flytekit|Trainer\(|training_args|model\.fit\(|fine_?tun|load_dataset\(|read_(csv|parquet)\(' .

# Model registry, complete artifact set, signature, digest, and promotion paths.
rg -n --hidden --glob '!**/{.git,node_modules,.venv,venv,dist,build}/**' 'registered_model_name|transition_model_version_stage|models:/|safetensors|torch\.(save|load)\(|onnx\.load\(|joblib\.load\(|verify_signature|artifact_digest|model_checksum|promot(e|ion)|rollback' .

# Adversarial, poisoning, extraction, inversion, and membership tests.
rg -n --hidden -i --glob '!**/{.git,node_modules,.venv,venv,dist,build}/**' 'poison|backdoor|clean[-_ ]label|adversarial|evasion|robust_accuracy|attack_success_rate|perturbation|model extraction|model stealing|membership inference|model inversion|differential privacy|DP-SGD|Opacus' .

# Inference admission, queue, concurrency, batch, accelerator, and fair-share controls.
rg -n --hidden --glob '!**/{.git,node_modules,.venv,venv,dist,build}/**' 'vllm|text-generation-inference|tritonserver|KServe|SeldonCore|BentoML|TorchServe|Ray Serve|max_num_seqs|max_batch_total_tokens|max_concurrent_requests|queue_timeout|BoundedSemaphore|admission|backpressure|fair.?share' .

# Security telemetry, model/data identity, drift, canary, shadow, and rollback.
rg -n --hidden -i --glob '!**/{.git,node_modules,.venv,venv,dist,build}/**' 'model[_ -]?version|dataset[_ -]?version|data drift|concept drift|population_stability_index|security regression|canary deployment|shadow deployment|rollback|kill.?switch|champion.?challenger' .
```

Reconcile each result against manifests and imports. These sweeps cover common
Python and YAML idioms plus serving configuration literals. They do not cover
every framework or custom platform; translate the shapes and record the
translation when an activated language or framework is not represented.

### 1. Training corpus and fine-tuning chain (`training-data-provenance-and-integrity`)

Build one source-to-release ledger. For every base-training, fine-tuning, RLHF,
preference, feedback, evaluation, and safety dataset record:

1. immutable dataset identity and origin;
2. responsible owner, license or use constraint, collection path, and approval;
3. every transform, filter, augmentation, label job, merge, and split;
4. digest or signature creation and the point where it is verified;
5. identities permitted to write source data, labels, manifests, and snapshots;
6. the exact trainer call and whether failure occurs before that call;
7. the checkpoints and final artifacts that inherit the dataset.

A moving URI such as `latest` is not independently a finding. It becomes one
when the training or promotion path trusts it without an immutable resolved
identity and integrity check. Likewise, a hash proves that bytes match a
baseline; it does not prove that the baseline came from an authorized or clean
source.

```detector
match: |
  TRAINING_URI = os.getenv("TRAINING_URI", "s3://fraud-data/latest/")
  rows = load_dataset(TRAINING_URI)
  trainer.fit(rows)
nomatch: |
  spec = verify_signed_manifest("training-manifest.json", APPROVED_DATA_KEYS)
  rows = load_dataset(spec.immutable_uri)
  verify_digest(rows, spec.sha256)
  require_pass(scan_training_data(rows, policy=spec.poisoning_policy))
  trainer.fit(rows)
```

#### Poisoning controls (`training-and-finetuning-poisoning`)

Trace every externally writable or automatically generated source into training.
High-signal sources are user feedback, production conversations, rewards,
preference pairs, annotations from contractors or models, scraped content,
federated updates, and resumed checkpoints. Require quarantine, source
authentication, distribution and label checks, poisoning or backdoor tests,
review, and a fail-closed release decision.

Do not claim that a configured scanner detects real poison. Source can show the
scanner is called and that an adverse result blocks training or promotion.
Effectiveness against the production data and attack is unassessed.

```detector
match: |
  feedback = warehouse.read("accepted_user_feedback")
  preference_rows.append(feedback)
  fine_tune(base_model, preference_rows)
nomatch: |
  feedback = quarantine(warehouse.read("accepted_user_feedback"))
  checked = poisoning_scan(feedback, baseline=approved_distribution)
  approval = reviewer.approve(checked.report_digest)
  require_verified_approval(approval, checked.snapshot_digest)
  fine_tune(base_model, checked.immutable_rows)
```

### 2. Model release set and promotion (`model-artifact-integrity-and-change-control`)

Treat an internally managed release as a set, not one weights file: weights, configuration,
tokenizer, base model, adapters, quantization parameters, preprocessing and
feature definitions, safety/policy models, thresholds, and evaluation results.
Verify that the registry assigns an immutable identity to the complete set,
that every component and evaluation result is bound to that identity, and that
only an authorized promotion record for that exact identity can change the
served release. Verification of an externally sourced artifact before it is
interpreted belongs to `model-artifact-provenance`; deploy-time signature
enforcement belongs to the applicable CI/CD or cloud owner.

Trace every promotion path, including manual scripts and provider-managed model
or routing changes. A material change must select the matching security suite,
enforce its result, produce an immutable audit record, and preserve a rollback
unit that restores all security-relevant state. A rollback that restores weights
but leaves a new tokenizer, adapter, threshold, feature transform, or routing
rule is incomplete.

Unsafe serialization, `trust_remote_code`, hub pinning, and whether a foreign
artifact is trusted belong to `model-artifact-provenance`. Quote them only as
context for a distinct admission or change-control failure.

```detector
match: |
  def promote(model_name):
      uri = f"models:/{model_name}/Production"
      serving.reload(mlflow.pyfunc.load_model(uri))
nomatch: |
  def promote(release):
      registered = registry.require_immutable_release(release.release_id)
      verify_complete_release_binding(registered)
      require_pass(run_security_regression_suite(registered))
      approval = promotion_approvals.require_for(registered.release_digest)
      rollback.register(registered.complete_state)
      serving.reload_registered(registered, approval=approval)
```

### 3. Adversarial model behavior (`adversarial-input-and-evasion-resilience`)

Start with the model's named security function and attacker capability. Select
modality-appropriate evasion, perturbation, poisoning, extraction, and privacy
attacks from `nist-ai-100-2-e2025` and `mitre-atlas`. Require a
version-controlled corpus, tool and model versions, attack parameters, a
predeclared metric and threshold, negative and sensitivity controls, and a
release gate that prevents promotion when the threshold fails.

`robust_accuracy` or `attack_success_rate` without a threat model is not an
answer. A classifier that recommends music and a classifier that blocks malware
do not carry the same security consequence. The candidate must name what the
attacker bypasses or obtains.

```detector
match: |
  report = evaluate_adversarial(candidate, suite="security-evasion-v4")
  logger.warning("adversarial evaluation", extra=report.as_dict())
  registry.promote(candidate)
nomatch: |
  report = evaluate_adversarial(candidate, suite="security-evasion-v4")
  if report.attack_success_rate > SECURITY_EVASION_MAX:
      raise ReleaseBlocked(report.digest)
  registry.promote(candidate, attestation=report.signed_attestation)
```

#### Extraction and direct weight theft (`model-extraction-and-weight-theft`)

For API extraction, inspect per-principal and global rate limits sized to the
extraction threat, coordinated-query detection, output detail, response
actions, evidence retention, and alert metadata. Generic HTTP throttling belongs
to web-and-api; this topic concerns systematic model cloning and the model
owner's response.

For direct theft, trace export, checkpoint download, registry read, debug,
backup, and edge-package paths. File the authorization or storage defect under
its general owner when that is the root cause; this lens owns the model-specific
failure to protect or control the complete weight set.

Do not claim a model contains memorized secrets, that watermarking proves legal
ownership, or that a query detector catches an attack unless those propositions
were tested with valid local evidence. AISVS itself does not require an
extraction simulation.

#### Inversion and membership inference (`model-inversion-and-membership-inference`)

Inspect output minimization and calibration, rate limiting, differentially
private training configuration and accounted privacy budget, and committed
membership-inference tests. A test must define member and non-member populations,
balance or baseline, attack knowledge, confidence interval, and a threshold.

AISVS `v1.0-C11.2.5` directly requires a membership-inference simulation.
There is no equivalent numbered v1.0 requirement for a model-inversion
reconstruction test. Add that test when this topic is in scope, but label it as
an audit extension rather than mis-citing AISVS. Without a repository-shipped
local model and synthetic or explicitly authorized dataset, both attacks remain
UNPROVEN; never query a hosted model under a repository proof recipe.

### 4. Serving, monitoring, and recovery (`model-security-monitoring-drift-and-rollback`)

For `model-serving-resource-exhaustion`, inventory every inference admission
path and shared pool. Read the queue bound, maximum wait, maximum in-flight work,
batch limits, accelerator-memory reservation, cancellation cleanup, overload
response, per-principal or per-tenant fair share, and circuit breaker. Prove that
rejection happens before allocation or inference. A large configured number is
not automatically a vulnerability; show how an untrusted principal can consume
the shared capacity and what other work is starved.

```detector
match: |
  @app.post("/predict")
  async def predict(req: Prediction):
      return await engine.generate(req.inputs)
nomatch: |
  @app.post("/predict")
  async def predict(request: Request, principal=Depends(authenticated_principal)):
      prediction = await read_prediction_at_most(request, MAX_INPUT_BYTES)
      input_tokens = tokenizer.count(prediction.inputs)
      if input_tokens > MAX_INPUT_TOKENS:
          raise RequestTooLarge()
      reservation = await admission.reserve(
          tenant=principal.tenant_id,
          queue_limit=GLOBAL_QUEUE_LIMIT,
          max_wait=QUEUE_TIMEOUT,
          max_in_flight=PER_TENANT_INFLIGHT,
          accelerator_bytes=estimate_accelerator_bytes(input_tokens, MAX_OUTPUT_TOKENS),
          cancel_event=request.disconnect_event,
      )
      try:
          return await engine.generate(
              prediction.inputs,
              max_batch=MAX_BATCH,
              max_output_tokens=MAX_OUTPUT_TOKENS,
              deadline=INFERENCE_DEADLINE,
          )
      finally:
          await reservation.release()
```

`admission.reserve` is acceptable evidence only when its contract and tests show that the queue is bounded, the per-tenant and global capacity checks reject before accelerator allocation, cancellation removes queued work, and every terminal path releases the reservation. An opaque helper name does not prove those properties.

For monitoring, require model and dataset identifiers, provider or runtime,
operation, principal or tenant attribution, resource use, security-evaluation
version, decision, and correlation identifier. Trace each security-relevant
threshold to an alert and then to a deterministic response: pause rollout,
isolate a version, disable a path, or roll back to the last attested complete
state.

```detector
match: |
  if metrics["security_evasion_rate"] > SECURITY_EVASION_MAX:
      logger.error("security regression", extra={"model": active.version})
nomatch: |
  if metrics["security_evasion_rate"] > SECURITY_EVASION_MAX:
      rollout.pause(active.version)
      incident.raise_alert(model=active.version, metric="security_evasion_rate")
      rollback.restore(last_attested_release.complete_state)
```

Do not turn an ordinary input-distribution shift, accuracy change,
hallucination-rate increase, or fairness metric into a security finding. The
record must identify the security control degraded, the threshold approved for
that control, and the unsafe behavior allowed to continue. Source can prove
that the response path exists and responds to a synthetic event; it cannot prove
the production metric crossed the threshold or that an operational rollback
completed.

## Candidate requirements

Every candidate follows `_schema.md`. In this lens especially:

- quote the repository text at `location`; a model card or filename is not a
  substitute for the relevant code or manifest;
- describe a concrete sequence such as "write an accepted feedback record,
  trigger the nightly fine-tune, and promote the resulting checkpoint without
  the poisoning gate", not "an attacker may poison the model";
- name the entry point or use `contingent:` with exactly one runtime fact and
  one runnable query; otherwise use `unknown` and accept the Medium cap;
- separate claimed impact from what source evidence verified;
- identify every unavailable model, dataset, registry, deployment, or telemetry
  premise in Coverage.

## Severity

These are claimed-impact grades. `_schema.md` still caps T0, T3, UNPROVEN,
INCONCLUSIVE, `unknown`, and `contingent:` findings at Medium.

| Condition established | Claimed impact severity |
|---|---|
| An attacker-controlled training or fine-tuning source reaches a production promotion path without integrity, poisoning detection, or approval and can install a targeted backdoor in a security-relevant model | High |
| A principal with a traced write path can substitute a model-release component that deployment loads without an authorized signature or digest check | High |
| An unauthenticated or low-friction path exports the complete proprietary model weight set, checkpoint, or adapter without server-side authorization | High |
| A model makes or gates a security-relevant decision and the committed promotion path ignores a failed adversarial-security threshold | High |
| A valid local membership-inference or inversion oracle exceeds its approved threshold against a model trained on a repository-established sensitive data class | High |
| A local concurrency oracle shows one untrusted principal can occupy all shared inference slots or accelerator capacity and starve other tenants | High |
| A named security regression crosses its threshold while the source path only logs it and continues serving the affected release | High |
| Training lineage, release-set identity, security telemetry, or rollback state is incomplete, but attacker reachability or production use is not established | Medium |
| A defense-in-depth detector, watermark, audit field, or periodic exercise is absent without a demonstrated attack path | Low |
| Fairness, hallucination, accuracy, or drift has no named security consequence | Not a finding |

## Known false positives

1. **A public or third-party dataset is automatically poisoned.** Origin changes
   the threat model; it does not establish malicious contents. File only a
   missing or bypassable admission control with a traced path.
2. **A digest proves provenance or safety.** It proves equality to a baseline.
   Verify who authorized the baseline, how its identity was bound, and where the
   digest is checked.
3. **A mutable registry alias is always vulnerable.** An alias can be a human
   interface over an immutable resolved digest with signature verification and
   an audited promotion record. Follow the resolution.
4. **Any failed adversarial example is a security issue.** It is a security
   finding only when the model enforces or materially influences a named
   security property.
5. **Differential privacy configuration proves privacy.** Confirm accounting,
   clipping, noise, composition, sampling assumptions, and the test gate. Source
   still does not establish the deployed model's empirical privacy loss.
6. **Raw scores or embeddings imply extraction or inversion.** They can increase
   attack capability, but the finding needs the applicable threat model and an
   exposed path; embedding inheritance remains with llm-and-ai.
7. **A model watermark proves origin.** Treat it as one evidentiary signal, not
   sole attribution or proof of theft.
8. **A high accelerator or batch limit is exhaustion.** Capacity is contextual.
   Show shared allocation, attacker control, absent fair share, and starvation.
9. **No rollback in an offline experiment is a production defect.** Establish a
   promotion or serving path first.
10. **Fairness, hallucination, ordinary drift, or low accuracy is graded under
    security.** Reject it unless the record names a concrete security impact and
    the code path that permits it.

## Proof recipes

All proofs obey `_harness.md`. They run only in a disposable mirror, use the
project's own test runner for T1, install the socket-layer destination recorder
before code that may open a socket, never contact a model hub or hosted
inference endpoint, and never use production data or credentials.

### R1 - Manifest closure and trainer-spy gate (T1)

Use the **registry-driven enumerator** to list every trainer and fine-tuning entry
point plus every referenced dataset manifest. Assert the discovered set against
a non-zero committed set. Seed synthetic clean and adverse dataset manifests:
an altered shard, an unsigned source, a missing transform, a label-distribution
outlier, and a feedback batch without approval. Put a spy immediately before
the real trainer boundary.

Assert every adverse fixture is rejected and the trainer spy records zero calls.
Assert the clean, signed fixture records exactly one call. This proves the
admission gate and fails closed behavior. It does not prove that the production
dataset is clean or that a poisoning detector recognizes unknown attacks.

### R2 - Complete model-release admission and rollback (T1)

Create a synthetic release containing weights bytes, tokenizer, adapter,
configuration, safety threshold, and manifest. Sign it with a test-only key.
Mutate each component one at a time, substitute an unauthorized signer, omit a
component, and change a provider version or route. Assert the loader or promoter
spy records zero calls until signature, completeness, digest, and required
security-evaluation checks pass.

For rollback, promote release B over A, inject a synthetic rollback trigger, and
assert the exact complete state of A is restored. Check weights, tokenizer,
adapter, preprocessing version, policy model, thresholds, and routing. The
positive control promotes an intact release. No artifact is deserialized and no
network is used.

### R3 - Adversarial-security release gate (T1, or T3 when no local seam exists)

Replace the evaluator with deterministic signed reports at values immediately
inside and outside the approved threshold. Enumerate every security-relevant
model release path and assert that a failing report blocks promotion before the
promoter spy is called, an expired or wrong-model report is rejected, and a
passing report bound to the exact release is accepted.

Where the repository already ships a small local test model and synthetic
corpus, its own test runner may additionally execute modality-appropriate
attacks. Otherwise write the attack harness and leave that half at T3 UNPROVEN
with the missing model or dataset named. A fake evaluator proves the gate, never
the model's robustness.

### R4 - Extraction and inference-privacy controls (T1/T3)

Use a local fake inference handler and the **counting fake provider client**.
Replay benign traffic and a deterministic coordinated-query corpus across
several principals. Assert extraction-aware rate limits, query-pattern alerts,
response action, and alert metadata; include sensitivity controls showing the
detector fires and remains silent on the benign fixture. Assert rejection occurs
before the provider counter increments where policy requires it.

Run membership-inference or inversion only against a repository-shipped local
model and synthetic or explicitly supplied non-sensitive data. Predeclare the
baseline, population split, metric, threshold, and assertion. Without those
inputs, leave a runnable local proof at T3 UNPROVEN. Never use these recipes
against a remote provider.

### R5 - Serving fairness and security-triggered rollback (T1)

Stand in for inference with a barrier-controlled fake engine recording
allocations, in-flight work, queue time, cancellation, principal, and release
identity. Submit more concurrent work than the configured capacity from
principal A, then one request from B. Assert the maximum in-flight count never
exceeds the cap, queue wait is bounded, rejected work never reaches the engine,
cancellation releases allocation, and B retains its documented fair share. A
shared global rejection of B is the starvation finding.

Then feed a synthetic security metric event across the exact threshold. Assert
the alert fires, rollout pauses, the active release stops receiving new work,
and the complete last-attested release is selected. Feed ordinary operational
drift as the negative control and assert it does not manufacture a security
incident. This proves controller behavior only; production capacity, alerts, and
rollback remain unverified.

## Framework citations for findings

- `owasp-aisvs-1.0` is the versioned verification baseline; cite the exact
  `v1.0-Cx.y.z` identifiers from the mapping above.
- `owasp-ai-testing-guide-v1` supplies attack-oriented test procedures and
  broader trustworthiness tests. A trustworthiness result becomes a security
  finding only through the named-impact rule in Scope.
- `nist-ai-100-2-e2025` supplies the adversarial-ML vocabulary and attack
  taxonomy, including poisoning, evasion, privacy, extraction, and availability.
- `nist-sp-800-218a` supplies secure AI-model development lifecycle practices.
- `mitre-atlas` supplies technique identifiers where the candidate maps to a
  documented adversary behavior.
- `cwe` is used only for a concrete conventional weakness shown in the
  repository; it is not a substitute taxonomy for model behavior.
