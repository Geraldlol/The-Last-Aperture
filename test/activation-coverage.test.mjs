import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { parseLens, stripFencedBlocks } from '../scripts/lib/frontmatter.mjs'
import { signalActivatorMatches } from '../scripts/lib/activation.mjs'

const LENS_DIR = 'skills/red-team-audit/lenses'
const FIXTURE_MANIFEST = 'fixtures/EXPECTED.md'
const FIXTURE_OWNERSHIP = 'fixtures/OWNERSHIP.tsv'

function indexes(spec = '') {
  if (!spec) return []
  return spec.split(',').flatMap((part) => {
    const [start, end] = part.split('-').map(Number)
    if (end === undefined) return [start]
    return Array.from({ length: end - start + 1 }, (_, offset) => start + offset)
  })
}

function family(id, label, status, anchor, evidence, paths = '', signals = '') {
  return {
    id,
    label,
    status,
    anchor,
    evidence,
    selectors: {
      paths: indexes(paths),
      signals: indexes(signals),
    },
  }
}

// Each selector index addresses one complete scalar in the hash-locked
// activates_on.paths or activates_on.signals array. The test below materializes
// the raw scalar-to-family relation and requires exactly one family for every
// scalar. The hash makes an insertion, removal, reorder or text edit fail before
// an old positional assignment can silently inherit the changed activator.
const CONTRACT = {
  'ai-model-and-mlops-security': {
    hash: '3d7d4abec28e457a',
    families: [
      family(
        'training-data-and-finetuning',
        'Training data and fine-tuning pipelines',
        'PARTIAL',
        'training-data-provenance-and-integrity',
        'Manifest, lineage, admission, and trainer-gate checks are actionable from source; dataset contents and executed training runs are not consumed',
        '0-3',
        '0-17',
      ),
      family(
        'model-artifacts-and-promotion',
        'Model artifacts, registries and promotion',
        'PARTIAL',
        'model-artifact-integrity-and-change-control',
        'Registry identity, complete-set binding, change, promotion, and rollback code is reviewable; external artifact admission, built artifacts, and deployed versions are not consumed',
        '4-5',
        '18-29',
      ),
      family(
        'adversarial-and-privacy-attacks',
        'Adversarial evaluation, extraction and privacy attacks',
        'PARTIAL',
        'adversarial-input-and-evasion-resilience',
        'Evaluation and response gates can be exercised with deterministic fixtures; real model attack success remains unassessed',
        '6-7',
        '30-48',
      ),
      family(
        'serving-monitoring-and-rollback',
        'Inference serving, security monitoring and rollback',
        'PARTIAL',
        'model-security-monitoring-drift-and-rollback',
        'Source configuration and synthetic control events are testable; live capacity, telemetry, drift, alerts, and rollback state are not consumed',
        '8-10',
        '49-67',
      ),
    ],
  },
  'failure-semantics-and-resilience': {
    hash: 'f7d76c755e998cf6',
    families: [
      family(
        'exception-handlers',
        'General exception and handler surfaces',
        'PARTIAL',
        'security-control-failure-mode',
        'Cross-language candidate checks exist, but framework exception propagation and middleware ordering require local reading',
        '0-3',
        '0-8',
      ),
      family(
        'workers-retries-redelivery',
        'Workers, queues, schedulers, retries, and redelivery',
        'PARTIAL',
        'retry-backoff-and-redelivery-safety',
        'Attempt, delay, duplicate, and poison-message checks exist; broker-side delivery policy is not repository evidence unless exported',
        '4-7',
        '9-19,31-32,40-42',
      ),
      family(
        'transactions-compensation-pools',
        'Transactions, compensation, and resource pools',
        'PARTIAL',
        'partial-operation-and-rollback',
        'Application boundaries and cleanup paths are assessed; database and provider atomicity remain domain-specific or external',
        '8-10',
        '20-30,33-39',
      ),
      family(
        'supervisors-health-degraded',
        'Supervisors, health paths, and degraded modes',
        'PARTIAL',
        'safe-degradation-and-last-resort-handling',
        'Source handlers and health decisions are assessed; deployed restart policy and operational recovery are not consumed',
        '11-13',
        '43-48',
      ),
      family(
        'cross-cutting-source',
        'Cross-cutting application source and absence-shaped failure paths',
        'PARTIAL',
        'security-control-failure-mode',
        'Broad source assignment prevents neutral filenames from escaping review; every candidate still needs a traced failure branch, protected decision or side effect, and violated invariant',
        '14',
      ),
    ],
  },
  'native-and-memory-safety': {
    hash: '3a97077af300a698',
    families: [
      family(
        'c-cpp-source',
        'C and C++ source surfaces',
        'PARTIAL',
        'memory-bounds-and-integer-conversion',
        'Cross-language bounds and lifetime checks exist; macros, generated code, target ABI, and whole-program aliasing require local analysis',
        '0-8',
        '0-14',
      ),
      family(
        'rust-unsafe',
        'Rust unsafe and raw-memory surfaces',
        'PARTIAL',
        'use-after-free-and-ownership-lifetime',
        'Unsafe blocks, raw parts, manual initialization, and unsafe trait claims are reviewed; safe Rust and dependency internals are not assumed vulnerable',
        '16-18',
        '15-29',
      ),
      family(
        'ffi-native-extensions',
        'FFI and native extension boundaries',
        'PARTIAL',
        'unsafe-ffi-and-language-boundaries',
        'Major bridge APIs and ownership contracts are covered; generated glue and foreign-runtime guarantees require the selected ABI and version',
        '19-24',
        '30-43',
      ),
      family(
        'native-parsers-drivers',
        'Native parsers, codecs, drivers, and firmware',
        'PARTIAL',
        'native-parser-and-state-machine-safety',
        'Length, offset, state, user-pointer, and incremental-input checks exist; format grammar and device reachability remain repository-specific',
        '25-32',
        '44-55',
      ),
      family(
        'native-verification-hardening',
        'Native build, sanitizer, and fuzz configuration',
        'PARTIAL',
        'native-fuzzing-and-sanitizer-coverage',
        'Committed targets and flags are inventoried; actual release hardening, execution history, and dynamic coverage are not consumed evidence',
        '9-15,33-40',
        '56-76',
      ),
    ],
  },
  'security-observability-and-response': {
    hash: 'f32ab1925efce918',
    families: [
      family(
        'application-events-logging',
        'Application security events and logging frameworks — paths 1–3; signals 1–11',
        'PARTIAL',
        'security-event-coverage',
        'Source emitters and application audit stores can be traced, but generic logger presence neither enumerates security obligations nor proves delivery.',
        '0-2',
        '0-10',
      ),
      family(
        'detection-escalation',
        'Detection, alert routing, escalation, and playbooks — paths 4–6; signals 12–18',
        'PARTIAL',
        'detection-alerting-and-escalation',
        'Committed rules and routing graphs can be parsed and fixture-tested; deployed evaluation, delivery, acknowledgement, and response remain unverified.',
        '3-5',
        '11-17',
      ),
      family(
        'telemetry-pipelines',
        'Telemetry SDKs, exporters, collectors, and shippers — paths 7–9; signals 19–32',
        'PARTIAL',
        'security-telemetry-pipeline-resilience',
        'Source retry, queue, loss-accounting, and failure branches can be reviewed; production capacity, connectivity, ingestion, retention, and noise cannot.',
        '6-8',
        '18-31',
      ),
      family(
        'security-decision-denominator',
        'Application source security-decision denominator — path 10',
        'PARTIAL',
        'security-event-coverage',
        'Broad source assignment is required to discover absent events; security relevance and a complete entry-point denominator still require recon and branch tracing.',
        '9',
      ),
    ],
  },
  'database-and-data-stores': {
    hash: '1c45b8c1294b084f',
    families: [
      family(
        'generic-sql-orm',
        'Generic SQL, ORM and migration surfaces',
        'PARTIAL',
        'database-principal-and-role-boundaries',
        'A provider profile and adapter are required; generic syntax cannot establish engine semantics',
        '0-13',
        '0-7,70',
      ),
      family(
        'postgresql-supabase',
        'PostgreSQL and Supabase surfaces',
        'PARTIAL',
        'database-native-authorization-and-tenant-isolation',
        'The PostgreSQL/Supabase adapter covers native policy semantics; deployed roles and service-key paths still need proof',
        '14',
        '8-10,37-39,48,54,56,63,69,71,76,93',
      ),
      family(
        'sqlserver-azure-sql',
        'SQL Server and Azure SQL surfaces',
        'PARTIAL',
        'database-native-authorization-and-tenant-isolation',
        'The SQL Server adapter separates filter, block, CDC, temporal and execution-context behavior',
        '',
        '11-13,41,49-51,79,95',
      ),
      family(
        'mysql-mariadb-oracle-sqlite',
        'MySQL, MariaDB, Oracle and SQLite surfaces',
        'PARTIAL',
        'database-privileged-code-and-execution-context',
        'Separate adapters prevent definer, role, VPD and embedded-engine semantics from being collapsed',
        '',
        '14-18,40,42,52,53,55,72,75,77,78,80,81,94,96,97',
      ),
      family(
        'firestore-baas',
        'Firestore and BaaS rule surfaces',
        'PARTIAL',
        'database-native-authorization-and-tenant-isolation',
        'Rules, query shape and server-SDK bypass require the Firestore adapter plus IAM evidence',
        '15,16',
        '23,24,44',
      ),
      family(
        'mongodb',
        'MongoDB document-store surfaces',
        'PARTIAL',
        'database-principal-and-role-boundaries',
        'Native roles are evaluated with source collections, views, change streams and server-side scripting',
        '17',
        '19,20,47,64,73,82',
      ),
      family(
        'redis-valkey',
        'Redis and Valkey key-value surfaces',
        'PARTIAL',
        'database-principal-and-role-boundaries',
        'ACL key, channel and command scopes are covered; value-level policy is unsupported',
        '18,19',
        '21,22,45,57,65-67,74,83,84',
      ),
      family(
        'elastic-opensearch',
        'Elasticsearch and OpenSearch surfaces',
        'PARTIAL',
        'database-native-authorization-and-tenant-isolation',
        'Vendor-specific effective-role, alias, script, snapshot and replication semantics remain separate',
        '20,21',
        '27,28,46,88,89',
      ),
      family(
        'dynamodb',
        'DynamoDB item-policy surfaces',
        'PARTIAL',
        'database-native-authorization-and-tenant-isolation',
        'LeadingKeys, attributes, batch, transaction, PartiQL, stream and index paths require one condition matrix',
        '',
        '25,26,43',
      ),
      family(
        'wide-column-graph',
        'Cassandra, Scylla and graph surfaces',
        'PARTIAL',
        'database-integrity-transactions-and-concurrency',
        'Wide-column and graph adapters cover their native units; shared-row tenancy may remain application-only',
        '22-24',
        '29,30,58,85,86',
      ),
      family(
        'vector-warehouse',
        'Vector and warehouse surfaces',
        'PARTIAL',
        'database-lifecycle-and-copy-propagation',
        'Control-plane tenancy and copy behavior are assessed; semantic retrieval remains in llm-and-ai',
        '',
        '31-36,59-62,68,87,90-92',
      ),
      family(
        'copy-operations',
        'Backup, restore, replication and CDC artifacts',
        'PARTIAL',
        'database-replication-cdc-history-and-sharing',
        'A named copy path is inventoried; consistency and authority require the selected engine adapter',
        '25-45',
      ),
      family(
        'connection-configuration',
        'Connection strings and application settings',
        'PARTIAL',
        'database-principal-and-role-boundaries',
        'Host, transport mode and connecting principal are established; engine version is not, so adapter selection still needs a declared version',
        '46-51',
        '98-108',
      ),
    ],
  },
  'cicd-and-supply-chain': {
    hash: '4bf21bc4b88d373c',
    families: [
      family(
        'github-actions',
        'GitHub Actions',
        'COVERED',
        'workflow-trigger-and-script-injection',
        'fixture:V-009',
        '0-4',
        '0-14',
      ),
      family(
        'npm-pnpm',
        'npm and pnpm install or lockfile paths',
        'COVERED',
        'install-and-lifecycle-scripts',
        'detector:install-and-lifecycle-scripts',
        '20-22',
        '24,26-28',
      ),
      family(
        'other-ci-glue',
        'GitLab, Jenkins, CircleCI, Azure Pipelines, Buildkite, shell and Make glue',
        'PARTIAL',
        'ci-secret-and-token-handling',
        'Cross-provider token, runner and shell checks exist; provider semantics are not complete',
        '5-9,11,16,18,19',
        '32-41,49',
      ),
      family(
        'other-packages',
        'Other package ecosystems except Bun, plus registry configuration',
        'PARTIAL',
        'dependency-pinning-and-lockfiles',
        'Generic lock, registry and install checks exist; ecosystem-specific resolution is uneven',
        '23,25-43',
        '25,29-31,47,48',
      ),
      family(
        'provenance-release',
        'Signing, provenance, SBOM, scanner and release configuration',
        'PARTIAL',
        'artifact-signing-and-provenance-emission',
        'Dedicated checklist and proof recipes exist; provider-specific release behavior still needs reading',
        '44-50',
        '15-23,42-46',
      ),
      family(
        'unsupported-ci',
        'Bitbucket, Drone, Cloud Build, CodeBuild, Travis, Taskfile, Fastlane, EAS and Bun',
        'NOT ASSESSED',
        null,
        'These activators have no dedicated actionable body path; report the matching surface as not assessed',
        '10,12-15,17,24,51,52',
      ),
    ],
  },
  'cloud-and-iac': {
    hash: '7efcc62f3b991bef',
    families: [
      family(
        'terraform-hcl',
        'Terraform HCL',
        'COVERED',
        'encryption-at-rest-configuration',
        'fixture:V-010',
        '0',
        '0-14',
      ),
      family(
        'terraform-metadata',
        'Terraform values, state and lock metadata',
        'PARTIAL',
        'terraform-state-protection',
        'State and guard-rail checks exist; values and generated state require format-aware reading',
        '1,3,5,6',
      ),
      family(
        'bicep',
        'Azure Bicep',
        'PARTIAL',
        'network-exposure-and-segmentation',
        'V-016 covers formatted top-level resources; modules, nested children, loops and parameter resolution remain outside the helper',
        '18,19',
        '32-36',
      ),
      family(
        'kubernetes-helm',
        'Kubernetes, Helm, Kustomize and policy YAML',
        'PARTIAL',
        'kubernetes-workload-hardening',
        'Per-document checks and policy recipes exist; rendered and live admission behavior is not fully established',
        '27-36,40',
        '40-60,82',
      ),
      family(
        'docker',
        'Dockerfiles, dockerignore and images',
        'PARTIAL',
        'dockerfile-and-image-content',
        'Final-stage, ignored-content and image-content checks exist; Compose semantics are not covered by them',
        '22-25',
        '61-65',
      ),
      family(
        'rego',
        'Rego policy',
        'PARTIAL',
        'kubernetes-rbac-and-admission',
        'A detector pair covers default-allow; configured decision entrypoints still require tracing',
        '39',
      ),
      family(
        'firebase',
        'Firebase and BaaS rules',
        'PARTIAL',
        'baas-security-rules',
        'Rule checks exist without a committed fixture pair',
        '46-49',
        '83',
      ),
      family(
        'scanner-config',
        'Checkov and cloud scanner configuration',
        'PARTIAL',
        'image-cve-exposure',
        'Checkov, image-scanner and policy-engine inventory exists; pipeline gating belongs to the CI lens',
        '41',
        '73-81',
      ),
      family(
        'tflint',
        'TFLint configuration',
        'NOT ASSESSED',
        null,
        'The path activates inventory only; this lens has no TFLint-specific actionable review path',
        '42',
      ),
      family(
        'cloud-sdk-signals',
        'Cloud SDK and resource-positive signals',
        'PARTIAL',
        'iam-policy-and-privilege-scope',
        'Positive call and policy checks exist; SDK control-flow coverage is generic',
        '',
        '24-31,37-39,66-72',
      ),
      family(
        'unsupported-iac',
        'CloudFormation, SAM, ARM JSON, CDKTF, Terraform JSON, Pulumi, Serverless Framework and AWS CDK',
        'NOT ASSESSED',
        null,
        'No syntax-aware absence sweep; report these stacks as not assessed',
        '2,7-17,20,21',
        '15-23',
      ),
      family(
        'unsupported-deploy',
        'Terragrunt, Compose, Skaffold, eksctl, app.yaml, cloud-init and user-data',
        'NOT ASSESSED',
        null,
        'Activation or inventory only; no dedicated body semantics',
        '4,26,37,38,43-45',
      ),
    ],
  },
  'crypto-and-key-management': {
    hash: '7eab8f327c8b1374',
    families: [
      family(
        'primitive-umbrellas',
        'Multi-language primitive and auth source umbrellas',
        'PARTIAL',
        'legacy-hash-and-cipher-primitives',
        'Construction and misuse checks exist, but the composite activators span uneven language support; the Scala branch is NOT ASSESSED',
        '0,1,3,6',
        '0-3,6,7,9,10',
      ),
      family(
        'apex-primitives',
        'Apex crypto, signature and webhook sources',
        'PARTIAL',
        'hmac-and-constant-time-comparison',
        'V-014 measures the HMAC comparison path, but both assigned Apex activators are compound inventories',
        '4',
        '4',
      ),
      family(
        'swift-primitives',
        'Swift CryptoKit, swift-crypto and CommonCrypto signals',
        'PARTIAL',
        'csprng-and-token-entropy',
        'Scoped nonce, HMAC, digest and RNG checks exist; there is no compiled fixture pair',
        '',
        '5',
      ),
      family(
        'auth-protocols',
        'JWT, JWKS, JOSE, OAuth, OIDC, SAML and SSO source umbrella',
        'PARTIAL',
        'jwt-jws-and-jwks-verification',
        'V-003 measures the JWT path; OAuth, OIDC, SAML and the remaining languages require separate checklist reads',
        '2',
        '8',
      ),
      family(
        'password-kdf',
        'Password and KDF source paths',
        'PARTIAL',
        'password-hashing-and-kdf-parameters',
        'Parameter and storage-format checks exist, but the multi-language glob has no measured pair',
        '5',
      ),
      family(
        'tls-assets',
        'TLS configuration and committed key assets',
        'PARTIAL',
        'tls-and-certificate-validation',
        'Actionable checks exist; version, parser and runtime behavior still govern the verdict',
        '7-10',
      ),
      family(
        'inventory-agility-migration',
        'Cryptographic inventory, agility, and migration artifacts',
        'PARTIAL',
        'cryptographic-inventory-and-discovery',
        'Focused inventory and migration artifacts activate the lens; completeness, deployed overrides, and operational migration readiness remain unverified',
        '11',
        '11-20',
      ),
    ],
  },
  'hipaa-and-phi': {
    hash: 'aa0e6dabc1a8c60d',
    families: [
      family(
        'phi-discovery',
        'Patient, PHI, clinical, consent and audit-data discovery',
        'PARTIAL',
        'phi-classification',
        'Classification and audit checks exist; broad vocabulary activation is not proof that every data flow was traced',
        '0-7,12,13,15,22,23',
        '7,18,19',
      ),
      family(
        'health-formats',
        'FHIR, HL7 and X12 content',
        'PARTIAL',
        'phi-classification',
        'Classification and message-shaped checks exist; parser- and transaction-specific coverage is incomplete',
        '8-10,18-21',
        '0-2,5',
      ),
      family(
        'baa',
        'Business-associate perimeter and BAA artifacts',
        'PARTIAL',
        'baa-coverage-determination',
        'A dedicated perimeter decision path exists; executed agreements and provider status remain outside the repository',
        '14',
      ),
      family(
        'deidentification',
        'De-identification and anonymization paths',
        'PARTIAL',
        'phi-deidentification-standard',
        'Safe Harbor, expert-determination and re-identification checks exist; runtime data cannot be established from source alone',
        '16,17',
        '21',
      ),
      family(
        'lower-environments',
        'Seed, fixture and lower-environment patient data',
        'PARTIAL',
        'phi-in-lower-environments',
        'Provenance and crosswalk checks exist; repository fixtures do not establish every deployed lower environment',
        '24,25',
      ),
      family(
        'salesforce-ephi',
        'Salesforce declarative ePHI, grants, destinations and audit metadata',
        'PARTIAL',
        'phi-classification',
        'Metadata detectors and reading paths exist; licensed org controls and deployed grants remain external',
        '26-34',
        '8-11,20',
      ),
      family(
        'tracking-messaging-llm',
        'Tracking, replay, messaging and LLM flows carrying ePHI',
        'PARTIAL',
        'phi-tracking-technologies',
        'Destination and telemetry checks exist; vendor defaults and complete data-flow tracing remain manual',
        '35-39',
        '12-17',
      ),
      family(
        'unsupported-clinical',
        'C-CDA, clinical coding libraries and named EHR, clearinghouse or cloud-healthcare SDKs',
        'NOT ASSESSED',
        null,
        'Activation-only format and vendor families; no dedicated actionable body checks',
        '11',
        '3,4,6',
      ),
    ],
  },
  'llm-and-ai': {
    hash: '245a86b33db633d4',
    families: [
      family(
        'mcp',
        'MCP server, client and configuration surfaces',
        'PARTIAL',
        'mcp-server-trust',
        'Authority, transport and trust checks exist; MCP implementation coverage is not provider-complete',
        '5-8',
        '36',
      ),
      family(
        'agent-runners',
        'Tool authority and autonomous agent runners',
        'PARTIAL',
        'agent-runner-authority',
        'V-015 measures the body check, but the assigned runner and authority signals are compound inventories',
        '',
        '37,43-45,49-52',
      ),
      family(
        'langchain',
        'LangChain framework signals',
        'PARTIAL',
        'prompt-injection',
        'V-004 contains framework-shaped stand-ins but no LangChain activator; no measured LangChain fixture establishes activation coverage',
        '',
        '6-10',
      ),
      family(
        'langgraph',
        'LangGraph configuration and signals',
        'PARTIAL',
        'multi-agent-trust-propagation',
        'StateGraph and authority checks exist; no LangGraph-specific fixture proves activation and behavior together',
        '9',
        '11',
      ),
      family(
        'local-retrieval',
        'Local retrieval, Chroma, FAISS and embedding flows',
        'PARTIAL',
        'rag-retrieval-authorization',
        'Retrieval authorization and derived-store checks exist; ingestion and runtime filters still require tracing',
        '12',
        '30,34,40-42',
      ),
      family(
        'remote-vector',
        'Pinecone, Weaviate, Qdrant and pgvector flows',
        'PARTIAL',
        'rag-retrieval-authorization',
        'Generic retrieval checks exist; remote vector-store authorization and tenancy semantics are provider-specific',
        '',
        '31-33,35',
      ),
      family(
        'provider-model-template',
        'Provider calls, model loading, templates and notebooks',
        'PARTIAL',
        'llm-provider-template-inventory',
        'Generic inventory and sink checks exist; provider, serialization, template and notebook semantics are not complete',
        '3,4,11',
        '0-5,18-24,28,38,39,46-48,53',
      ),
      family(
        'broad-source-umbrellas',
        'Mixed-language prompt, agent and retrieval source umbrellas',
        'PARTIAL',
        'llm-provider-template-inventory',
        'Python and JavaScript checks are actionable; Ruby, Go, Java, Kotlin and C# branches remain NOT ASSESSED',
        '0-2',
      ),
      family(
        'unsupported-llm',
        'LlamaIndex, Haystack, Semantic Kernel, PydanticAI, Instructor, Guardrails, vLLM, TGI, Ollama, Vertex and Modelfile',
        'NOT ASSESSED',
        null,
        'Named activators without dedicated actionable body paths',
        '10',
        '12-17,25-27,29',
      ),
    ],
  },
  'mobile-app-security': {
    hash: '4d7b13a050eb575f',
    families: [
      family(
        'react-native',
        'React Native, Expo, Metro and EAS',
        'PARTIAL',
        'mobile-local-data-storage',
        'Storage and configuration checks exist, but app.config uses a compound extension activator and the family is not uniformly measured',
        '0-4',
        '0,2-15,20-27,32,63-66',
      ),
      family(
        'react-native-web',
        'React Native Web',
        'NOT ASSESSED',
        null,
        'The signal activates the lens, but browser-only React Native Web behavior has no dedicated path',
        '',
        '1',
      ),
      family(
        'android-metadata',
        'Android manifest, Gradle, network and platform API surfaces',
        'COVERED',
        'mobile-cleartext-and-ats-config',
        'detector:mobile-cleartext-and-ats-config',
        '5-9,17,21',
        '18,19,28-31,39-44,48,51-58,61,62',
      ),
      family(
        'ios-metadata',
        'iOS plist, entitlements, CocoaPods, privacy manifest and universal links',
        'PARTIAL',
        'privacy-manifest-and-store-declarations',
        'Actionable platform checks exist; native runtime behavior remains incomplete',
        '10-13,18,20,22',
        '33-38,45-47,49,50,59,67',
      ),
      family(
        'unscoped-swift-objc',
        'Unscoped Swift and Objective-C source globs',
        'PARTIAL',
        'platform-keystore-key-custody',
        'Native API checks exist only after iOS corroboration; these broad globs also activate non-mobile source trees',
        '14,15',
      ),
      family(
        'unscoped-jvm',
        'Unscoped Kotlin, KTS and Java source glob',
        'PARTIAL',
        'mobile-build-and-runtime-flags',
        'Android API checks exist only after platform corroboration; the broad glob also activates server-side JVM projects',
        '16',
      ),
      family(
        'flutter',
        'Flutter and Dart application signals',
        'NOT ASSESSED',
        null,
        'Signals still activate the lens, but Dart behavior has no executable coverage',
        '',
        '16,17,60',
      ),
      family(
        'fastlane',
        'Fastlane repository paths',
        'NOT ASSESSED',
        null,
        'Fastlane activates inventory only; this lens has no dedicated actionable Fastlane review path',
        '19',
      ),
    ],
  },
  'privacy-and-data-protection': {
    hash: '0179be1bf144e88e',
    families: [
      family(
        'browser-consent-gpc',
        'Browser consent, cookie, tracker and GPC surfaces',
        'PARTIAL',
        'consent-gating-of-trackers',
        'Consent and GPC detectors exist, but the assigned multi-language brace paths make family-wide activation coverage partial',
        '0,3-5,14',
        '0-2,13-18,31-33',
      ),
      family(
        'policy-destination',
        'Privacy policy, destination, marketing and residency surfaces',
        'PARTIAL',
        'third-party-destination-inventory',
        'Inventory and opt-out checks exist; legal basis, contracts and deployed destinations require external evidence',
        '1,15',
        '58-68',
      ),
      family(
        'named-analytics',
        'PostHog, Segment and session-replay surfaces',
        'PARTIAL',
        'consent-gating-of-trackers',
        'PostHog, Segment and replay checks are actionable; vendor defaults and runtime initialization still require reading',
        '2',
        '19,22,24-30',
      ),
      family(
        'unsupported-analytics',
        'Mixpanel, Amplitude and RudderStack signals',
        'NOT ASSESSED',
        null,
        'Named activation signals without a dedicated stack-specific actionable body path',
        '',
        '20,21,23',
      ),
      family(
        'unsupported-cmp',
        'CMP product signals',
        'NOT ASSESSED',
        null,
        'The generic consent model is actionable, but these products have no stack-specific review path',
        '',
        '3-12',
      ),
      family(
        'stripe-card-data',
        'Stripe and card-data signals',
        'COVERED',
        'pci-scope-and-cardholder-data',
        'detector:pci-scope-and-cardholder-data',
        '',
        '34,35,39-44',
      ),
      family(
        'payment-umbrellas',
        'Mixed-language payment pages and processor webhook paths',
        'PARTIAL',
        'payment-page-script-authorization',
        'Generic payment and destination checks exist; non-Stripe provider branches remain NOT ASSESSED',
        '6,7',
      ),
      family(
        'unsupported-payments',
        'Braintree, Adyen and PayPal SDK signals',
        'NOT ASSESSED',
        null,
        'Named provider activators without dedicated stack-specific checks',
        '',
        '36-38',
      ),
      family(
        'dsr-retention',
        'DSR, erasure, retention and pseudonymization paths',
        'PARTIAL',
        'retention-lawfulness-and-deletion-completeness',
        'Actionable lifecycle checks exist; the broad multi-language paths are not stack-complete',
        '8,9',
        '48-57',
      ),
      family(
        'schema-orm',
        'Migration, schema, model and ORM inventory',
        'PARTIAL',
        'collection-side-minimization',
        'Inventory and minimization checks exist; framework-specific schema semantics remain uneven',
        '10-13',
        '69-74',
      ),
      family(
        'fingerprinting',
        'Fingerprinting and storage-free identification signals',
        'PARTIAL',
        'fingerprinting-and-tracking-techniques',
        'Dedicated review questions exist; runtime entropy and destination use require measurement',
        '',
        '45-47',
      ),
    ],
  },
  'salesforce-platform': {
    hash: '5a745a982e3675c1',
    families: [
      family(
        'force-app-umbrella',
        'force-app repository umbrella',
        'PARTIAL',
        'sfdx-deploy-exposure',
        'The umbrella activates all Salesforce source and metadata; the narrower rows below determine actual coverage',
        '0',
      ),
      family(
        'apex',
        'Apex classes, triggers and scripts',
        'COVERED',
        'apex-entry-point-exposure',
        'fixture:V-012',
        '1-4,27',
        '0-22',
      ),
      family(
        'lwc',
        'LWC source and UI API signals',
        'COVERED',
        'lwc-aura-vf-output-sinks',
        'detector:lwc-aura-vf-output-sinks',
        '5,6',
        '23,27-30',
      ),
      family(
        'aura-vf',
        'Aura and Visualforce source',
        'PARTIAL',
        'lwc-aura-vf-output-sinks',
        'Dedicated output and parameter checks exist; component semantics and fixture coverage are incomplete',
        '7-10',
        '24-26',
      ),
      family(
        'flow',
        'Flow metadata',
        'PARTIAL',
        'flow-run-context-and-authz',
        'Run-context and authorization checks exist; Flow graph and invoked-action coverage remain manual',
        '11',
      ),
      family(
        'permission-sharing',
        'Object, permission-set, permission-group, profile and sharing metadata',
        'COVERED',
        'permission-set-and-profile-grants',
        'fixture:V-013',
        '12-16',
      ),
      family(
        'credential-integration',
        'Credential, trusted-site, connected-app, custom metadata and settings surfaces',
        'PARTIAL',
        'named-and-external-credentials',
        'Dedicated credential, redirect and connected-app checks exist; deployed secret values remain external',
        '17-23',
        '37,38',
      ),
      family(
        'sites-networks',
        'Sites and Experience Cloud network metadata',
        'PARTIAL',
        'guest-user-and-site-exposure',
        'Guest-access and sharing checks exist; org-side membership and publication remain external',
        '24,25',
      ),
      family(
        'static-resources',
        'Static resources',
        'PARTIAL',
        'lwc-aura-vf-output-sinks',
        'Bundle and output-sink checks exist; generated and vendored content needs provenance-aware reading',
        '26',
      ),
      family(
        'sfdx-tooling',
        'SFDX project, deployment tooling and local auth artifacts',
        'PARTIAL',
        'sfdx-deploy-exposure',
        'Repository and secret-artifact checks exist; org-side deployment behavior remains external',
        '28',
        '31-36,39-45',
      ),
      family(
        'package-forceignore',
        'package.xml and .forceignore',
        'NOT ASSESSED',
        null,
        'Activation or repository inventory only; no dedicated security semantics',
        '29,30',
      ),
    ],
  },
  'threat-modeling': {
    hash: '99b41150a62b9d60',
    families: [
      family(
        'architecture-docs',
        'Architecture documents, ADRs, RFCs, Mermaid, PlantUML, MMD and BPMN',
        'PARTIAL',
        'threat-model-input-anchors',
        'Text-backed participants and flows can be inventoried; there is no committed fixture pair',
        '0-7,9,10',
        '0,1,12,13',
      ),
      family(
        'drawio',
        'Draw.io',
        'PARTIAL',
        'threat-model-input-anchors',
        'Inline XML can be triaged; compressed or mixed pages remain NO VERDICT',
        '8',
      ),
      family(
        'deployment-topology',
        'Compose, multi-deployable, Kubernetes and service-mesh boundaries',
        'PARTIAL',
        'trust-boundary-inventory',
        'Transport and policy inventories exist; deployed topology still requires anchoring',
        '11,16-21,23-25',
        '2-5',
      ),
      family(
        'transport-integration',
        'Inter-service transport, webhook and outbound-integration signals',
        'PARTIAL',
        'exfiltration-path-enumeration',
        'Code-derived boundary and egress inventories exist; runtime destinations and broker policy remain external',
        '',
        '7,10',
      ),
      family(
        'tenancy-identity',
        'Multi-tenancy and identity-broker signals',
        'PARTIAL',
        'trust-boundary-inventory',
        'Tenant and identity boundaries can be inventoried; deployed isolation and broker policy still require proof',
        '',
        '8,9',
      ),
      family(
        'admin-user-surfaces',
        'Admin and end-user surface signals',
        'PARTIAL',
        'architecture-trust-design-gaps',
        'Privilege-boundary review paths exist; route reachability and deployed guard order require anchoring',
        '',
        '11',
      ),
      family(
        'unsupported-formats',
        'OpenAPI, AsyncAPI, protobuf and Terraform format inventories',
        'NOT ASSESSED',
        null,
        'Discovery or inventory only; no format-specific threat semantics',
        '12-15,22',
        '6',
      ),
    ],
  },
  'web-and-api': {
    hash: 'eb757277a921c03f',
    families: [
      family(
        'express-node',
        'Express framework and middleware signals',
        'COVERED',
        'authz-object-level',
        'fixture:V-001',
        '',
        '0,5-10',
      ),
      family(
        'node-server-path',
        'Generic Node server filename path',
        'PARTIAL',
        'api-inventory-and-version-deprecation',
        'The compound extension glob inventories Node-shaped entry points but does not establish Express or framework coverage',
        '10',
      ),
      family(
        'generic-route-umbrellas',
        'Generic route, handler, middleware, API and mixed-language source umbrellas',
        'PARTIAL',
        'authz-function-level',
        'Cross-language source and sink checks exist; a matching path alone does not establish framework coverage',
        '0-5,11,12',
        '14-16',
      ),
      family(
        'java-spring',
        'Java or Kotlin controllers and Spring security surfaces',
        'PARTIAL',
        'injection-sql-nosql-orm',
        'V-002 proves the JDBC body detector, not web activation; Spring route and security checks remain framework-partial',
        '9,28',
        '37-41',
      ),
      family(
        'ruby-rails',
        'Ruby on Rails surfaces',
        'PARTIAL',
        'deserialization-and-xxe',
        'V-008 proves a Ruby deserialization detector, not a declared Rack activator; Rails checks remain framework-partial',
        '15,16',
        '46-48',
      ),
      family(
        'python-web',
        'Django, Flask and DRF surfaces',
        'PARTIAL',
        'csrf',
        'Dedicated and generic checklist paths exist; framework-complete fixture pairs do not',
        '13,14',
        '25,28-31,35',
      ),
      family(
        'aspnet-laravel',
        'ASP.NET and Laravel surfaces',
        'PARTIAL',
        'authz-function-level',
        'Dedicated and generic checklist paths exist; framework-complete fixture pairs do not',
        '17,18,29',
        '42-45,49,50',
      ),
      family(
        'graphql-streaming',
        'GraphQL, WebSocket, SSE, gRPC and OpenAPI surfaces',
        'PARTIAL',
        'graphql-api-surface',
        'Dedicated protocol checklists exist; schema, transport and generated behavior remain incomplete',
        '19-25',
        '17-24,57-63',
      ),
      family(
        'node-alt-frameworks',
        'Koa, Hono, Nest and Next surfaces',
        'PARTIAL',
        'authz-function-level',
        'Narrow route and sink checks exist; broad framework semantics are not covered',
        '6-8,30',
        '2-4,11',
      ),
      family(
        'chi',
        'Go Chi signals',
        'PARTIAL',
        'authz-function-level',
        'Middleware-order guidance explicitly covers Chi; router-complete detector coverage does not',
        '',
        '53',
      ),
      family(
        'outbound-http',
        'Outbound Python, Go and Node HTTP-client signals',
        'PARTIAL',
        'third-party-api-response-trust',
        'SSRF, destination and response-trust checks exist; client-specific redirect and resolver behavior requires reading',
        '',
        '32-34,56,64-66',
      ),
      family(
        'webhooks',
        'Webhook receiver and signature signals',
        'PARTIAL',
        'webhook-handler-integrity',
        'Signature, freshness and replay checks exist; provider-specific semantics are incomplete',
        '26,27',
        '67-71',
      ),
      family(
        'headers-sinks',
        'Nginx, header configuration and generic output-sink signals',
        'PARTIAL',
        'security-headers-and-csp',
        'Actionable header and sink checks exist; deployment inheritance and framework defaults require reading',
        '32,34,35',
        '72-78',
      ),
      family(
        'browser-runtime',
        'Browser UI paths, window APIs, cross-origin headers and prototype keys',
        'PARTIAL',
        'browser-origin-and-runtime-trust',
        'Dedicated detector pairs cover message-origin validation and prototype-pollution authority gadgets; UI path activation still requires mechanism-specific tracing',
        '36,37',
        '79-85',
      ),
      family(
        'specialized-interpreters',
        'Spreadsheet, naming, cache-text, format, mail and dynamic-regex sinks',
        'PARTIAL',
        'specialized-interpreter-and-format-injection',
        'Dedicated detector pairs cover spreadsheet formulas and ReDoS; the other interpreter families require source-to-sink and runtime-specific validation',
        '38-40',
        '86-111',
      ),
      family(
        'unsupported-web',
        'Fastify, Remix, SvelteKit, FastAPI, Starlette, Gin, Gorilla, Echo, net/http, Caddy and static-host configs',
        'NOT ASSESSED',
        null,
        'Activation-only or isolated literals with no dedicated actionable body path',
        '31,33',
        '1,12,13,26,27,36,51,52,54,55',
      ),
    ],
  },
}

const NO_ACTIVATION = new Map([
  ['ai-generated-code', 'always'],
  ['attack-chaining', 'triage'],
  ['business-logic', 'triage'],
  ['completeness', 'triage'],
])

// Scoped to the activation scalars this check is about. `activates_on` also
// carries `evidence_classes`, which declares which evidence classes the lens
// consumes and has no paths, signals or family selectors in it; hashing it here
// would make every evidence-class edit demand a re-audit of all 1315 scalars.
function activationHash(frontmatter) {
  const activatesOn = frontmatter.activates_on ?? {}
  return createHash('sha256')
    .update(JSON.stringify({
      paths: activatesOn.paths ?? [],
      signals: activatesOn.signals ?? [],
    }))
    .digest('hex')
    .slice(0, 16)
}

function tableRows(section, lens) {
  const rows = section
    .split(/\r?\n/)
    .filter((line) => /^\|.*\|\s*$/.test(line))
    .map((line) => line.slice(1, line.lastIndexOf('|')).split('|').map((cell) => cell.trim()))
    .filter(([label]) => label !== 'Activation family' && !/^---+$/.test(label))

  for (const [index, row] of rows.entries()) {
    assert.equal(row.length, 4, `${lens}: activation table row ${index + 1} must have four cells`)
  }
  return rows
}

function expectedRows(families) {
  return families.map(({ label, status, anchor, evidence }) => [
    label,
    status,
    anchor === null ? '—' : `\`${anchor}\``,
    evidence,
  ])
}

function bodyWithoutFrontmatter(text) {
  return text.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n?/, '')
}

function headingBlocks(text, anchor) {
  const rawBody = bodyWithoutFrontmatter(text)
  const matches = [...rawBody.matchAll(/^###\s+.*$/gm)]
    .filter((match) => [...match[0].matchAll(/`([^`]+)`/g)].some((token) => token[1] === anchor))

  return matches.map((match) => {
    const rest = rawBody.slice(match.index + match[0].length)
    const nextHeading = /\r?\n#{2,3}\s+/.exec(rest)
    return rawBody.slice(
      match.index,
      nextHeading ? match.index + match[0].length + nextHeading.index : rawBody.length,
    )
  })
}

function fixtureIndex() {
  const manifest = readFileSync(FIXTURE_MANIFEST, 'utf8')
  const ids = new Set([...manifest.matchAll(/^\|\s*([VC]-\d{3})\s*\|/gm)].map((match) => match[1]))
  const owners = new Map()
  const caught = new Set()

  for (const line of manifest.split(/\r?\n/).filter((entry) => /^\|\s*V-\d{3}\s*\|/.test(entry))) {
    const cells = line.slice(1, line.lastIndexOf('|')).split('|').map((cell) => cell.trim())
    const owner = /^`([^`]+)`\s*\//.exec(cells[6] ?? '')
    assert.ok(owner, `${cells[0]}: vulnerable fixture must name an owning lens`)
    owners.set(cells[0], owner[1])
    if (/^\*\*CAUGHT\b/.test(cells.at(-1) ?? '')) caught.add(cells[0])
  }

  const ownershipRows = readFileSync(FIXTURE_OWNERSHIP, 'utf8')
    .split(/\r?\n/)
    .flatMap((line, index) => {
      if (!line || line.startsWith('#')) return []
      const fields = line.split('\t')
      assert.ok(
        fields.length === 2 || fields.length === 3,
        `${FIXTURE_OWNERSHIP}:${index + 1}: malformed ownership row`,
      )
      return [{ id: fields[0], selector: fields[1], line: index + 1 }]
    })
  const trackedPaths = execFileSync(
    'git',
    ['ls-files', 'fixtures/vulnerable', 'fixtures/clean'],
    { encoding: 'utf8' },
  )
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .map((path) => path.replace(/^fixtures\//, '').replaceAll('\\', '/'))

  return { ids, owners, caught, ownershipRows, trackedPaths }
}

function ownershipSelectorMatches(selector, path) {
  return selector.endsWith('/**')
    ? path.startsWith(selector.slice(0, -2))
    : path === selector
}

function expandBraceAlternations(pattern) {
  const match = /\{([^{}]*,[^{}]*)\}/.exec(pattern)
  if (!match) return [pattern]
  return match[1].split(',').flatMap((alternative) => expandBraceAlternations(
    `${pattern.slice(0, match.index)}${alternative}${pattern.slice(match.index + match[0].length)}`,
  ))
}

function globRegex(pattern) {
  let source = '^'
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index]
    if (char === '*') {
      if (pattern[index + 1] === '*') {
        while (pattern[index + 1] === '*') index += 1
        if (pattern[index + 1] === '/') {
          source += '(?:.*/)?'
          index += 1
        } else {
          source += '.*'
        }
      } else {
        source += '[^/]*'
      }
      continue
    }
    if (char === '?') {
      source += '[^/]'
      continue
    }
    source += /[\\^$+.[\]()|]/.test(char) ? `\\${char}` : char
  }
  return new RegExp(`${source}$`)
}

function pathActivatorMatches(pattern, path) {
  return expandBraceAlternations(pattern).some((expanded) => globRegex(expanded).test(path))
}

function fixtureActivatesFamily(fixtureId, familySpec, rawActivators, fixtures) {
  const ownedPaths = fixtures.ownershipRows
    .filter(({ id }) => id === fixtureId)
    .flatMap(({ selector }) => fixtures.trackedPaths.filter((path) => ownershipSelectorMatches(selector, path)))
  assert.ok(ownedPaths.length > 0, `${fixtureId}: ownership selectors match no tracked fixture payload`)

  const pathPatterns = familySpec.selectors.paths.map((index) => rawActivators.paths[index])
  const signalLiterals = familySpec.selectors.signals.map((index) => rawActivators.signals[index])

  return ownedPaths.some((fixturePath) => {
    const logicalPath = fixturePath.replace(/^(?:vulnerable|clean)\//, '')
    if (pathPatterns.some((pattern) => pathActivatorMatches(pattern, logicalPath))) return true
    const content = readFileSync(join('fixtures', fixturePath), 'utf8')
    return signalLiterals.some((signal) => content.includes(signal))
  })
}

function isCompoundActivator(kind, scalar) {
  if (kind === 'paths') return /\{[^{}]*,[^{}]*\}/.test(scalar)
  return scalar.includes(',') || scalar.includes(' / ')
}

test('fixture relevance matching expands brace globs and globstars', () => {
  assert.equal(pathActivatorMatches('**/*.{ts,js,mjs}', 'src/routes/order.ts'), true)
  assert.equal(pathActivatorMatches('**/*.{ts,js,mjs}', 'server.mjs'), true)
  assert.equal(pathActivatorMatches('**/*.{ts,js,mjs}', 'server.py'), false)
  assert.equal(pathActivatorMatches('.github/workflows/**/*.y*ml', '.github/workflows/pr.yml'), true)
})

test('web activation reaches browser-only and specialized-sink repositories', () => {
  const text = readFileSync(join(LENS_DIR, 'web-and-api.md'), 'utf8')
  const web = parseLens(text, 'web-and-api.md').frontmatter.activates_on
  const contract = CONTRACT['web-and-api']
  const browser = contract.families.find(({ id }) => id === 'browser-runtime').selectors
  const specialized = contract.families.find(({ id }) => id === 'specialized-interpreters').selectors
  const selectedPaths = (selector) => selector.paths.map((index) => web.paths[index])
  const selectedSignals = (selector) => selector.signals.map((index) => web.signals[index])

  for (const path of ['src/components/BillingFrame.tsx', 'legacy/public/main.js']) {
    assert.ok(
      selectedPaths(browser).some((pattern) => pathActivatorMatches(pattern, path)),
      `${path}: browser-only repository must activate web-and-api`,
    )
  }
  for (const content of [
    'window.addEventListener("message", receiveMessage)',
    'response.setHeader("Cross-Origin-Resource-Policy", "same-site")',
  ]) {
    assert.ok(
      selectedSignals(browser).some((signal) => signalActivatorMatches(signal, content)),
      `${content}: browser runtime signal must activate web-and-api`,
    )
  }

  for (const path of ['src/reports/customer-csv-export.ts', 'src/mailers/receipt.py']) {
    assert.ok(
      selectedPaths(specialized).some((pattern) => pathActivatorMatches(pattern, path)),
      `${path}: specialized-sink repository must activate web-and-api`,
    )
  }
  for (const content of [
    'return stringifyCsv(rows)',
    'new InitialContext().lookup(requestedName)',
    'const cache = new MemcachedClient(endpoint)',
    'fprintf(stderr, userControlledFormat)',
    'nodemailer.createTransport(options)',
    'const matcher = new RegExp(request.body.pattern)',
  ]) {
    assert.ok(
      selectedSignals(specialized).some((signal) => signalActivatorMatches(signal, content)),
      `${content}: specialized interpreter signal must activate web-and-api`,
    )
  }
})

test('absence-shaped observability and failure checks activate on neutral source files', () => {
  const cases = [
    {
      lensName: 'security-observability-and-response',
      familyId: 'security-decision-denominator',
      path: 'src/roles.ts',
      content: 'export async function grantAdmin(userId) { await roles.add(userId, "admin") }',
    },
    {
      lensName: 'failure-semantics-and-resilience',
      familyId: 'cross-cutting-source',
      path: 'src/enrich.ts',
      content: 'return Promise.all(request.items.map((item) => enrich(item)))',
    },
    {
      lensName: 'failure-semantics-and-resilience',
      familyId: 'cross-cutting-source',
      path: 'src/policy.ts',
      content: 'default: return true',
    },
  ]

  for (const { lensName, familyId, path, content } of cases) {
    const text = readFileSync(join(LENS_DIR, `${lensName}.md`), 'utf8')
    const activation = parseLens(text, `${lensName}.md`).frontmatter.activates_on
    const selectors = CONTRACT[lensName].families
      .find(({ id }) => id === familyId).selectors
    assert.equal(
      activation.signals.some((signal) => signalActivatorMatches(signal, content)),
      false,
      `${lensName}: regression content must exercise the absence-shaped path rather than an existing signal`,
    )
    assert.ok(
      selectors.paths
        .map((index) => activation.paths[index])
        .some((pattern) => pathActivatorMatches(pattern, path)),
      `${lensName}: ${path} must activate the cross-cutting review`,
    )
  }
})

test('COVERED compound classification distinguishes paths from signals', () => {
  assert.equal(isCompoundActivator('paths', '**/server.{js,ts,mjs}'), true)
  assert.equal(isCompoundActivator('paths', '**/server.js'), false)
  assert.equal(isCompoundActivator('signals', 'claude -p / codex exec'), true)
  assert.equal(isCompoundActivator('signals', 'first, second'), true)
  assert.equal(isCompoundActivator('signals', 'express'), false)
})

test('all nineteen lenses have an exact, drift-checked activation coverage disposition', () => {
  const files = readdirSync(LENS_DIR)
    .filter((name) => name.endsWith('.md') && !name.startsWith('_'))
  const lenses = files.map((file) => {
    const text = readFileSync(join(LENS_DIR, file), 'utf8')
    return { file, text, lens: parseLens(text, file) }
  })
  const fixtures = fixtureIndex()

  assert.equal(lenses.length, 19)
  assert.deepEqual(
    new Set(lenses.map(({ lens }) => lens.name)),
    new Set([...Object.keys(CONTRACT), ...NO_ACTIVATION.keys()]),
  )
  const typedActivationEntries = lenses.flatMap(({ lens }) => ['paths', 'signals'].flatMap((kind) =>
    (lens.frontmatter.activates_on?.[kind] ?? [])
      .map((scalar, index) => `${lens.name}\0${kind}\0${index}\0${scalar}`)))
  assert.equal(typedActivationEntries.length, 1315, 'the exact contract must own all 1315 typed activation entries')
  assert.equal(
    new Set(typedActivationEntries).size,
    1315,
    'lens + kind + index + scalar activation identities must remain unique',
  )
  const lensQualifiedRawScalars = lenses.flatMap(({ lens }) => [
    ...(lens.frontmatter.activates_on?.paths ?? []),
    ...(lens.frontmatter.activates_on?.signals ?? []),
  ].map((scalar) => `${lens.name}\0${scalar}`))
  assert.equal(
    new Set(lensQualifiedRawScalars).size,
    1314,
    'raw scalar duplication drifted; audit repeated text separately from typed ownership',
  )

  for (const { text, lens } of lenses) {
    const noActivation = NO_ACTIVATION.get(lens.name)
    const paths = lens.frontmatter.activates_on?.paths ?? []
    const signals = lens.frontmatter.activates_on?.signals ?? []

    if (noActivation) {
      assert.deepEqual(paths, [], `${lens.name}: ${noActivation} lens must not path-activate`)
      assert.deepEqual(signals, [], `${lens.name}: ${noActivation} lens must not signal-activate`)
      if (noActivation === 'always') assert.equal(lens.frontmatter.always_active, true)
      if (noActivation === 'triage') assert.equal(lens.frontmatter.runs_in, 'triage')
      continue
    }

    const contract = CONTRACT[lens.name]
    assert.equal(
      activationHash(lens.frontmatter),
      contract.hash,
      `${lens.name}: activates_on drifted; re-audit every changed scalar and its family selector`,
    )
    assert.equal(
      new Set(contract.families.map(({ id }) => id)).size,
      contract.families.length,
      `${lens.name}: activation family IDs must be unique`,
    )
    for (const familySpec of contract.families) {
      for (const kind of ['paths', 'signals']) {
        assert.equal(
          new Set(familySpec.selectors[kind]).size,
          familySpec.selectors[kind].length,
          `${lens.name}/${familySpec.id}: duplicate ${kind} selector index`,
        )
      }
    }

    const scalarOwners = new Map()
    for (const [kind, scalars] of Object.entries({ paths, signals })) {
      for (const [index, scalar] of scalars.entries()) {
        const matches = contract.families.filter(({ selectors }) => selectors[kind].includes(index))
        assert.equal(
          matches.length,
          1,
          `${lens.name}/${kind}[${index}] ${JSON.stringify(scalar)} must map exactly once; got ${matches.map(({ id }) => id).join(', ') || 'none'}`,
        )
        if (scalarOwners.has(scalar)) {
          assert.equal(
            matches[0].id,
            scalarOwners.get(scalar),
            `${lens.name}: duplicate raw scalar ${JSON.stringify(scalar)} must retain one family owner across paths and signals`,
          )
        } else {
          scalarOwners.set(scalar, matches[0].id)
        }
      }
      for (const familySpec of contract.families) {
        for (const index of familySpec.selectors[kind]) {
          assert.ok(
            Number.isInteger(index) && index >= 0 && index < scalars.length,
            `${lens.name}/${familySpec.id}: ${kind} selector ${index} is outside the raw activation array`,
          )
        }
      }
    }

    const rows = tableRows(lens.sections['Activation coverage'] ?? '', lens.name)
    assert.deepEqual(
      rows,
      expectedRows(contract.families),
      `${lens.name}: Activation coverage table must be the exact rendered family contract`,
    )

    const unfencedBody = stripFencedBlocks(bodyWithoutFrontmatter(text))
    for (const familySpec of contract.families) {
      const { id, status, anchor, evidence } = familySpec
      assert.ok(evidence, `${lens.name}/${id}: evidence or limit is required`)

      for (const fixtureId of evidence.match(/\b[VC]-\d{3}\b/g) ?? []) {
        assert.ok(fixtures.ids.has(fixtureId), `${lens.name}/${id}: nonexistent fixture ${fixtureId}`)
        if (fixtureId.startsWith('V-')) {
          assert.equal(
            fixtures.owners.get(fixtureId),
            lens.name,
            `${lens.name}/${id}: ${fixtureId} belongs to another lens`,
          )
        }
      }

      if (status === 'NOT ASSESSED') {
        assert.equal(anchor, null, `${lens.name}/${id}: NOT ASSESSED must not claim a body anchor`)
        continue
      }

      const anchorHeadings = [...unfencedBody.matchAll(/^###\s+.*$/gm)]
        .filter((match) => [...match[0].matchAll(/`([^`]+)`/g)].some((token) => token[1] === anchor))
      assert.equal(
        anchorHeadings.length,
        1,
        `${lens.name}/${id}: anchor ${anchor} must resolve to exactly one actionable heading`,
      )

      if (status !== 'COVERED') continue
      for (const [kind, scalars] of Object.entries({ paths, signals })) {
        for (const index of familySpec.selectors[kind]) {
          assert.equal(
            isCompoundActivator(kind, scalars[index]),
            false,
            `${lens.name}/${id}: COVERED cannot own compound ${kind}[${index}] ${JSON.stringify(scalars[index])}`,
          )
        }
      }
      const refs = evidence.split(/;\s*/)
      assert.ok(refs.length > 0, `${lens.name}/${id}: COVERED requires explicit evidence refs`)
      for (const ref of refs) {
        const fixtureRef = /^fixture:(V-\d{3})$/.exec(ref)
        const detectorRef = /^detector:([a-z0-9-]+)$/.exec(ref)
        assert.ok(
          fixtureRef || detectorRef,
          `${lens.name}/${id}: COVERED evidence must be exact fixture:V-NNN or detector:heading-slug refs`,
        )
        if (fixtureRef) {
          assert.ok(fixtures.ids.has(fixtureRef[1]), `${lens.name}/${id}: nonexistent fixture ${fixtureRef[1]}`)
          assert.ok(
            fixtures.caught.has(fixtureRef[1]),
            `${lens.name}/${id}: ${fixtureRef[1]} is not recorded as CAUGHT`,
          )
          assert.equal(
            fixtures.owners.get(fixtureRef[1]),
            lens.name,
            `${lens.name}/${id}: ${fixtureRef[1]} belongs to another lens`,
          )
          assert.ok(
            fixtureActivatesFamily(
              fixtureRef[1],
              familySpec,
              { paths, signals },
              fixtures,
            ),
            `${lens.name}/${id}: ${fixtureRef[1]} matches no path glob or literal signal assigned to this family`,
          )
        }
        if (detectorRef) {
          assert.equal(
            detectorRef[1],
            anchor,
            `${lens.name}/${id}: detector ref must equal the family anchor`,
          )
          const blocks = headingBlocks(text, detectorRef[1])
          assert.equal(
            blocks.length,
            1,
            `${lens.name}/${id}: detector heading ${detectorRef[1]} must resolve exactly once`,
          )
          assert.match(
            blocks[0],
            /```detector\r?\n[\s\S]*?\bmatch:\s*\|[\s\S]*?\bnomatch:\s*\|[\s\S]*?```/,
            `${lens.name}/${id}: detector:${detectorRef[1]} must contain a match/nomatch detector block`,
          )
        }
      }
    }
  }
})
