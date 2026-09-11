// This registry describes public release behavior. It grants no execution
// authority and imports neither a target runtime nor a transport.
function deepFreeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child)
    Object.freeze(value)
  }
  return value
}

export const CAPABILITY_REGISTRY = deepFreeze({
  schema_version: '1.0.0',
  capabilities: [
    {
      id: 'source-review', status: 'AVAILABLE', commands: ['plan', 'next', 'ingest', 'ingest-batch', 'finalize', 'validate'],
      description: 'Sealed repository inventory, scoped review packets, validated result ingestion, and coverage accounting.',
      limitation: 'An external reviewer supplies analysis. Completion and zero findings do not establish security clearance.',
    },
    {
      id: 'review-integration', status: 'AVAILABLE', commands: ['review-template', 'check-result'],
      description: 'Export an inert result template and validate a reviewer result against its sealed packet without ingesting it.',
      limitation: 'Integration helpers do not perform semantic source analysis or run an analysis provider.',
    },
    {
      id: 'source-analysis-provider', status: 'UNAVAILABLE', commands: [],
      description: 'Bundled automated semantic source-analysis provider.',
      limitation: 'The reference byte consumer checks transport behavior; it does not analyze security.',
    },
    {
      id: 'source-pattern-checks', status: 'AVAILABLE_NARROW', commands: ['npm run audit:source-check', 'npm run evaluate:source-check'],
      description: 'Standalone passive JavaScript checks for two literal Node TLS configuration patterns, with source coordinates and repair guidance.',
      limitation: 'Observations remain UNPROVEN; no target execution, automatic ingestion, semantic security verdict, TypeScript/JSX support, or independent quality validation.',
    },
    {
      id: 'status', status: 'AVAILABLE', commands: ['status'],
      description: 'Read saved progress, coverage gaps, failures, and interrupted attempts.',
      limitation: 'Saved state is not evidence that a target remains unchanged.',
    },
    {
      id: 'reports', status: 'AVAILABLE', commands: ['report', 'compare'],
      description: 'Generate Markdown and SARIF reports and compare finding lineages.',
      limitation: 'Disappearance is claimed-fixed or not-observed, never independently verified remediation.',
    },
    {
      id: 'repair-brief', status: 'AVAILABLE', commands: ['repair-brief'],
      description: 'Prepare evidence-linked repair and retest guidance from recorded findings.',
      limitation: 'A brief does not patch a target, execute a retest, or verify a fix.',
    },
    {
      id: 'verdict-assessment', status: 'AVAILABLE', commands: ['verdict'],
      description: 'Explain the evidence supporting and limiting a recorded verdict.',
      limitation: 'Descriptive assessment cannot promote provider claims into controller-authenticated semantic proof.',
    },
    {
      id: 'benchmark', status: 'AVAILABLE', commands: ['benchmark'],
      description: 'Evaluate recorded benchmark submissions against labeled cases and report coverage and accuracy limitations.',
      limitation: 'Fixture tests and evaluator scores do not establish independent real-world detection accuracy.',
    },
    {
      id: 'readiness', status: 'AVAILABLE', commands: ['doctor', 'capabilities'],
      description: 'Inspect local installation prerequisites and publish this capability registry without target execution.',
      limitation: 'Static checks do not inspect a Docker daemon, verify an image, or prove runtime readiness.',
    },
    {
      id: 't1-proof', status: 'AVAILABLE_NARROW', commands: ['run-proof'],
      description: 'Sealed, network-denied repository proof through the fixed Docker worker route.',
      limitation: 'Requires a compatible immutable Node/npm worker, sealed inputs, and the existing proof contract; no arbitrary runtime support.',
    },
    {
      id: 't2-service-proof', status: 'AVAILABLE_NARROW', commands: ['run-service-proof'],
      description: 'One foreground Node/npm service with loopback probes in separate isolated sessions and verified cleanup.',
      limitation: 'Lifecycle evidence remains UNPROVEN without a controller-authenticated semantic oracle. Browser and multi-service/database stacks are unsupported.',
    },
    {
      id: 'https-recon', status: 'AVAILABLE_NARROW', commands: ['http-recon go'],
      description: 'One bounded HTTPS reconnaissance action through its existing public controller.',
      limitation: 'A URL entry point is not a comprehensive website assessment.',
    },
    {
      id: 'authenticated-http', status: 'AVAILABLE_NARROW', commands: ['http-authed campaign-attested', 'http-authed campaign-stop'],
      description: 'Fixed sealed authenticated HTTP requests through the existing campaign controller.',
      limitation: 'No generic live probing or automatic scope expansion is provided.',
    },
    {
      id: 'semantic-oracle', status: 'UNAVAILABLE', commands: [],
      description: 'Controller-authenticated semantic vulnerability and remediation verdicts.',
      limitation: 'Process exit differences and cleanup receipts alone cannot establish a vulnerability or a verified fix.',
    },
    {
      id: 'browser-execution', status: 'UNAVAILABLE', commands: [],
      description: 'Browser-driven application testing.',
      limitation: 'Browser configuration can be reviewed as source; a public browser execution route is not shipped.',
    },
    {
      id: 'database-stack-execution', status: 'UNAVAILABLE', commands: [],
      description: 'Database-backed and multi-service application execution.',
      limitation: 'Retained conformance kernels are not public target execution capabilities.',
    },
    {
      id: 'multi-runtime-execution', status: 'UNAVAILABLE', commands: [],
      description: 'Python, JVM, .NET, Go, Rust, and native target execution.',
      limitation: 'A language detected in source does not imply a compatible public proof worker.',
    },
    {
      id: 'deployed-evidence-acquisition', status: 'UNAVAILABLE', commands: [],
      description: 'Acquire and trust current deployment or cloud runtime evidence.',
      limitation: 'Repository deployment configuration does not establish what is running. Public evidence-import and acquisition transports remain unavailable.',
    },
    {
      id: 'generic-live', status: 'UNAVAILABLE', commands: [],
      description: 'Generic autonomous live assessment, bounty, and out-of-band workflows.',
      limitation: 'Only the specific implemented public routes listed above are available.',
    },
    {
      id: 'remote-provider-and-publication', status: 'UNAVAILABLE', commands: [],
      description: 'Public provider execution, remote gateways, and transparency publication.',
      limitation: 'Retained command names fail closed pending their required trusted runtime identities.',
    },
  ],
  environment_profiles: [
    { id: 'node-npm', source_review: 'AVAILABLE', execution_support: 'AVAILABLE_NARROW', limitation: 'Compatible sealed Node/npm T1 and single-service loopback T2 only; dependencies and worker image must match.' },
    { id: 'python', source_review: 'AVAILABLE', execution_support: 'UNAVAILABLE', limitation: 'Source review is available; no public Python proof execution profile.' },
    { id: 'dotnet', source_review: 'AVAILABLE', execution_support: 'UNAVAILABLE', limitation: 'Source review is available; no public .NET proof execution profile.' },
    { id: 'jvm', source_review: 'AVAILABLE', execution_support: 'UNAVAILABLE', limitation: 'Source review is available; no public JVM proof execution profile.' },
    { id: 'go', source_review: 'AVAILABLE', execution_support: 'UNAVAILABLE', limitation: 'Source review is available; no public Go proof execution profile.' },
    { id: 'rust-native', source_review: 'AVAILABLE', execution_support: 'UNAVAILABLE', limitation: 'Source review is available; no public Rust or native proof execution profile.' },
    { id: 'browser', source_review: 'AVAILABLE', execution_support: 'UNAVAILABLE', limitation: 'Browser source and test configuration do not establish browser execution coverage.' },
    { id: 'database-stack', source_review: 'AVAILABLE', execution_support: 'UNAVAILABLE', limitation: 'Database or composition indicators require source review; multi-service execution is unavailable.' },
    { id: 'deployment-configuration', source_review: 'AVAILABLE', execution_support: 'UNAVAILABLE', limitation: 'Configuration can be reviewed but does not establish deployed state or active acquisition support.' },
  ],
})

export function capabilityRegistry() {
  return structuredClone(CAPABILITY_REGISTRY)
}

export function renderCapabilities(registry = CAPABILITY_REGISTRY) {
  return [
    'The Last Aperture capabilities',
    '',
    ...registry.capabilities.flatMap((item) => [
      `${item.status} ${item.id}${item.commands.length ? ` (${item.commands.join(', ')})` : ''}`,
      `  ${item.description}`,
      `  Limit: ${item.limitation}`,
    ]),
    '',
    'Support declarations describe shipped behavior, not runtime readiness or evidence of security.',
    '',
  ].join('\n')
}

const PROFILE_DETECTORS = Object.freeze({
  'node-npm': /(?:^|\/)(?:package(?:-lock)?\.json|npm-shrinkwrap\.json)$|\.(?:[cm]?js|jsx|tsx?)$/i,
  python: /(?:^|\/)(?:pyproject\.toml|Pipfile(?:\.lock)?|requirements[^/]*\.txt|setup\.py)$|\.py$/i,
  dotnet: /\.(?:[cfv]sproj|sln|cs|fs|vb)$/i,
  jvm: /(?:^|\/)(?:pom\.xml|build\.gradle(?:\.kts)?|settings\.gradle(?:\.kts)?)$|\.(?:java|kt|scala)$/i,
  go: /(?:^|\/)go\.(?:mod|sum)$|\.go$/i,
  'rust-native': /(?:^|\/)(?:Cargo\.(?:toml|lock)|CMakeLists\.txt|Makefile)$|\.(?:rs|c|cc|cpp|cxx|h|hpp)$/i,
  browser: /(?:^|\/)(?:playwright|cypress|webdriverio|wdio|karma)\.config\.[^/]+$|(?:^|\/)(?:cypress|selenium)\//i,
  'database-stack': /(?:^|\/)(?:(?:docker-)?compose(?:\.[^/]+)?\.ya?ml|schema\.prisma|knexfile\.[^/]+|ormconfig\.[^/]+)$|(?:^|\/)(?:migrations|alembic|prisma)\/|\.sql$/i,
  'deployment-configuration': /(?:^|\/)(?:Dockerfile(?:\.[^/]+)?|(?:docker-)?compose(?:\.[^/]+)?\.ya?ml|Chart\.yaml|serverless\.ya?ml|app\.yaml|vercel\.json|netlify\.toml)$|(?:^|\/)(?:kubernetes|k8s|helm|terraform)\/|\.tf$/i,
})

export const ENVIRONMENT_INVENTORY_LIMITS = Object.freeze({
  max_paths: 100_000, max_path_characters: 4_096, max_total_characters: 16 * 1024 * 1024, max_evidence_paths: 8,
})

export function assessEnvironmentCoverage(inventoryPaths) {
  if (!Array.isArray(inventoryPaths) || inventoryPaths.length > ENVIRONMENT_INVENTORY_LIMITS.max_paths) {
    throw new TypeError('environment inventory must be an array of at most 100000 recorded relative paths')
  }
  let total = 0
  const paths = new Set()
  for (const value of inventoryPaths) {
    if (typeof value !== 'string' || value.length === 0 || value.length > ENVIRONMENT_INVENTORY_LIMITS.max_path_characters || /[\x00-\x1f\x7f]/.test(value)) {
      throw new TypeError('environment inventory contains an invalid recorded relative path')
    }
    const normalized = value.replaceAll('\\', '/')
    if (normalized.startsWith('/') || /^[A-Za-z]:/.test(normalized) || normalized.split('/').some((part) => part === '..' || part === '')) {
      throw new TypeError('environment inventory paths must stay relative to the recorded repository')
    }
    total += value.length
    if (total > ENVIRONMENT_INVENTORY_LIMITS.max_total_characters) throw new RangeError('environment inventory exceeds its total character limit')
    paths.add(normalized)
  }
  const detected = CAPABILITY_REGISTRY.environment_profiles.flatMap((profile) => {
    const matched = [...paths].filter((path) => PROFILE_DETECTORS[profile.id].test(path)).sort()
    return matched.length ? [{
      profile_id: profile.id,
      matching_paths: matched.slice(0, ENVIRONMENT_INVENTORY_LIMITS.max_evidence_paths),
      matching_path_count: matched.length,
      source_review: profile.source_review,
      execution_support: profile.execution_support,
      limitation: profile.limitation,
    }] : []
  })
  return {
    schema_version: '1.0.0',
    basis: 'RECORDED_FILENAMES_ONLY',
    inventory_path_count: paths.size,
    detection_status: detected.length ? 'PROFILE_INDICATORS_FOUND' : 'UNKNOWN',
    detected_profiles: detected,
    deployment_evidence: 'NOT_ASSESSED',
    limitations: [
      'Filename indicators are heuristic, not evidence of runtime compatibility, actual analysis, or dependency availability.',
      'Source configuration does not establish deployed state; no target files, services, or deployment endpoints were read.',
      'Source review availability does not guarantee language-specific completeness. Absent indicators do not establish absence of a technology.',
    ],
  }
}

export function renderCapabilityDocumentation() {
  const lines = [
    '# Public capabilities and environment coverage', '',
    '<!-- GENERATED by scripts/gen-capabilities.mjs from scripts/lib/capabilities.mjs; do not edit by hand. -->', '',
    'This registry describes implemented public workflows. Availability is not runtime readiness or a security verdict. `doctor` performs static installation checks; it does not execute target code, Docker, or network requests.', '',
    '| Capability | Release support | Public commands | Behavior and limits |',
    '|---|---|---|---|',
  ]
  for (const item of CAPABILITY_REGISTRY.capabilities) {
    lines.push(`| ${item.id} | ${item.status} | ${item.commands.map((command) => `\`${command}\``).join(', ') || 'None'} | ${item.description} ${item.limitation} |`)
  }
  lines.push('', '## Environment declarations', '',
    'Recorded filename indicators can identify likely review and execution gaps. They neither open current target files nor establish what is deployed. A source-review profile does not promise language-specific analysis completeness.', '',
    '| Profile | Source review workflow | Public execution | Limit |', '|---|---|---|---|')
  for (const item of CAPABILITY_REGISTRY.environment_profiles) {
    lines.push(`| ${item.id} | ${item.source_review} | ${item.execution_support} | ${item.limitation} |`)
  }
  lines.push('', 'Regenerate with `node scripts/gen-capabilities.mjs`; check for drift with `node scripts/gen-capabilities.mjs --check`.', '')
  return lines.join('\n')
}
