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
      id: 'engagement-orchestration', status: 'AVAILABLE_NARROW', commands: ['engage unleash', 'engage run', 'engage resume', 'engage status', 'engage confirm', 'engage pause', 'engage rollback', 'engage stop', 'engage work next', 'engage work status', 'engage work submit', 'engage work finalize', 'engage work validate'],
      description: 'Durable target-neutral engagement orchestration across registered routes, including one-target Unleash with a hash-bound BORG proposal swarm, action-risk preflight, confirmation, Pause, Resume, rollback, and Stop controls.',
      limitation: 'Unleash accepts HTTPS targets, performs one bounded credential-free HEAD, and seals at most two reasoning rounds. Action-risk scores are uncalibrated relative-exposure estimates with unknown telemetry coverage. Rollback cancels future local work and inert proposals; it does not reverse target-side effects. Only shipped registered routes can dispatch. No reasoning adapter is enrolled by the packaged CLI; proposed actions stay inert and findings stay empty until typed execution and proof routes exist. Missing routes and adapters remain explicit gaps.',
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
      id: 'https-recon', status: 'AVAILABLE_NARROW', commands: ['last-aperture http-recon go'],
      description: 'One bounded HTTPS reconnaissance action through its existing public controller.',
      limitation: 'A URL entry point is not a comprehensive website assessment.',
    },
    {
      id: 'authenticated-http', status: 'AVAILABLE_NARROW', commands: ['last-aperture http-authed campaign-attested', 'last-aperture http-authed campaign-stop'],
      description: 'Adaptive sealed authenticated HTTP discovery and actions through the durable campaign controller.',
      limitation: 'Every request remains bound to the campaign authority, scope policy, action limits, retained receipt, and stop/cleanup state.',
    },
    {
      id: 'adversarial-validation', status: 'AVAILABLE_NARROW', commands: ['last-aperture adversarial go', 'last-aperture adversarial scope validate', 'last-aperture adversarial plan seal', 'last-aperture adversarial plan validate', 'last-aperture adversarial plan inspect', 'last-aperture adversarial enrollment status', 'last-aperture adversarial execute'],
      description: 'Bounded reconnaissance plus sealed-plan adversarial execution through an explicitly enrolled runtime.',
      limitation: 'The direct controller remains available, but unified engagement dispatch awaits a grant-preserving adapter and therefore records an explicit unavailable route.',
    },
    {
      id: 'bounty-perimeter', status: 'AVAILABLE_NARROW', commands: ['last-aperture bounty plan', 'last-aperture bounty validate', 'last-aperture bounty revalidate', 'last-aperture bounty scope', 'last-aperture bounty authz import', 'last-aperture bounty authz status', 'last-aperture bounty recon status', 'last-aperture bounty scan status', 'last-aperture bounty report draft'],
      description: 'Seal and inspect one program perimeter, import bounded passive authorization evidence, and render status and draft reports.',
      limitation: 'Unified engagement intake does not yet construct the required policy snapshot and program enrollment bundle, so its perimeter route cannot dispatch.',
    },
    {
      id: 'bounty-live-work', status: 'UNAVAILABLE', commands: [],
      description: 'Bounty reconnaissance, authorization replay, crafted scanning, and out-of-band sessions.',
      limitation: 'Their public live commands fail closed pending trusted scope, transport, prepared-request, and session migrations.',
    },
    {
      id: 'bounty-proxy-capture', status: 'UNAVAILABLE', commands: [],
      description: 'Direct bounty proxy capture ingestion and flow projection.',
      limitation: 'Public capture commands fail closed pending bounded no-follow ingestion and trusted capture provenance.',
    },
    {
      id: 'ghidra-static-reverse', status: 'AVAILABLE_NARROW', commands: ['last-aperture-reverse ghidra analyze'],
      description: 'Fixed Ghidra headless static export for one copied native artifact with bounded function, network API/reference/call-site, sanitized static endpoint, and authentication-hint metadata.',
      limitation: 'Native launchers run directly; Windows .bat and .cmd launchers require javac.exe and jar.exe and run through the bundled fixed compatibility agent and Job Object bridge. Static observations do not execute the target or establish program semantics.',
    },
    {
      id: 'frida-local-reverse', status: 'AVAILABLE_NARROW', commands: ['last-aperture-reverse frida trace'],
      description: 'Fixed Frida local spawn and enter/leave trace for one exact module and symbol, with an opaque module-relative symbol offset.',
      limitation: 'This v1 host process route is not a sandbox and records no arguments, return values, memory, or protocol values.',
    },
    {
      id: 'frida-typed-reverse', status: 'AVAILABLE_NARROW', commands: ['last-aperture-reverse frida trace-plan'],
      description: 'Typed multi-hook Frida call tracing for bounded local spawn, local PID/name attach, USB PID/name/application attach, and explicit-device attach plans.',
      limitation: 'Only the bundled typed-capture agent and exact plan selectors are accepted. Declared raw captures can contain sensitive values. Attach evidence remains PARTIAL because a supplied local artifact copy cannot prove the attached runtime loaded identical bytes.',
    },
    {
      id: 'web-protocol-reconstruction', status: 'AVAILABLE_NARROW', commands: ['last-aperture-reverse web import-live-metadata', 'last-aperture-reverse web import-har', 'last-aperture-reverse web import-burp', 'last-aperture-reverse protocol build', 'last-aperture-reverse protocol generate', 'last-aperture-reverse protocol verify'],
      description: 'Import verified Last Aperture recon and settled sealed-plan auth metadata, an authorized HAR, or Burp HTTP-items XML offline; compile bounded observed protocol shapes; and generate a deterministic contract-bound Node connector.',
      limitation: 'Live-metadata projection retains no values and does not claim complete endpoint/auth coverage, response-discovered locators, response shape, redirects, writes, replay, or pagination. Generation and verification perform no network I/O. The generated runtime is labeled GENERATED_REVIEWABLE, remains limited to its validated observed contract, and requires the externally retained manifest digest.',
    },
    {
      id: 'burp-proxy-history-export', status: 'AVAILABLE_NARROW', commands: ['integrations/burp-montoya/build.ps1'],
      description: 'Optional Community-compatible Montoya extension that exports deterministic value-free HAR from existing Burp Proxy history under one exact origin, path prefix, reviewed route-literal set, and item limit.',
      limitation: 'Requires a caller-supplied local Montoya API JAR, JDK 17 through 21, and Burp. It reads existing history only; Scanner, network dispatch, and traffic modification are disabled.',
    },
    {
      id: 'semantic-oracle', status: 'UNAVAILABLE', commands: [],
      description: 'Controller-authenticated semantic vulnerability and remediation verdicts.',
      limitation: 'Process exit differences and cleanup receipts alone cannot establish a vulnerability or a verified fix.',
    },
    {
      id: 'browser-execution', status: 'AVAILABLE_NARROW', commands: ['last-aperture http-authed campaign-attested'],
      description: 'Selected-tab authenticated request execution through the active browser companion bridge, with an optional declarative Web Storage session-to-header adapter.',
      limitation: 'The bridge executes authorized actions in the selected tab and does not automate navigation or login. The optional adapter accepts one exact storage source and request-header carrier; its value stays inside the isolated dispatch.',
    },
    {
      id: 'database-stack-execution', status: 'UNAVAILABLE', commands: [],
      description: 'Database-backed and multi-service application execution.',
      limitation: 'Retained conformance kernels are not public target execution capabilities.',
    },
  {
    id: 'multi-runtime-execution', status: 'UNAVAILABLE', commands: [],
    description: 'Generic proof-worker execution for Python, JVM, .NET, Go, Rust, and native targets beyond the fixed Frida routes.',
    limitation: 'A language detected in source does not imply a compatible public proof worker.',
  },
    {
      id: 'deployed-evidence-acquisition', status: 'UNAVAILABLE', commands: [],
      description: 'Acquire artifact, registry, deployed, and runtime evidence through content-bound adapter plans.',
      limitation: 'Public acquisition commands fail closed pending detached signed-plan migration through the trusted controller.',
    },
    {
      id: 'evidence-bundle-import', status: 'UNAVAILABLE', commands: [],
      description: 'Import a verified evidence bundle into repository audit planning.',
      limitation: 'Public import fails closed pending controller-authenticated manifest semantics and atomic verification.',
    },
    {
      id: 'generic-live', status: 'UNAVAILABLE', commands: [],
      description: 'Unbounded or arbitrary autonomous live assessment, bounty, and out-of-band execution.',
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
    { id: 'browser', source_review: 'AVAILABLE', execution_support: 'AVAILABLE_NARROW', limitation: 'Execution is limited to authorized selected-tab actions through the authenticated browser bridge and its optional declarative Web Storage adapter; navigation, login automation, and general browser capture are not provided.' },
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
