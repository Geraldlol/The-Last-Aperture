const ALL_CAPABILITIES = Object.freeze([
  'repository-audit',
  'repository-agent-work',
  'https-recon',
  'authenticated-http-browser',
  'web-live-metadata-import',
  'web-capture-har-import',
  'web-capture-burp-import',
  'ghidra-analysis',
  'frida-trace',
  'protocol-build',
  'connector-generate',
  'connector-verify',
])

const ALL_EFFECTS = Object.freeze([
  'ANALYZE_LOCAL_ARTIFACT',
  'ATTACH_AUTHORIZED_RUNTIME',
  'GENERATE_LOCAL_CONNECTOR',
  'INGEST_BOUND_AGENT_RESULT',
  'INSPECT_AUTHORIZED_REPOSITORY',
  'RUN_TARGET_BOUND_PROBES',
  'SEND_AUTHENTICATED_TARGET_REQUESTS',
  'SEND_BOUNDED_TARGET_REQUESTS',
])

function profile(capabilities, effects, {
  scopeMode = 'DECLARED_CAPABILITY_AUTHORITY',
  autonomyProfile = 'L3_MAXIMUM_AUTHORIZED',
} = {}) {
  return Object.freeze({
    capabilities: Object.freeze([...capabilities]),
    effects: Object.freeze([...effects]),
    scope_mode: scopeMode,
    autonomy_profile: autonomyProfile,
  })
}

export const ENGAGEMENT_AUTHORIZATION_PROFILES = Object.freeze({
  full: profile(ALL_CAPABILITIES, ALL_EFFECTS, { scopeMode: 'FULL_TARGET_AUTHORITY' }),
  'repository-read': profile(
    ['repository-audit', 'repository-agent-work'],
    ['INGEST_BOUND_AGENT_RESULT', 'INSPECT_AUTHORIZED_REPOSITORY'],
  ),
  web: profile(
    [
      'https-recon',
      'authenticated-http-browser',
      'web-live-metadata-import',
      'web-capture-har-import',
      'web-capture-burp-import',
      'protocol-build',
      'connector-generate',
      'connector-verify',
    ],
    [
      'GENERATE_LOCAL_CONNECTOR',
      'RUN_TARGET_BOUND_PROBES',
      'SEND_AUTHENTICATED_TARGET_REQUESTS',
      'SEND_BOUNDED_TARGET_REQUESTS',
    ],
  ),
  reverse: profile(
    ['ghidra-analysis', 'frida-trace', 'protocol-build', 'connector-generate', 'connector-verify'],
    [
      'ANALYZE_LOCAL_ARTIFACT',
      'ATTACH_AUTHORIZED_RUNTIME',
      'GENERATE_LOCAL_CONNECTOR',
      'RUN_TARGET_BOUND_PROBES',
    ],
  ),
  offline: profile(
    [
      'repository-audit',
      'repository-agent-work',
      'web-capture-har-import',
      'web-capture-burp-import',
      'ghidra-analysis',
      'protocol-build',
      'connector-generate',
      'connector-verify',
    ],
    [
      'ANALYZE_LOCAL_ARTIFACT',
      'GENERATE_LOCAL_CONNECTOR',
      'INGEST_BOUND_AGENT_RESULT',
      'INSPECT_AUTHORIZED_REPOSITORY',
    ],
  ),
})

export const ENGAGEMENT_AUTHORIZATION_PROFILE_NAMES = Object.freeze(
  Object.keys(ENGAGEMENT_AUTHORIZATION_PROFILES),
)
export const ENGAGEMENT_AUTHORIZED_CAPABILITIES = ALL_CAPABILITIES
export const ENGAGEMENT_AUTHORIZED_EFFECTS = ALL_EFFECTS

export function engagementAuthorizationProfile(name) {
  return typeof name === 'string' ? ENGAGEMENT_AUTHORIZATION_PROFILES[name] : undefined
}
