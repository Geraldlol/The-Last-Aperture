import { createHash } from 'node:crypto'
import fc, { __version as fastCheckVersion } from 'fast-check'
import { stableJson } from './run-engine.mjs'

const MAX_RUNS = 1_000_000
const MAX_TIMEOUT_MS = 900_000
const MIN_COUNTEREXAMPLE_BYTES = 64
const MAX_COUNTEREXAMPLE_BYTES = 16 * 1024 * 1024
const MAX_CASES = 1_000_000
const MAX_CASE_BYTES = 16 * 1024 * 1024
const MAX_JSON_NODES = 20_000
const MAX_JSON_DEPTH = 32
const LOCAL_EXECUTION_DOMAINS = new Set(['repository', 'local_service'])

export class FuzzStrategyError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'FuzzStrategyError'
    this.code = code
  }
}

function fail(code, message, options = {}) {
  throw new FuzzStrategyError(code, message, options)
}

function canonicalJson(value) {
  const rendered = stableJson(value, 0)
  return rendered.endsWith('\n') ? rendered.slice(0, -1) : rendered
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value
  seen.add(value)
  for (const child of Object.values(value)) deepFreeze(child, seen)
  return Object.freeze(value)
}

function inspectJsonValue(root, label) {
  const active = new WeakSet()
  const stack = [{ value: root, depth: 0, exit: false }]
  let nodes = 0
  while (stack.length > 0) {
    const item = stack.pop()
    if (item.exit) {
      active.delete(item.value)
      continue
    }
    const { value, depth } = item
    nodes += 1
    if (nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH) {
      fail('FUZZ_JSON_LIMIT', `${label} exceeds the structured JSON depth or node limit`)
    }
    if (value === null || typeof value === 'string' || typeof value === 'boolean') continue
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) fail('FUZZ_JSON_INVALID', `${label} contains a non-finite number`)
      continue
    }
    if (typeof value !== 'object') fail('FUZZ_JSON_INVALID', `${label} contains non-JSON data`)
    if (active.has(value)) fail('FUZZ_JSON_INVALID', `${label} contains a cycle`)
    active.add(value)
    stack.push({ value, depth, exit: true })
    const isArray = Array.isArray(value)
    const prototype = Object.getPrototypeOf(value)
    if ((isArray && prototype !== Array.prototype)
      || (!isArray && prototype !== Object.prototype && prototype !== null)) {
      fail('FUZZ_JSON_INVALID', `${label} must contain only plain JSON objects and arrays`)
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      fail('FUZZ_JSON_INVALID', `${label} contains symbol-keyed data`)
    }
    const keys = Object.keys(value)
    if (isArray && (
      keys.length !== value.length
      || keys.some((key) => !/^(?:0|[1-9]\d*)$/.test(key) || Number(key) >= value.length)
    )) {
      fail('FUZZ_JSON_INVALID', `${label} contains a sparse or named-property array`)
    }
    const descriptors = Object.getOwnPropertyDescriptors(value)
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (isArray && key === 'length') continue
      if (!descriptor.enumerable || 'get' in descriptor || 'set' in descriptor) {
        fail('FUZZ_JSON_INVALID', `${label} contains hidden or accessor data`)
      }
      stack.push({ value: descriptor.value, depth: depth + 1, exit: false })
    }
  }
}

function snapshotJson(value, label) {
  inspectJsonValue(value, label)
  let rendered
  let snapshot
  try {
    rendered = canonicalJson(value)
    snapshot = JSON.parse(rendered)
  } catch (cause) {
    fail('FUZZ_JSON_INVALID', `${label} cannot be encoded as canonical JSON`, { cause })
  }
  inspectJsonValue(snapshot, `${label} snapshot`)
  if (canonicalJson(snapshot) !== rendered) {
    fail('FUZZ_JSON_UNSTABLE', `${label} changed while being snapshotted`)
  }
  return { snapshot: deepFreeze(snapshot), rendered }
}

function boundedInteger(value, label, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    fail('FUZZ_LIMIT_INVALID', `${label} must be a safe integer between ${min} and ${max}`)
  }
  return value
}

function assertSeed(seed) {
  return boundedInteger(seed, 'seed', -0x80000000, 0x7fffffff)
}

function assertArbitrary(arbitrary) {
  if (!arbitrary || typeof arbitrary.generate !== 'function' || typeof arbitrary.shrink !== 'function') {
    fail('FUZZ_ARBITRARY_INVALID', 'arbitrary must be a fast-check Arbitrary')
  }
}

function sanitizedError(error) {
  const clean = (value) => String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .slice(0, 512)
  return deepFreeze({
    name: clean(error?.name || 'Error'),
    message: clean(error?.message || 'fuzz harness failed'),
  })
}

function baseResult(details) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/structured-fuzz-result',
    provider: { name: 'fast-check', version: fastCheckVersion },
    seed: details.seed,
    requested_runs: details.requestedRuns,
    executed_runs: details.numRuns,
    skipped_runs: details.numSkips,
    shrink_count: details.numShrinks,
    interrupted: details.interrupted,
    non_clearance: true,
  }
}

function validateOptions(options) {
  const {
    executionDomain,
    arbitrary,
    property,
    seed,
    numRuns,
    timeoutMs,
    maxCounterexampleBytes,
    asyncProperty = false,
    path,
  } = options ?? {}
  if (!LOCAL_EXECUTION_DOMAINS.has(executionDomain)) {
    fail(
      'FUZZ_LIVE_RUNTIME_REQUIRED',
      'property execution is limited to repository or disposable local-service targets; live cases must route through the adversarial runtime',
    )
  }
  assertArbitrary(arbitrary)
  if (typeof property !== 'function') fail('FUZZ_PROPERTY_INVALID', 'property must be a function')
  if (typeof asyncProperty !== 'boolean') fail('FUZZ_PROPERTY_INVALID', 'asyncProperty must be boolean')
  if (path !== undefined && (
    typeof path !== 'string'
    || path.length > 4_096
    || !/^(?:\d+)(?::\d+)*$/.test(path)
  )) {
    fail('FUZZ_REPLAY_PATH_INVALID', 'counterexample replay path is invalid')
  }
  return {
    executionDomain,
    arbitrary,
    property,
    seed: assertSeed(seed),
    numRuns: boundedInteger(numRuns, 'numRuns', 1, MAX_RUNS),
    timeoutMs: boundedInteger(timeoutMs, 'timeoutMs', 1, MAX_TIMEOUT_MS),
    maxCounterexampleBytes: boundedInteger(
      maxCounterexampleBytes,
      'maxCounterexampleBytes',
      MIN_COUNTEREXAMPLE_BYTES,
      MAX_COUNTEREXAMPLE_BYTES,
    ),
    asyncProperty,
    path,
  }
}

/**
 * Run structured property fuzzing only against code or a disposable local
 * harness. This adapter has no network or process I/O seam. Live generated
 * values must be converted into governed actions and sent through
 * executeAdversarialCampaign.
 */
export async function runStructuredFuzz(options) {
  const config = validateOptions(options)
  let harnessError = null
  let harnessTimedOut = false
  const deadline = Date.now() + config.timeoutMs
  const invoke = async (...rawArguments) => {
    let argumentsSnapshot
    try {
      argumentsSnapshot = snapshotJson(rawArguments, 'generated fuzz arguments').snapshot
    } catch (error) {
      harnessError = sanitizedError(error)
      throw error
    }
    try {
      const remainingMs = deadline - Date.now()
      if (remainingMs <= 0) {
        fail('FUZZ_PROPERTY_TIMEOUT', 'fuzz property exceeded the campaign deadline')
      }
      let timer
      const verdict = await Promise.race([
        Promise.resolve(config.property(...structuredClone(argumentsSnapshot))),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new FuzzStrategyError(
            'FUZZ_PROPERTY_TIMEOUT',
            'fuzz property exceeded the campaign deadline',
          )), remainingMs)
        }),
      ]).finally(() => clearTimeout(timer))
      if (typeof verdict !== 'boolean') {
        fail('FUZZ_PROPERTY_VERDICT_INVALID', 'fuzz property must return a boolean verdict')
      }
      return verdict
    } catch (error) {
      if (error?.code === 'FUZZ_PROPERTY_TIMEOUT') harnessTimedOut = true
      harnessError = sanitizedError(error)
      throw error
    }
  }
  const syncInvoke = (...rawArguments) => {
    let argumentsSnapshot
    try {
      argumentsSnapshot = snapshotJson(rawArguments, 'generated fuzz arguments').snapshot
      const verdict = config.property(...structuredClone(argumentsSnapshot))
      if (verdict && typeof verdict.then === 'function') {
        fail('FUZZ_PROPERTY_PROMISE_UNDECLARED', 'set asyncProperty for a property returning a Promise')
      }
      if (typeof verdict !== 'boolean') {
        fail('FUZZ_PROPERTY_VERDICT_INVALID', 'fuzz property must return a boolean verdict')
      }
      return verdict
    } catch (error) {
      harnessError = sanitizedError(error)
      throw error
    }
  }
  const property = config.asyncProperty
    ? fc.asyncProperty(config.arbitrary, invoke)
    : fc.property(config.arbitrary, syncInvoke)
  let details
  try {
    details = await fc.check(property, {
      seed: config.seed,
      numRuns: config.numRuns,
      path: config.path,
      interruptAfterTimeLimit: config.timeoutMs,
      markInterruptAsFailure: false,
    })
  } catch (error) {
    return deepFreeze({
      schema_version: '1.0.0',
      kind: 'red-team-audit/structured-fuzz-result',
      provider: { name: 'fast-check', version: fastCheckVersion },
      status: 'INCONCLUSIVE',
      seed: config.seed,
      requested_runs: config.numRuns,
      executed_runs: 0,
      skipped_runs: 0,
      shrink_count: 0,
      interrupted: false,
      non_clearance: true,
      statement: 'The fuzz harness failed before a reliable result was produced.',
      harness_error: sanitizedError(error),
    })
  }
  const common = baseResult({ ...details, requestedRuns: config.numRuns })
  if (harnessError) {
    return deepFreeze({
      ...common,
      status: 'INCONCLUSIVE',
      interrupted: common.interrupted || harnessTimedOut,
      statement: 'The fuzz harness failed; no vulnerability conclusion is valid.',
      harness_error: harnessError,
    })
  }
  if (details.interrupted || (details.failed && details.counterexample === null)) {
    return deepFreeze({
      ...common,
      status: 'INCONCLUSIVE',
      statement: details.interrupted
        ? 'The bounded fuzz campaign was interrupted before completing its sample.'
        : 'The fuzz campaign exhausted its skip budget; the sample is inconclusive.',
    })
  }
  if (!details.failed) {
    return deepFreeze({
      ...common,
      status: 'NO_COUNTEREXAMPLE_OBSERVED',
      statement: 'No counterexample was observed in this finite sample; this does not establish absence of a vulnerability.',
    })
  }

  let encoded
  try {
    encoded = snapshotJson(details.counterexample, 'minimized counterexample')
  } catch (error) {
    return deepFreeze({
      ...common,
      status: 'INCONCLUSIVE',
      statement: 'A failure occurred, but the minimized value was not safe canonical JSON and cannot be promoted as evidence.',
      harness_error: sanitizedError(error),
      reproducer: {
        seed: details.seed,
        counterexample_path: details.counterexamplePath,
        counterexample_omitted: true,
      },
    })
  }
  const bytes = Buffer.from(encoded.rendered, 'utf8')
  const reproducer = {
    seed: details.seed,
    counterexample_path: details.counterexamplePath,
    counterexample_sha256: sha256(bytes),
    counterexample_bytes: bytes.byteLength,
  }
  if (bytes.byteLength > config.maxCounterexampleBytes) {
    return deepFreeze({
      ...common,
      status: 'INCONCLUSIVE',
      statement: 'A failure occurred, but its minimized input exceeded the evidence byte cap and was omitted.',
      reproducer: {
        ...reproducer,
        counterexample_omitted: true,
      },
    })
  }
  return deepFreeze({
    ...common,
    status: 'COUNTEREXAMPLE_OBSERVED',
    statement: 'A minimized counterexample was observed; it still requires the strategy oracle and matched control before confirming a finding.',
    reproducer: {
      ...reproducer,
      concrete_arguments: encoded.snapshot,
    },
  })
}

export async function replayStructuredFuzz(options) {
  const { priorResult, ...rest } = options ?? {}
  if (
    priorResult?.status !== 'COUNTEREXAMPLE_OBSERVED'
    || !Number.isSafeInteger(priorResult.reproducer?.seed)
    || typeof priorResult.reproducer?.counterexample_path !== 'string'
  ) {
    fail('FUZZ_REPLAY_RECEIPT_INVALID', 'replay requires a counterexample result with a seed and path')
  }
  return runStructuredFuzz({
    ...rest,
    seed: priorResult.reproducer.seed,
    path: priorResult.reproducer.counterexample_path,
    numRuns: priorResult.requested_runs,
  })
}

/** Generate inert, deterministic JSON cases. Callers targeting live systems
 * must map these values into plans and submit them to the governed runtime. */
export function generateStructuredFuzzCases({
  arbitrary,
  seed,
  numCases,
  maxCaseBytes,
} = {}) {
  assertArbitrary(arbitrary)
  const checkedSeed = assertSeed(seed)
  const checkedCases = boundedInteger(numCases, 'numCases', 1, MAX_CASES)
  const checkedBytes = boundedInteger(maxCaseBytes, 'maxCaseBytes', 1, MAX_CASE_BYTES)
  const values = fc.sample(arbitrary, { seed: checkedSeed, numRuns: checkedCases })
  return deepFreeze(values.map((value, index) => {
    const encoded = snapshotJson(value, `generated fuzz case ${index}`)
    const bytes = Buffer.from(encoded.rendered, 'utf8')
    if (bytes.byteLength > checkedBytes) {
      fail('FUZZ_CASE_SIZE_EXCEEDED', `generated fuzz case ${index} exceeds maxCaseBytes`)
    }
    return {
      case_id: `fast-check:${checkedSeed}:${index}`,
      seed: checkedSeed,
      index,
      value: encoded.snapshot,
      value_sha256: sha256(bytes),
      value_bytes: bytes.byteLength,
      route: 'ADVERSARIAL_RUNTIME_REQUIRED',
    }
  }))
}
