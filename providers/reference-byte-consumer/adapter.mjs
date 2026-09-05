#!/usr/bin/env node

import { createHash, createHmac } from 'node:crypto'
import { createInterface } from 'node:readline'
import { runReferenceIsolationProbes } from './isolation-probes.mjs'

const DOMAIN = 'red-team-audit/provider-delivery/v1'
const MAX_INPUT_LINE_BYTES = 100 * 1024 * 1024
const ISOLATION_PROBES_ENABLED = (
  process.env.RTA_REFERENCE_ISOLATION_PROBES === '1'
)
const TIMEOUT_CONFORMANCE_JOB = 'lens:docker-timeout-conformance'

if (ISOLATION_PROBES_ENABLED) {
  try {
    await runReferenceIsolationProbes()
  } catch (error) {
    process.stderr.write(
      `reference isolation conformance failed: ${String(error?.code ?? 'UNKNOWN')}\n`,
    )
    process.exit(78)
  }
}

function send(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`)
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function consumptionHmac(challenge, jobId, artifactId, size, bytes) {
  return createHmac('sha256', challenge)
    .update(DOMAIN, 'utf8')
    .update('\0', 'utf8')
    .update(jobId, 'utf8')
    .update('\0', 'utf8')
    .update(artifactId, 'utf8')
    .update('\0', 'utf8')
    .update(String(size), 'utf8')
    .update('\0', 'utf8')
    .update(bytes)
    .digest('hex')
}

function terminalResult(packet, examinedFiles) {
  const unsupported = (
    (
      packet.kind === 'TRIAGE'
      && (packet.findings?.length ?? 0) > 0
    )
    || packet.kind === 'PROOF'
    || (
      packet.kind === 'LENS'
      && packet.lens === 'database-and-data-stores'
    )
  )
  const semanticGapReason =
    'reference-byte-consumer verifies broker conformance only and performs no semantic vulnerability analysis'
  return {
    schema_version: '1.0.0',
    run_id: packet.run_id,
    job_id: packet.job_id,
    input_sha256: packet.packet_sha256,
    producer: {
      name: 'reference-byte-consumer',
      version: '1.0.0',
      instance_id: ISOLATION_PROBES_ENABLED
        ? 'reference-byte-consumer:docker-isolation-probes-v1'
        : 'reference-byte-consumer:local',
    },
    state: unsupported ? 'FAILED' : 'SUCCEEDED',
    examined_files: examinedFiles,
    findings: [],
    coverage_gaps: [{
      area: packet.job_id,
      reason: semanticGapReason,
    }],
    topic_assessments: unsupported
      ? []
      : (packet.topic_obligations ?? []).map((topic) => ({
          topic,
          disposition: 'not-assessed',
          reason: semanticGapReason,
          coverage_gap_areas: [packet.job_id],
        })),
    ...(unsupported ? {
      error: {
        code: 'REFERENCE_ADAPTER_NO_SEMANTIC_ANALYZER',
        message:
          'this reference adapter cannot triage findings, prove findings, or inventory database semantics',
        recoverable: false,
      },
    } : {}),
  }
}

const lines = createInterface({
  input: process.stdin,
  crlfDelay: Number.POSITIVE_INFINITY,
  terminal: false,
})

let session
let packet
let artifacts = []
let nextArtifact = 0
const examinedFiles = []

function requestNext() {
  if (nextArtifact < artifacts.length) {
    send({
      type: 'artifact_request',
      schema_version: '1.0.0',
      session_id: session,
      artifact_id: artifacts[nextArtifact].artifact_id,
    })
    return
  }
  send({
    type: 'job_result',
    schema_version: '1.0.0',
    session_id: session,
    result: terminalResult(packet, examinedFiles),
  })
}

for await (const line of lines) {
  if (Buffer.byteLength(line, 'utf8') > MAX_INPUT_LINE_BYTES) {
    process.stderr.write('controller frame exceeded reference adapter limit\n')
    process.exitCode = 1
    break
  }
  let frame
  try {
    frame = JSON.parse(line)
  } catch {
    process.stderr.write('controller emitted invalid JSONL\n')
    process.exitCode = 1
    break
  }
  if (frame.type === 'provider_start') {
    if (session !== undefined) {
      process.stderr.write('duplicate provider_start\n')
      process.exitCode = 1
      break
    }
    session = frame.session_id
    packet = frame.packet
    artifacts = frame.allowed_artifacts
    if (
      ISOLATION_PROBES_ENABLED
      && packet.job_id === TIMEOUT_CONFORMANCE_JOB
    ) {
      continue
    }
    requestNext()
    continue
  }
  if (frame.type !== 'artifact_delivery' || session === undefined) {
    process.stderr.write('unexpected controller frame\n')
    process.exitCode = 1
    break
  }
  const expected = artifacts[nextArtifact]
  const bytes = Buffer.from(frame.content_base64, 'base64')
  const challenge = Buffer.from(frame.challenge_base64, 'base64')
  if (
    frame.session_id !== session
    || frame.artifact_id !== expected?.artifact_id
    || frame.delivery_id === undefined
    || frame.size !== bytes.length
    || frame.sha256 !== sha256(bytes)
    || frame.sha256 !== expected.sha256
    || challenge.length !== 32
  ) {
    process.stderr.write('artifact delivery failed integrity checks\n')
    process.exitCode = 1
    break
  }
  send({
    type: 'artifact_consumed',
    schema_version: '1.0.0',
    session_id: session,
    delivery_id: frame.delivery_id,
    artifact_id: frame.artifact_id,
    challenge_hmac_sha256: consumptionHmac(
      challenge,
      packet.job_id,
      frame.artifact_id,
      bytes.length,
      bytes,
    ),
  })
  if (expected.kind === 'FILE') examinedFiles.push(expected.logical_name)
  nextArtifact += 1
  requestNext()
}
