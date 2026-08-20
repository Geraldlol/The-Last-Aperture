import { connect } from 'node:tls'
import { assertApproved } from './bounty-recon-gate.mjs'

const DEFAULT_TIMEOUT_MS = 15000

// SAN strings arrive as "DNS:a.example, DNS:*.b.example, IP Address:203.0.113.7".
export function parseSubjectAltName(subjectaltname) {
  const dns = []
  const ip = []
  if (typeof subjectaltname !== 'string' || subjectaltname.length === 0) return { dns, ip }
  for (const part of subjectaltname.split(',')) {
    const entry = part.trim()
    if (entry.toLowerCase().startsWith('dns:')) {
      dns.push(entry.slice(4).trim())
    } else if (entry.toLowerCase().startsWith('ip address:')) {
      ip.push(entry.slice(11).trim())
    }
  }
  return { dns, ip }
}

export function certificateFacts(cert) {
  if (cert === null || typeof cert !== 'object') return null
  return {
    commonName: cert.subject?.CN ?? null,
    issuer: cert.issuer?.O ?? cert.issuer?.CN ?? null,
    validFrom: cert.valid_from ?? null,
    validTo: cert.valid_to ?? null,
    fingerprint256: cert.fingerprint256 ?? null,
  }
}

function defaultConnect({ host, port, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const socket = connect({ host, port, servername: host, timeout: timeoutMs }, () => {
      const cert = socket.getPeerCertificate(false)
      socket.end()
      resolve(cert)
    })
    socket.on('error', reject)
    socket.on('timeout', () => {
      socket.destroy()
      reject(new Error('tls handshake timed out'))
    })
  })
}

export async function harvestTlsSans({
  approval,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  connectImpl = defaultConnect,
}) {
  // Takes an approval, never a hostname: there is no parameter here that lets a
  // caller reach a host the gate has not cleared.
  assertApproved(approval)
  try {
    const cert = await connectImpl({ host: approval.host, port: approval.port, timeoutMs })
    const { dns, ip } = parseSubjectAltName(cert?.subjectaltname)
    const names = [...dns]
    const commonName = cert?.subject?.CN
    if (typeof commonName === 'string' && commonName.length > 0 && !names.includes(commonName)) {
      names.push(commonName)
    }
    return { names, ipSans: ip, certificate: certificateFacts(cert), gap: null }
  } catch (error) {
    // A handshake failure is a gap in coverage, not a pipeline error. Throwing
    // here would abort a sweep because one host was down.
    return {
      names: [],
      ipSans: [],
      certificate: null,
      gap: { source: 'tls', reason: 'tls-handshake-failed', detail: `${approval.host}: ${error.message}` },
    }
  }
}
