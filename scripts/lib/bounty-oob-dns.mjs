import { createSocket } from 'node:dgram'

export const DNS_TYPE = { A: 1, NS: 2, CNAME: 5, TXT: 16, AAAA: 28 }

const TYPE_NAME = new Map(Object.entries(DNS_TYPE).map(([name, value]) => [value, name]))

const HEADER_LENGTH = 12
const CLASS_IN = 1

export function parseDnsQuery(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < HEADER_LENGTH) {
    throw new Error('dns packet too short')
  }
  const id = buffer.readUInt16BE(0)
  const qdcount = buffer.readUInt16BE(4)
  if (qdcount < 1) {
    throw new Error('dns packet carries no question')
  }
  const labels = []
  let offset = HEADER_LENGTH
  for (;;) {
    if (offset >= buffer.length) throw new Error('malformed dns name: ran past packet')
    const length = buffer.readUInt8(offset)
    if (length === 0) {
      offset += 1
      break
    }
    // A question section never uses compression, so a pointer here is malformed
    // input rather than something to follow.
    if ((length & 0xc0) !== 0) throw new Error('malformed dns name: compression pointer in question')
    if (offset + 1 + length > buffer.length) throw new Error('malformed dns name: label overruns packet')
    labels.push(buffer.toString('ascii', offset + 1, offset + 1 + length))
    offset += 1 + length
  }
  if (offset + 4 > buffer.length) throw new Error('malformed dns question: missing type or class')
  return {
    id,
    name: labels.join('.'),
    qtype: buffer.readUInt16BE(offset),
    qclass: buffer.readUInt16BE(offset + 2),
    questionEnd: offset + 4,
  }
}

function ipv4Bytes(address) {
  if (typeof address !== 'string') throw new Error(`not an ipv4 address: ${address}`)
  const octets = address.split('.').map((part) => Number.parseInt(part, 10))
  const valid = octets.length === 4
    && octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255)
  if (!valid) throw new Error(`not an ipv4 address: ${address}`)
  return Buffer.from(octets)
}

export function buildDnsResponse({ query, buffer, address, ttl = 60 }) {
  const question = buffer.subarray(HEADER_LENGTH, query.questionEnd)
  const answerable = query.qtype === DNS_TYPE.A
  const header = Buffer.alloc(HEADER_LENGTH)
  header.writeUInt16BE(query.id, 0)
  // QR=1 AA=1 RD=1, RCODE=0
  header.writeUInt16BE(0x8580, 2)
  header.writeUInt16BE(1, 4)
  header.writeUInt16BE(answerable ? 1 : 0, 6)
  if (!answerable) return Buffer.concat([header, question])

  const rdata = ipv4Bytes(address)
  // The question is NAME + QTYPE(2) + QCLASS(2); the answer reuses that NAME
  // verbatim rather than a compression pointer, which every resolver accepts.
  const name = question.subarray(0, question.length - 4)
  const record = Buffer.alloc(name.length + 10 + rdata.length)
  name.copy(record, 0)
  let cursor = name.length
  record.writeUInt16BE(DNS_TYPE.A, cursor)
  record.writeUInt16BE(CLASS_IN, cursor + 2)
  record.writeUInt32BE(ttl, cursor + 4)
  record.writeUInt16BE(rdata.length, cursor + 8)
  rdata.copy(record, cursor + 10)
  return Buffer.concat([header, question, record])
}

export function startDnsListener({
  port = 53,
  address = '0.0.0.0',
  answerAddress = '127.0.0.1',
  onQuery,
}) {
  const socket = createSocket('udp4')
  socket.on('message', (message, remote) => {
    let query
    try {
      query = parseDnsQuery(message)
    } catch {
      // Scanners and stray traffic hit any open resolver. Malformed input is
      // dropped rather than allowed to take the listener down.
      return
    }
    try {
      socket.send(buildDnsResponse({ query, buffer: message, address: answerAddress }), remote.port, remote.address)
    } catch {
      // Failing to answer must not lose the observation below.
    }
    onQuery?.({
      protocol: 'dns',
      name: query.name,
      qType: TYPE_NAME.get(query.qtype) ?? String(query.qtype),
      remoteAddress: remote.address,
      rawRequest: message.toString('base64'),
    })
  })
  return new Promise((resolve, reject) => {
    socket.once('error', reject)
    socket.bind(port, address, () => {
      resolve({
        port: socket.address().port,
        close: () => new Promise((done) => socket.close(done)),
      })
    })
  })
}
