import { createHash } from 'node:crypto'

export function artifactToken(value) {
  const input = String(value)
  const slug = input.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 96)
  const digest = createHash('sha256').update(input).digest('hex').slice(0, 16)
  return `${slug}--${digest}`
}

export function artifactKeyToken(value) {
  return artifactToken(value).replaceAll('.', '_')
}
