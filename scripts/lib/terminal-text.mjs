const TERMINAL_CONTROL_PATTERN =
  /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu
const JSON_TERMINAL_STATE_PATTERN =
  /[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu
const DOCUMENT_TERMINAL_CONTROL_PATTERN =
  /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu

function visibleCodePoint(character) {
  const code = character.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')
  return `\\u${code}`
}

/** Render untrusted text without terminal control or bidi state changes. */
export function terminalSafeText(value, maxLength = 8192) {
  const boundedLength = Number.isInteger(maxLength) && maxLength > 0 ? maxLength : 8192
  const rendered = String(value ?? '').replace(TERMINAL_CONTROL_PATTERN, visibleCodePoint)
  if (rendered.length <= boundedLength) return rendered
  return `${rendered.slice(0, boundedLength)}...[truncated]`
}

/** Serialize JSON while making non-JSON terminal/bidi state characters visible. */
export function terminalSafeJson(value, space = 2) {
  return JSON.stringify(value, null, space).replace(JSON_TERMINAL_STATE_PATTERN, visibleCodePoint)
}

/** Neutralize terminal/bidi state in already serialized valid JSON. */
export function terminalSafeSerializedJson(value) {
  return String(value).replace(JSON_TERMINAL_STATE_PATTERN, visibleCodePoint)
}

/** Join trusted line structure while neutralizing every untrusted line value. */
export function terminalSafeLines(lines) {
  return lines.map((line) => terminalSafeText(line)).join('\n')
}

/** Preserve deliberate LF/CRLF/tab document layout while neutralizing terminal state. */
export function terminalSafeDocumentText(value, maxLength = 16 * 1024 * 1024) {
  const boundedLength = Number.isInteger(maxLength) && maxLength > 0
    ? maxLength
    : 16 * 1024 * 1024
  const rendered = String(value ?? '').replace(DOCUMENT_TERMINAL_CONTROL_PATTERN, visibleCodePoint)
  if (rendered.length <= boundedLength) return rendered
  return `${rendered.slice(0, boundedLength)}...[truncated]`
}
