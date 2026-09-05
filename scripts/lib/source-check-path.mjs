// Shared lexical policy only. No filesystem access or host-specific resolution.
export const SOURCE_CHECK_PATH_MAX_CHARACTERS = 4096

const UNSAFE_TEXT = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u
const RESERVED_DEVICE = /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\.|$)/iu

export function isSourceCheckPathText(value) {
  return typeof value === 'string' && value.length > 0
    && value.length <= SOURCE_CHECK_PATH_MAX_CHARACTERS && !UNSAFE_TEXT.test(value)
}

export function isSourceCheckRelativePath(value) {
  return isSourceCheckPathText(value) && value.split('/').every((segment) =>
    segment !== '' && segment !== '.' && segment !== '..'
    && !/[<>:"|?*\\]/u.test(segment) && !/[. ]$/u.test(segment)
    && !RESERVED_DEVICE.test(segment))
}
