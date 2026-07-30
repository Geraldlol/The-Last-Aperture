// One convention, mechanically enforced: American -ization. The verifier found
// payment-page-script-authorisation three slugs from rag-retrieval-authorization,
// which is a typo hazard no reviewer reliably catches.
const BRITISH = [
  { pattern: /isation\b/, fix: (s) => s.replace(/isation\b/, 'ization') },
  { pattern: /isations\b/, fix: (s) => s.replace(/isations\b/, 'izations') },
  { pattern: /ised\b/, fix: (s) => s.replace(/ised\b/, 'ized') },
  { pattern: /yse\b/, fix: (s) => s.replace(/yse\b/, 'yze') },
  { pattern: /ysed\b/, fix: (s) => s.replace(/ysed\b/, 'yzed') },
]

export function checkOrthography(slugs) {
  const violations = []
  for (const slug of slugs) {
    for (const { pattern, fix } of BRITISH) {
      if (pattern.test(slug)) {
        violations.push({ rule: 'R5', slug, lenses: [], message: `slug "${slug}" uses British spelling; use "${fix(slug)}"` })
        break
      }
    }
  }
  return violations
}
