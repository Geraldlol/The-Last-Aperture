// One convention, mechanically enforced: American -ization. The verifier found
// payment-page-script-authorisation three slugs from rag-retrieval-authorization,
// which is a typo hazard no reviewer reliably catches.
const BRITISH = [
  { pattern: /isation\b/, fix: (s) => s.replace(/isation\b/, 'ization') },
  { pattern: /isations\b/, fix: (s) => s.replace(/isations\b/, 'izations') },
  // Only the -ise suffix that pairs with -isation above. A bare /ised\b/ also
  // fires on American spellings (unsupervised, advised, revised, compromised)
  // and would demand "unsupervized", so the stem shape is required and the
  // pr-omised / pr-emised collision is excluded.
  {
    pattern: /(?<!pr)[aeiouy][lmnrt]ised\b/,
    fix: (s) => s.replace(/(?<!pr)([aeiouy][lmnrt])ised\b/, '$1ized'),
  },
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
