// Pure detection: no `$`, no I/O. The built-in patterns, the user's patterns
// file, the allow-list, and findSecrets, which answers non-overlapping spans.

/** One way to recognise a secret. `group` masks only that capture group. */
export type Rule = { kind: string; re: RegExp; group?: number }

export type Rules = {
  patterns: readonly Rule[]
  /** Exact values never masked. */
  allow: ReadonlySet<string>
  /** Values matching any of these are never masked. */
  allowPatterns: readonly RegExp[]
}

/** A secret found in a text: `[start, end)` in UTF-16 code units. */
export type Span = { start: number; end: number; value: string; kind: string }

export type ParsedPatterns = { patterns: Rule[]; allow: string[]; allowPatterns: RegExp[]; errors: string[] }

/** Names whose value is treated as secret in `NAME=value` and `"name": "value"`. */
const SECRET_NAME =
  '[A-Za-z][A-Za-z0-9_.-]*?(?:secret|token|passw(?:or)?d|passphrase|pwd|api[_-]?key|access[_-]?key|private[_-]?key|credentials?|auth[_-]?key|signing[_-]?key)[A-Za-z0-9_.-]*'

/** The minimum length of an assigned value before it counts as a secret. */
export const MIN_ASSIGNED_LENGTH = 12

// Order matters only for ties: on the same span, the earlier rule's kind wins,
// so a known format beats the generic assignment rule.
const BUILTIN: readonly Rule[] = [
  {
    kind: 'PRIVATE_KEY',
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g,
  },
  { kind: 'AWS_KEY_ID', re: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
  { kind: 'GITHUB_TOKEN', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b/g },
  { kind: 'GITLAB_TOKEN', re: /\bglpat-[A-Za-z0-9_-]{20,}/g },
  { kind: 'SLACK_TOKEN', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g },
  { kind: 'SLACK_WEBHOOK', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{20,}/g },
  { kind: 'ANTHROPIC_KEY', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { kind: 'OPENAI_KEY', re: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/g },
  { kind: 'STRIPE_KEY', re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g },
  { kind: 'GOOGLE_API_KEY', re: /\bAIza[0-9A-Za-z_-]{35}/g },
  { kind: 'NPM_TOKEN', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { kind: 'HF_TOKEN', re: /\bhf_[A-Za-z0-9]{34,}\b/g },
  { kind: 'JWT', re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { kind: 'BEARER_TOKEN', re: /\b[Bb]earer\s+([A-Za-z0-9._~+/-]{16,}=*)/g, group: 1 },
  { kind: 'URL_PASSWORD', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@'"]+:([^\s@/'"]{6,})@/gi, group: 1 },
  {
    kind: 'SECRET_VALUE',
    re: new RegExp(`(?<![A-Za-z0-9_])${SECRET_NAME}["']?\\s*[:=]\\s*(["']?)([^\\s"'\`,;]{${MIN_ASSIGNED_LENGTH},})\\1`, 'gi'),
    group: 2,
  },
]

/** An assigned value that is a reference, a path, a URL or filler, not a secret. */
function looksLikeReference(value: string): boolean {
  if (/^[$<{%~/]|^\.\.?\//.test(value)) return true
  if (value.includes('://')) return true
  if (/^(.)\1+$/.test(value)) return true
  if (/^(?:true|false|null|none|undefined)$/i.test(value)) return true
  // A value of one character class (all lowercase letters, say) is usually a word.
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter(c => c.test(value)).length
  return classes < 2
}

export function builtinRules(): Rules {
  return { patterns: BUILTIN, allow: new Set(), allowPatterns: [] }
}

/** A user pattern's name as a placeholder kind: A-Z, 0-9 and _, at most 24. */
export function kindOf(name: string): string {
  return (
    name
      .toUpperCase()
      .replace(/[^A-Z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 24) || 'USER'
  )
}

function compile(source: unknown, flags: unknown): RegExp | string {
  if (typeof source !== 'string' || source === '') return 'regex must be a non-empty string'
  const f = flags === undefined ? '' : flags
  if (typeof f !== 'string' || !/^[imsu]*$/.test(f)) return 'flags may only hold i, m, s and u'
  let re: RegExp
  try {
    re = new RegExp(source, `${f}g`)
  } catch (err) {
    return `does not compile (${err instanceof Error ? err.message : String(err)})`
  }
  if (new RegExp(source, f).test('')) return 'can match an empty string'
  return re
}

/** Parses the patterns file. Every entry it can't use is named in `errors`. */
export function parsePatternsFile(text: string): ParsedPatterns {
  const out: ParsedPatterns = { patterns: [], allow: [], allowPatterns: [], errors: [] }
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch {
    out.errors.push('the file is not valid JSON')
    return out
  }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    out.errors.push('the file must hold a JSON object')
    return out
  }
  const d = data as Record<string, unknown>
  const list = (key: string): unknown[] => {
    const v = d[key]
    if (v === undefined) return []
    if (Array.isArray(v)) return v
    out.errors.push(`"${key}" must be a list`)
    return []
  }
  list('patterns').forEach((p, i) => {
    const entry = (typeof p === 'object' && p !== null ? p : {}) as Record<string, unknown>
    const name = typeof entry.name === 'string' && entry.name.trim() ? entry.name : `pattern ${i + 1}`
    const re = compile(entry.regex, entry.flags)
    if (typeof re === 'string') return void out.errors.push(`pattern "${name}": ${re}`)
    const group = entry.group
    if (group !== undefined && !(typeof group === 'number' && Number.isInteger(group) && group >= 0)) {
      return void out.errors.push(`pattern "${name}": group must be a whole number`)
    }
    out.patterns.push({ kind: kindOf(name), re, ...(group ? { group } : {}) })
  })
  list('allow').forEach((a, i) => {
    if (typeof a === 'string' && a !== '') out.allow.push(a)
    else out.errors.push(`allow entry ${i + 1} must be a non-empty string`)
  })
  list('allowPatterns').forEach((a, i) => {
    const re = compile(a, '')
    if (typeof re === 'string') out.errors.push(`allowPatterns entry ${i + 1}: ${re}`)
    else out.allowPatterns.push(new RegExp(re.source))
  })
  return out
}

export function withUserRules(base: Rules, user: ParsedPatterns): Rules {
  return {
    patterns: [...base.patterns, ...user.patterns],
    allow: new Set([...base.allow, ...user.allow]),
    allowPatterns: [...base.allowPatterns, ...user.allowPatterns],
  }
}

export function isAllowed(value: string, rules: Rules): boolean {
  return rules.allow.has(value) || rules.allowPatterns.some(re => re.test(value))
}

const indexed = new WeakMap<RegExp, RegExp>()

/** The same regex with the `d` flag, so a capture group's offset is known. */
function withIndices(re: RegExp): RegExp {
  if (re.hasIndices) return re
  let d = indexed.get(re)
  if (d === undefined) {
    d = new RegExp(re.source, `${re.flags}d`)
    indexed.set(re, d)
  }
  return d
}

/** Every candidate span from the patterns, allow-listed values removed. */
export function candidates(text: string, rules: Rules): (Span & { rank: number })[] {
  const found: (Span & { rank: number })[] = []
  rules.patterns.forEach((rule, rank) => {
    for (const m of text.matchAll(withIndices(rule.re))) {
      const g = rule.group ?? 0
      const value = m[g]
      const at = m.indices?.[g]
      if (value === undefined || value === '' || at === undefined) continue
      const start = at[0]
      if (rule.kind === 'SECRET_VALUE' && rank < BUILTIN.length && looksLikeReference(value)) continue
      if (isAllowed(value, rules)) continue
      found.push({ start, end: start + value.length, value, kind: rule.kind, rank })
    }
  })
  return found
}

/** Keeps the earliest, then longest, then highest-ranked spans that don't overlap. */
export function resolveOverlaps<T extends Span & { rank: number }>(spans: T[]): T[] {
  const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end || a.rank - b.rank)
  const kept: T[] = []
  let end = -1
  for (const s of sorted) {
    if (s.start < end) continue
    kept.push(s)
    end = s.end
  }
  return kept
}

export function findSecrets(text: string, rules: Rules): Span[] {
  return resolveOverlaps(candidates(text, rules)).map(({ start, end, value, kind }) => ({ start, end, value, kind }))
}
