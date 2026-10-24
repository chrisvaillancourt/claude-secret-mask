// Pure detection: no `$`, no I/O. The built-in patterns, the user's patterns
// file, the allow-list, and findSecrets, which answers non-overlapping spans.

/**
 * One way to recognise a secret. `group` masks only that capture group; a
 * list masks the first of them that matched (alternative value forms).
 */
export type Rule = {
  kind: string
  re: RegExp
  group?: number | readonly number[]
  /** Built-in rules only: a further check on the match (the assignment rule's name policy). */
  accept?: (m: RegExpMatchArray, value: string) => boolean
}

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

/** An assignment's name: `NAME=`, `name:`, `"name":`, `--name=`. */
const ASSIGNED_NAME = '(?<![A-Za-z0-9_.])([A-Za-z][A-Za-z0-9_.-]*)'

/** Final name segments that make an assignment secret. */
const SECRET_WORDS = new Set(['password', 'passwd', 'pwd', 'secret', 'token', 'key', 'apikey', 'credential', 'credentials', 'auth', 'passphrase'])

/** Longer words a final segment may also end with (`PGPASSWORD`, `refreshtoken`). */
const SECRET_SUFFIXES = ['password', 'passwd', 'secret', 'token', 'apikey', 'credential', 'credentials', 'passphrase']

/**
 * Whether an assignment's name marks its value as secret: its final segment
 * (split on `_ . -` and camelCase) is a secret word, or ends with a long one.
 * `DB_PASSWORD`, `api_key`, `GITHUB_TOKEN`, `clientSecret` and `PGPASSWORD`
 * are; `token_count`, `token_kind`, `password_hint` and `GITHUB_TOKEN_PATH`
 * are not.
 */
export function isSecretName(name: string): boolean {
  const parts = name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[_.-]+/)
    .filter(Boolean)
  const last = parts.at(-1)
  if (last === undefined) return false
  return SECRET_WORDS.has(last) || SECRET_SUFFIXES.some(w => last.endsWith(w))
}

/** The minimum length of an assigned value before it counts as a secret. */
export const MIN_ASSIGNED_LENGTH = 8

// Order matters only for ties: on the same span, the earlier rule's kind wins,
// so a known format beats the generic assignment rule.
const BUILTIN: readonly Rule[] = [
  {
    kind: 'PRIVATE_KEY',
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g,
  },
  // Lookarounds, not \b: a key glued to `_` or a letter is still a key.
  { kind: 'AWS_KEY_ID', re: /(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![A-Z0-9])/g },
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
  { kind: 'BEARER_TOKEN', re: /\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)/gi, group: 1 },
  { kind: 'URL_PASSWORD', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@'"]+:([^\s@/'"]{6,})@/gi, group: 1 },
  {
    // NAME=value, NAME: value, "name": "value", where the name passes
    // isSecretName. A quoted value is taken whole (spaces and commas
    // included); an unquoted one runs to whitespace or , ;
    kind: 'SECRET_VALUE',
    re: new RegExp(
      `${ASSIGNED_NAME}["']?\\s*[:=]\\s*(?:"((?:[^"\\\\\\n]|\\\\.){${MIN_ASSIGNED_LENGTH},})"|'([^'\\n]{${MIN_ASSIGNED_LENGTH},})'|([^\\s"'\`,;&\\\\]{${MIN_ASSIGNED_LENGTH},}))`,
      'g',
    ),
    group: [2, 3, 4],
    accept: (m, value) => isSecretName(m[1] ?? '') && !looksLikeReference(value),
  },
]

/**
 * An assigned value that stands for a secret rather than being one: a shell
 * or template reference (`$VAR`, `${VAR}`, `{{ .x }}`), an `<angle-bracket>`
 * placeholder, or filler of one repeated character (`********`). Nothing else
 * is excluded: all-lowercase, numeric, paths and URLs are masked.
 */
export function looksLikeReference(value: string): boolean {
  return /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(value) || /^\{\{.*\}\}$/s.test(value) || /^<[^<>]*>$/.test(value) || /^(.)\1+$/.test(value)
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
    // A manual loop, not matchAll: when `accept` refuses a match (a name that
    // isn't secret), scanning resumes one character in, so a refused match
    // never swallows a secret assignment inside its span.
    const re = new RegExp(withIndices(rule.re))
    for (let m = re.exec(text); m !== null; m = re.exec(text)) {
      if (m[0] === '') re.lastIndex++
      const groups = rule.group === undefined ? [0] : typeof rule.group === 'number' ? [rule.group] : rule.group
      const g = groups.find(i => m[i] !== undefined) ?? groups[0]!
      const value = m[g]
      const at = m.indices?.[g]
      if (value === undefined || value === '' || at === undefined) continue
      const start = at[0]
      if (rule.accept !== undefined && !rule.accept(m, value)) {
        re.lastIndex = m.index + 1
        continue
      }
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
