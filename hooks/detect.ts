// Pure detection: no `$`, no I/O. Three sources, in this order of trust
// (README "What gets masked" is the contract): known values, the vendor
// formats, and one parser per assignment format. Plus the patterns file, the
// allow-list, which environment variables count, and findSecrets.

/** One way to recognise a secret. `group` masks only that capture group. */
export type Rule = {
  kind: string
  re: RegExp
  group?: number
  /** Built-in rules only: also register the percent-decoded value (a URL password). */
  decode?: boolean
}

/** An exact value, masked wherever it appears. */
export type KnownValue = { value: string; kind: string }

export type Rules = {
  /** Exact values: the environment's and the patterns file's. */
  values: readonly KnownValue[]
  patterns: readonly Rule[]
  /** Exact values never masked. */
  allow: ReadonlySet<string>
  /** Values matching any of these are never masked. */
  allowPatterns: readonly RegExp[]
}

/**
 * A secret found in a text: `[start, end)` in UTF-16 code units. For a value
 * registered in decoded form (an escaped JSON string, a percent-encoded URL
 * password) the span is where its written form is, and `value` the decoded one.
 */
export type Span = { start: number; end: number; value: string; kind: string }

export type ParsedPatterns = { patterns: Rule[]; values: KnownValue[]; allow: string[]; allowPatterns: RegExp[]; errors: string[] }

/** The shortest value an assignment, the environment or the patterns file contributes (omp's MIN_OBFUSCATE_SECRET_LEN). */
export const MIN_SECRET_LENGTH = 8

// ─── Names and values ────────────────────────────────────────────────────

/** Final name segments that make an assignment secret. */
const SECRET_WORDS = new Set(['password', 'passwd', 'pwd', 'secret', 'token', 'key', 'apikey', 'credential', 'credentials', 'auth', 'passphrase'])

/** Longer words a final segment may also end with (`PGPASSWORD`, `refreshtoken`). */
const SECRET_SUFFIXES = ['password', 'passwd', 'secret', 'token', 'apikey', 'credential', 'credentials', 'passphrase']

/**
 * Whether an assignment's name marks its value as secret: its final segment
 * (split on `_ . -` and camelCase) is a secret word, or ends with a long one.
 * `DB_PASSWORD`, `api_key`, `GITHUB_TOKEN`, `clientSecret`, `PGPASSWORD`,
 * `aws_secret_access_key` and `aws_session_token` are; `token_count`,
 * `token_kind`, `password_hint` and `GITHUB_TOKEN_PATH` are not.
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

/**
 * An assigned value that stands for a secret rather than being one: a shell
 * or template reference (`$VAR`, `${VAR}`, `${{ expr }}`, `{{ .x }}`), an
 * `<angle-bracket>` placeholder, or filler of one repeated character
 * (`********`). Nothing else is excluded: all-lowercase, numeric, paths and
 * URLs are masked.
 */
export function looksLikeReference(value: string): boolean {
  return (
    /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(value) ||
    /^\$?\{\{.*\}\}$/s.test(value) ||
    /^<[^<>]*>$/.test(value) ||
    /^(.)\1+$/s.test(value)
  )
}

/**
 * An unquoted line-format value that is code, not a secret: a call or a
 * subscript (`tokens[i]`, `getPassword(user),`). Applies to unquoted values
 * in the line formats only.
 */
function isCodeExpression(value: string): boolean {
  return /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*(?:\(.*\)|\[.*\])[,;]?$/.test(value)
}

function isSecretValue(value: string): boolean {
  return value.length >= MIN_SECRET_LENGTH && !looksLikeReference(value)
}

// ─── Source 2: vendor formats ────────────────────────────────────────────

/**
 * Left boundary: not after a letter or digit. Looser than omp's (which also
 * refuses `_` and `-`), because a masker should err toward matching: a key
 * glued to `_` or `=` is still a key.
 */
const B = '(?<![A-Za-z0-9])'

// Order matters only for ties: on the same span, the earlier rule's kind wins.
const VENDOR: readonly Rule[] = [
  {
    kind: 'PRIVATE_KEY',
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g,
  },
  { kind: 'AWS_KEY_ID', re: /(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![A-Z0-9])/g },
  { kind: 'GITHUB_TOKEN', re: new RegExp(`${B}(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\\b`, 'g') },
  { kind: 'GITLAB_TOKEN', re: new RegExp(`${B}glpat-[A-Za-z0-9_-]{20,}`, 'g') },
  { kind: 'SLACK_TOKEN', re: new RegExp(`${B}xox[abposr]-[A-Za-z0-9-]{10,}`, 'g') },
  { kind: 'SLACK_WEBHOOK', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{20,}/g },
  { kind: 'ANTHROPIC_KEY', re: new RegExp(`${B}sk-ant-[A-Za-z0-9_-]{20,}`, 'g') },
  { kind: 'OPENAI_KEY', re: new RegExp(`${B}sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}`, 'g') },
  { kind: 'STRIPE_KEY', re: new RegExp(`${B}(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`, 'g') },
  { kind: 'STRIPE_WEBHOOK', re: new RegExp(`${B}whsec_[A-Za-z0-9]{20,}`, 'g') },
  { kind: 'SENDGRID_KEY', re: new RegExp(`${B}SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}`, 'g') },
  { kind: 'GOOGLE_API_KEY', re: new RegExp(`${B}AIza[0-9A-Za-z_-]{35}`, 'g') },
  { kind: 'NPM_TOKEN', re: new RegExp(`${B}npm_[A-Za-z0-9]{36}\\b`, 'g') },
  { kind: 'HF_TOKEN', re: new RegExp(`${B}hf_[A-Za-z0-9]{34,}\\b`, 'g') },
  { kind: 'JWT', re: new RegExp(`${B}eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}`, 'g') },
  { kind: 'BEARER_TOKEN', re: /\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)/gi, group: 1 },
  { kind: 'URL_PASSWORD', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@'"]+:([^\s@/'"]{6,})@/gi, group: 1, decode: true },
]

// ─── Source 3: assignments, one parser per format ───────────────────────

/** A value an assignment parser found. `start` is where its written form begins. */
type Found = { start: number; end: number; value: string }

/** An assignment's name. Leading underscores are part of it (`_PASSWORD`, `_authToken`). */
const NAME = '_*[A-Za-z][A-Za-z0-9_.-]*'

/** A line format's start: indentation and an optional YAML list dash. */
const LEAD = '^[ \\t]*(?:-[ \\t]+)?'

/**
 * dotenv, shell, `.properties`, TOML and INI: `[export ]NAME=value`,
 * `declare -x NAME=value`, `name = value`, and `.npmrc`'s
 * `//registry/:_authToken=value`. Group 1 the name, 2 the rest of the line.
 */
const KEY_EQUALS = new RegExp(
  `${LEAD}(?:(?:export|(?:declare|typeset)[ \\t]+-[A-Za-z]+)[ \\t]+)?(?://[^\\s=]*?:)?(${NAME})[ \\t]*=(?!=)[ \\t]*([^\\n]*)`,
  'gmd',
)

/**
 * YAML: `name: value`, `"name": value`, `- name: value`. Groups 1-3 the name
 * (double-, single- or unquoted), 4 the space after the colon, 5 the rest. A
 * quoted key needs no space after its colon (`"name":value`, as YAML 1.2
 * allows for JSON-like keys); an unquoted one does.
 */
const YAML_KEY = new RegExp(`${LEAD}(?:"([^"\\n]*)"|'([^'\\n]*)'|(${NAME}))[ \\t]*:([ \\t]*)([^\\n]*)$`, 'gmd')

/** `--name=value` or `--name value`, anywhere. Group 1 the name, 2 the separator, 3-5 the value. */
const CLI_FLAG = /(?<![A-Za-z0-9_-])--(?!no-)([A-Za-z0-9][A-Za-z0-9_.-]*)(=|[ \t]+)(?:"([^"\n]*)"|'([^'\n]*)'|([^\s;&|<>()'"`]+))/dg

/** The index of the quote closing one opened at `rest[0]`, or -1. `escapes`: a backslash escapes the next character. */
function closingQuote(rest: string, escapes: boolean): number {
  const q = rest[0]
  for (let i = 1; i < rest.length; i++) {
    const c = rest[i]
    if (escapes && c === '\\') i++
    else if (c === q) return i
  }
  return -1
}

/** The value of a `KEY=value` line, from the text after `=`; `at` is where that text starts. */
function keyEqualsValues(rest: string, at: number, out: Found[]) {
  const q = rest[0]
  if (q === '"' || q === "'") {
    const close = closingQuote(rest, q === '"')
    const raw = close === -1 ? rest.slice(1).trimEnd() : rest.slice(1, close)
    out.push({ start: at + 1, end: at + 1 + raw.length, value: raw })
    if (q === '"' && raw.includes('\\')) out.push({ start: at + 1, end: at + 1 + raw.length, value: raw.replace(/\\(.)/g, '$1') })
    return
  }
  const comment = /\s#/.exec(rest)
  const value = rest.slice(0, comment?.index ?? rest.length).trimEnd()
  if (isCodeExpression(value)) return
  out.push({ start: at, end: at + value.length, value })
  // `NAME=value command ...`: the shell's reading, the first word, as well.
  const word = /^[^\s;&|<>()'"`]+/.exec(value)?.[0]
  if (word !== undefined && word !== value) out.push({ start: at, end: at + word.length, value: word })
}

/** The value of a YAML `name: value` line, from the text after `: `; `at` is where that text starts. */
function yamlValues(rest: string, at: number, isKeyQuoted: boolean, out: Found[]) {
  const anchor = /^&[^\s]+[ \t]+/.exec(rest)
  if (anchor !== null) return yamlValues(rest.slice(anchor[0].length), at + anchor[0].length, isKeyQuoted, out)
  const q = rest[0]
  if (q === '"' || q === "'") {
    const close = q === '"' ? closingQuote(rest, true) : singleQuoteClose(rest)
    const raw = close === -1 ? rest.slice(1).trimEnd() : rest.slice(1, close)
    out.push({ start: at + 1, end: at + 1 + raw.length, value: raw })
    let decoded = raw
    if (q === "'") decoded = raw.replace(/''/g, "'")
    else if (raw.includes('\\')) {
      try {
        decoded = JSON.parse(`"${raw}"`) as string
      } catch {
        decoded = raw.replace(/\\(.)/g, '$1')
      }
    }
    if (decoded !== raw) out.push({ start: at + 1, end: at + 1 + raw.length, value: decoded })
    return
  }
  // Block scalars, tags, aliases, flow collections and reserved indicators.
  if (q === undefined || '|>!*{[@`'.includes(q)) return
  const comment = /\s#/.exec(rest)
  let value = rest.slice(0, comment?.index ?? rest.length).trimEnd()
  // A JSON-style line in text that isn't JSON as a whole: drop the
  // separator and closing brackets that follow a scalar.
  if (isKeyQuoted) value = value.replace(/[,\]}]+$/, '')
  if (isCodeExpression(value)) return
  out.push({ start: at, end: at + value.length, value })
}

/** A YAML single-quoted scalar's closing quote (`''` is an escaped quote), or -1. */
function singleQuoteClose(rest: string): number {
  for (let i = 1; i < rest.length; i++) {
    if (rest[i] !== "'") continue
    if (rest[i + 1] === "'") i++
    else return i
  }
  return -1
}

function keyEqualsFinds(text: string, out: Found[]) {
  for (const m of text.matchAll(KEY_EQUALS)) {
    if (!isSecretName(m[1]!)) continue
    keyEqualsValues(m[2]!, m.indices![2]![0], out)
  }
}

function yamlFinds(text: string, out: Found[]) {
  for (const m of text.matchAll(YAML_KEY)) {
    const name = m[1] ?? m[2] ?? m[3]!
    const isKeyQuoted = m[3] === undefined
    if (m[5] === '' || (!isKeyQuoted && m[4] === '') || !isSecretName(name)) continue
    yamlValues(m[5]!, m.indices![5]![0], isKeyQuoted, out)
  }
}

function cliFinds(text: string, out: Found[]) {
  const re = new RegExp(CLI_FLAG)
  for (let m = re.exec(text); m !== null; m = re.exec(text)) {
    const g = m[3] !== undefined ? 3 : m[4] !== undefined ? 4 : 5
    const value = m[g]!
    const at = m.indices![g]![0]
    // `--flag --other`: the next word is a flag, not this one's value.
    if (g === 5 && m[2] !== '=' && value.startsWith('-')) {
      re.lastIndex = at
      continue
    }
    if (isSecretName(m[1]!)) out.push({ start: at, end: at + value.length, value })
  }
}

/** The line formats, which also read every string inside a JSON document. */
function lineFinds(text: string, out: Found[]) {
  keyEqualsFinds(text, out)
  yamlFinds(text, out)
  cliFinds(text, out)
}

function parses(text: string): boolean {
  try {
    JSON.parse(text)
    return true
  } catch {
    return false
  }
}

/** The deepest JSON-in-a-JSON-string the parsers follow. */
const MAX_JSON_DEPTH = 3

/**
 * Where the JSON value opened at `text[open]` closes (the index after its
 * closing bracket), skipping brackets inside strings; -1 when it doesn't
 * close or the scan would pass `limit`.
 */
function balancedEnd(text: string, open: number, limit: number): number {
  let depth = 0
  for (let i = open; i < text.length && i < limit; i++) {
    const c = text[i]
    if (c === '"') {
      for (i++; i < text.length && text[i] !== '"'; i++) if (text[i] === '\\') i++
    } else if (c === '{' || c === '[') depth++
    else if (c === '}' || c === ']') {
      if (--depth === 0) return i + 1
    }
  }
  return -1
}

/** The longest JSON document looked for inside other text; a whole-text document has no limit. */
const MAX_EMBEDDED_JSON = 1024 * 1024

/** How many opening brackets of one line are tried as the start of a document. */
const MAX_OPENS_PER_LINE = 8

/**
 * JSON: the whole text, or else each document that starts at one of a line's
 * first few `{` or `[` and runs to its matching bracket (NDJSON lines, a log
 * line's tail, a pretty-printed body after headers), where `JSON.parse`
 * accepts it. Text that doesn't parse gets no JSON handling. Bracket scans
 * are charged against a budget of a few passes over the text, each scan at
 * most 1 MiB, so code full of braces or unclosed brackets stays linear; once
 * the budget is spent the rest of the text gets no JSON handling.
 */
function jsonFinds(text: string, out: Found[], depth: number) {
  const trimmed = text.trim()
  if (/^[{[]/.test(trimmed) && parses(trimmed)) return walkJson(trimmed, text.indexOf(trimmed), out, depth)
  let budget = 8 * text.length
  for (let lineAt = 0; lineAt < text.length && budget > 0; ) {
    const nl = text.indexOf('\n', lineAt)
    const lineEnd = nl === -1 ? text.length : nl
    let next = lineEnd + 1
    let from = lineAt
    for (let tries = 0; tries < MAX_OPENS_PER_LINE && budget > 0; tries++) {
      const rel = text.slice(from, lineEnd).search(/[{[]/)
      if (rel === -1) break
      from += rel
      const limit = from + Math.min(budget, MAX_EMBEDDED_JSON)
      const close = balancedEnd(text, from, limit)
      budget -= (close === -1 ? Math.min(limit, text.length) : close) - from
      if (close !== -1) {
        const doc = text.slice(from, close)
        if (parses(doc)) {
          walkJson(doc, from, out, depth)
          next = Math.max(next, close)
          break
        }
      }
      from++
    }
    lineAt = next
  }
}

type Frame = { isObject: boolean; key: string | null; isAwaitingKey: boolean; isSecret: boolean }

/**
 * Walks a document `JSON.parse` accepted, at `base` in the text: a string or
 * number directly under a secret-named key, or in an array directly under
 * one, is a secret (a string as written and decoded, a number as its source
 * text). Every string value is also read with the line formats. Iterative, so
 * deep nesting can't overflow the stack.
 */
function walkJson(src: string, base: number, out: Found[], depth: number) {
  const stack: Frame[] = []
  const top = () => stack[stack.length - 1]
  const isSecretHere = () => {
    const f = top()
    if (f === undefined) return false
    return f.isObject ? !f.isAwaitingKey && f.key !== null && isSecretName(f.key) : f.isSecret
  }
  const afterValue = () => {
    const f = top()
    if (f?.isObject) f.key = null
  }
  for (let i = 0; i < src.length; ) {
    const c = src[i]!
    if (c === '{' || c === '[') {
      const isSecret = c === '[' && isSecretHere()
      stack.push({ isObject: c === '{', key: null, isAwaitingKey: c === '{', isSecret })
      i++
    } else if (c === '}' || c === ']') {
      stack.pop()
      afterValue()
      i++
    } else if (c === ',') {
      const f = top()
      if (f?.isObject) f.isAwaitingKey = true
      i++
    } else if (c === '"') {
      let j = i + 1
      while (src[j] !== '"') j += src[j] === '\\' ? 2 : 1
      const raw = src.slice(i + 1, j)
      const decoded = JSON.parse(src.slice(i, j + 1)) as string
      const f = top()
      if (f?.isObject && f.isAwaitingKey) {
        f.key = decoded
        f.isAwaitingKey = false
      } else {
        const start = base + i + 1
        if (isSecretHere()) {
          out.push({ start, end: start + raw.length, value: raw })
          if (decoded !== raw) out.push({ start, end: start + raw.length, value: decoded })
        }
        stringFinds(decoded, raw, start, out, depth)
        afterValue()
      }
      i = j + 1
    } else if (c === '-' || (c >= '0' && c <= '9')) {
      let j = i
      while (j < src.length && /[-+.0-9eE]/.test(src[j]!)) j++
      if (isSecretHere()) out.push({ start: base + i, end: base + j, value: src.slice(i, j) })
      afterValue()
      i = j
    } else if (c >= 'a' && c <= 'z') {
      while (i < src.length && src[i]! >= 'a' && src[i]! <= 'z') i++
      afterValue()
    } else i++
  }
}

/** A JSON string's decoded text read with the parsers; where it was escaped, by value only. */
function stringFinds(decoded: string, raw: string, start: number, out: Found[], depth: number) {
  if (depth >= MAX_JSON_DEPTH || !/[=:]|--/.test(decoded)) return
  const inner: Found[] = []
  assignmentsInto(decoded, inner, depth + 1)
  for (const f of inner) {
    out.push(decoded === raw ? { start: start + f.start, end: start + f.end, value: f.value } : { start, end: start + raw.length, value: f.value })
  }
}

function assignmentsInto(text: string, out: Found[], depth: number) {
  lineFinds(text, out)
  jsonFinds(text, out, depth)
}

/** Every secret value the assignment formats find, before the allow-list. */
export function assignments(text: string): Found[] {
  const out: Found[] = []
  assignmentsInto(text, out, 0)
  return out.filter(f => isSecretValue(f.value))
}

// ─── Source 1: known values ──────────────────────────────────────────────

/** omp's rule for environment variables whose values are secrets. */
const SECRET_ENV_NAME = /(?:KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH|CREDENTIAL|PRIVATE|OAUTH)(?:_|$)/i

/** The password of a value that is a connection URL (`scheme://user:password@host`). */
const CONNECTION_URL_PASSWORD = /^[a-z][a-z0-9+.-]*:\/\/[^/:@?#\s]*:([^/?#\s]+)@/i

/** `/usr/bin/env -0` output as name and value pairs (NUL-separated, so values may hold newlines). */
export function parseEnv0(stdout: string): [string, string][] {
  const out: [string, string][] = []
  for (const entry of stdout.split('\0')) {
    const eq = entry.indexOf('=')
    if (eq > 0) out.push([entry.slice(0, eq), entry.slice(eq + 1)])
  }
  return out
}

/**
 * The environment's secrets (omp's `collectEnvSecrets`): every value of at
 * least 8 characters under a name matching SECRET_ENV_NAME, then the
 * password of a connection URL in any value, raw and percent-decoded. Each
 * value once; the first name it came under gives the kind.
 */
export function envSecrets(env: readonly (readonly [string, string])[]): KnownValue[] {
  const out: KnownValue[] = []
  const seen = new Set<string>()
  const add = (value: string, kind: string) => {
    if (value.length < MIN_SECRET_LENGTH || seen.has(value)) return
    seen.add(value)
    out.push({ value, kind })
  }
  for (const [name, value] of env) {
    if (!SECRET_ENV_NAME.test(name)) continue
    const kind = kindOf(`ENV_${name}`)
    add(value, isKind(kind) ? kind : 'ENV_SECRET')
  }
  for (const [, value] of env) {
    const password = CONNECTION_URL_PASSWORD.exec(value)?.[1]
    if (password === undefined) continue
    add(password, 'URL_PASSWORD')
    try {
      add(decodeURIComponent(password), 'URL_PASSWORD')
    } catch {
      // Malformed percent-encoding: the raw password is registered.
    }
  }
  return out
}

// ─── Rules ───────────────────────────────────────────────────────────────

export function builtinRules(): Rules {
  return { values: [], patterns: VENDOR, allow: new Set(), allowPatterns: [] }
}

/** The rules with exact values added (the environment's). */
export function withKnownValues(base: Rules, values: readonly KnownValue[]): Rules {
  return { ...base, values: [...base.values, ...values] }
}

/** A placeholder KIND: an uppercase letter, then up to 23 of A-Z, 0-9 and _. One contract for parsing, minting and recognising. */
export const KIND_SOURCE = '[A-Z][A-Z0-9_]{0,23}'

export function isKind(kind: string): boolean {
  return new RegExp(`^${KIND_SOURCE}$`).test(kind) && !kind.endsWith('_')
}

/** A user pattern's name as a placeholder kind: A-Z, 0-9 and _, at most 24. */
export function kindOf(name: string): string {
  return (
    name
      .toUpperCase()
      .replace(/[^A-Z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 24)
      .replace(/_+$/, '')
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
  const out: ParsedPatterns = { patterns: [], values: [], allow: [], allowPatterns: [], errors: [] }
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
    const kind = kindOf(name)
    if (!isKind(kind)) return void out.errors.push(`pattern "${name}": the name must start with a letter (it becomes the placeholder's kind)`)
    out.patterns.push({ kind, re, ...(group ? { group } : {}) })
  })
  // Never echo a value into an error: name the entry by its position and name.
  list('secrets').forEach((s, i) => {
    const entry = (typeof s === 'object' && s !== null ? s : {}) as Record<string, unknown>
    const label = typeof entry.name === 'string' && entry.name.trim() ? `secret "${entry.name}"` : `secret ${i + 1}`
    const value = entry.value
    if (typeof value !== 'string') return void out.errors.push(`${label}: value must be a string`)
    if (value.length < MIN_SECRET_LENGTH) return void out.errors.push(`${label}: value must be at least ${MIN_SECRET_LENGTH} characters`)
    if (value.includes('__SECRET_')) return void out.errors.push(`${label}: value must not contain __SECRET_ (the placeholder prefix)`)
    const kind = entry.name === undefined ? 'SECRET' : typeof entry.name === 'string' ? kindOf(entry.name) : ''
    if (!isKind(kind)) return void out.errors.push(`${label}: the name must start with a letter (it becomes the placeholder's kind)`)
    out.values.push({ value, kind })
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
    values: [...base.values, ...user.values],
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

/** The kind of every value the assignment parsers find. */
export const ASSIGNMENT_KIND = 'SECRET_VALUE'

/**
 * Every candidate span, in order of trust: known values, then the patterns
 * (vendor formats, then the user's), then the assignment parsers. Allow-listed
 * values are removed. Overlapping candidates are all kept; `rank` settles ties.
 */
export function candidates(text: string, rules: Rules): (Span & { rank: number })[] {
  const found: (Span & { rank: number })[] = []
  const add = (start: number, end: number, value: string, kind: string, rank: number) => {
    if (value !== '' && !isAllowed(value, rules)) found.push({ start, end, value, kind, rank })
  }
  for (const { value, kind } of rules.values) {
    for (let at = text.indexOf(value); at !== -1; at = text.indexOf(value, at + 1)) add(at, at + value.length, value, kind, 0)
  }
  rules.patterns.forEach((rule, i) => {
    const re = new RegExp(withIndices(rule.re))
    const g = rule.group ?? 0
    for (let m = re.exec(text); m !== null; m = re.exec(text)) {
      if (m[0] === '') re.lastIndex++
      const value = m[g]
      const at = m.indices?.[g]
      if (value === undefined || at === undefined) continue
      add(at[0], at[1], value, rule.kind, i + 1)
      if (rule.decode && value.includes('%')) {
        try {
          const decoded = decodeURIComponent(value)
          if (decoded !== value) add(at[0], at[1], decoded, rule.kind, i + 1)
        } catch {
          // Malformed percent-encoding: the written value is registered.
        }
      }
    }
  })
  const rank = rules.patterns.length + 1
  for (const f of assignments(text)) add(f.start, f.end, f.value, ASSIGNMENT_KIND, rank)
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
