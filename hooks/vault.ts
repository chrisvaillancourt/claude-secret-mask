// Pure masking and restoring over a Vault: no `$`, no I/O. The vault is the
// only place a secret's value is kept; register.ts holds it in module memory.
import { candidates, resolveOverlaps } from './detect'
import type { Rules, Span } from './detect'

/** A placeholder this mod issues: `__SECRET_<KIND>_<8 uppercase hex>__`. */
export const PLACEHOLDER = /__SECRET_[A-Z0-9_]+?_[0-9A-F]{8}__/
const PLACEHOLDERS = new RegExp(PLACEHOLDER.source, 'g')

export type Vault = {
  /** Secret value to its placeholder. */
  byValue: Map<string, string>
  /** Placeholder to the value and its kind. */
  byToken: Map<string, { value: string; kind: string }>
}

/** Answers 8 uppercase hex digits; random in the mod, a counter in tests. */
export type Mint = () => string

export function newVault(): Vault {
  return { byValue: new Map(), byToken: new Map() }
}

export function placeholderFor(kind: string, hex: string): string {
  return `__SECRET_${kind}_${hex}__`
}

/** What a mask call did: how many spans it replaced and the kinds of new secrets. */
export type MaskTally = { count: number; added: string[] }

function issue(value: string, kind: string, vault: Vault, mint: Mint, text: string, tally: MaskTally): string {
  const known = vault.byValue.get(value)
  if (known !== undefined) return known
  for (let i = 0; i < 16; i++) {
    const token = placeholderFor(kind, mint())
    if (!PLACEHOLDER.test(token)) throw new Error('mint answered a token outside the placeholder form')
    if (vault.byToken.has(token) || text.includes(token)) continue
    vault.byValue.set(value, token)
    vault.byToken.set(token, { value, kind })
    tally.added.push(kind)
    return token
  }
  throw new Error('could not mint an unused placeholder')
}

/** Literal occurrences of values the vault already holds. */
function knownSpans(text: string, vault: Vault): (Span & { rank: number })[] {
  const out: (Span & { rank: number })[] = []
  for (const [value, token] of vault.byValue) {
    const kind = vault.byToken.get(token)?.kind ?? 'SECRET'
    for (let at = text.indexOf(value); at !== -1; at = text.indexOf(value, at + value.length)) {
      out.push({ start: at, end: at + value.length, value, kind, rank: -1 })
    }
  }
  return out
}

function maskSegment(seg: string, vault: Vault, rules: Rules, mint: Mint, whole: string, tally: MaskTally): string {
  const spans = resolveOverlaps([...knownSpans(seg, vault), ...candidates(seg, rules)])
  if (spans.length === 0) return seg
  let out = ''
  let at = 0
  for (const s of spans) {
    out += seg.slice(at, s.start) + issue(s.value, s.kind, vault, mint, whole, tally)
    at = s.end
    tally.count++
  }
  return out + seg.slice(at)
}

function maskInto(text: string, vault: Vault, rules: Rules, mint: Mint, tally: MaskTally): string {
  // Placeholders already in the text are kept as they are and never scanned,
  // so masking twice changes nothing and no rule matches across one.
  let out = ''
  let at = 0
  for (const m of text.matchAll(PLACEHOLDERS)) {
    const start = m.index ?? 0
    out += maskSegment(text.slice(at, start), vault, rules, mint, text, tally) + m[0]
    at = start + m[0].length
  }
  return out + maskSegment(text.slice(at), vault, rules, mint, text, tally)
}

export function maskText(text: string, vault: Vault, rules: Rules, mint: Mint): { text: string } & MaskTally {
  const tally: MaskTally = { count: 0, added: [] }
  return { text: maskInto(text, vault, rules, mint, tally), ...tally }
}

type Block = { type: string; [field: string]: unknown }

/**
 * Masks a row's blocks as session.append hands them: text blocks and each
 * tool_result's content (a string, or text blocks among others). Every other
 * block (thinking, tool_use, media) is returned as the same object.
 */
export function maskBlocks<B extends Block>(content: readonly B[], vault: Vault, rules: Rules, mint: Mint): { content: B[] } & MaskTally {
  const tally: MaskTally = { count: 0, added: [] }
  const text = (b: Block): Block => {
    if (b.type !== 'text' || typeof b.text !== 'string') return b
    const before = tally.count
    const masked = maskInto(b.text, vault, rules, mint, tally)
    return tally.count === before ? b : { ...b, text: masked }
  }
  const out = content.map(b => {
    if (b.type === 'text') return text(b) as B
    if (b.type !== 'tool_result') return b
    const before = tally.count
    let inner: unknown = b.content
    if (typeof inner === 'string') inner = maskInto(inner, vault, rules, mint, tally)
    else if (Array.isArray(inner)) inner = inner.map(x => (typeof x === 'object' && x !== null ? text(x as Block) : x))
    return tally.count === before ? b : ({ ...b, content: inner } as B)
  })
  return { content: out, ...tally }
}

/** Masks every string value in a structured result; keys and base64 payloads are left alone. */
export function maskDeep(value: unknown, vault: Vault, rules: Rules, mint: Mint): { value: unknown } & MaskTally {
  const tally: MaskTally = { count: 0, added: [] }
  const walk = (v: unknown, skip: boolean): unknown => {
    if (typeof v === 'string') return skip ? v : maskInto(v, vault, rules, mint, tally)
    if (Array.isArray(v)) return v.map(x => walk(x, false))
    if (typeof v === 'object' && v !== null) {
      const o = v as Record<string, unknown>
      const isMedia = o.type === 'base64'
      const out: Record<string, unknown> = {}
      for (const [k, x] of Object.entries(o)) out[k] = walk(x, k === 'base64' || (isMedia && k === 'data'))
      return out
    }
    return v
  }
  const out = walk(value, false)
  return { value: tally.count === 0 ? value : out, ...tally }
}

export type Restored = { text: string; count: number; unknown: string[] }

/** Puts back every placeholder the vault holds; reports the ones it doesn't. */
export function restoreText(text: string, vault: Vault): Restored {
  let count = 0
  const unknown = new Set<string>()
  const out = text.replace(PLACEHOLDERS, token => {
    const entry = vault.byToken.get(token)
    if (entry === undefined) {
      unknown.add(token)
      return token
    }
    count++
    return entry.value
  })
  return { text: out, count, unknown: [...unknown] }
}

/** Keys of a tool call's input that are the engine's, never the tool's arguments. */
const RESERVED = new Set(['tool', 'tool_use_id', 'agentId', 'requestMeta', 'consent'])

/**
 * Restores placeholders in a tool call's input: in the named top-level string
 * fields, or with `'all'` in every string value below the tool's arguments
 * (never in keys or the engine's reserved fields).
 */
export function restoreFields<T extends Record<string, unknown>>(
  input: T,
  fields: readonly string[] | 'all',
  vault: Vault,
): { input: T; count: number; unknown: string[] } {
  let count = 0
  const unknown = new Set<string>()
  const one = (s: string) => {
    const r = restoreText(s, vault)
    count += r.count
    r.unknown.forEach(u => unknown.add(u))
    return r.text
  }
  const deep = (v: unknown): unknown => {
    if (typeof v === 'string') return one(v)
    if (Array.isArray(v)) return v.map(deep)
    if (typeof v === 'object' && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, deep(x)]))
    return v
  }
  const out: Record<string, unknown> = { ...input }
  for (const [k, v] of Object.entries(input)) {
    if (RESERVED.has(k)) continue
    if (fields === 'all') out[k] = deep(v)
    else if (fields.includes(k) && typeof v === 'string') out[k] = one(v)
  }
  return { input: (count === 0 ? input : out) as T, count, unknown: [...unknown] }
}
