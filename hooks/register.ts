import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import { builtinRules, envSecrets, findSecrets, parseEnv0, parsePatternsFile, withKnownValues, withUserRules } from './detect'
import type { KnownValue, ParsedPatterns, Rules } from './detect'
import {
  INITIAL,
  USAGE,
  configFrom,
  expandHome,
  isActive,
  isMediaPath,
  isMissingPathError,
  isSessionToolResult,
  MAX_MENTION_BYTES,
  mentionReason,
  parseArgs,
  patternsLine,
  restoreFieldsFor,
  selfTest,
  statusText,
  unknownReason,
  withheld,
  WITHHELD,
} from './policy'
import type { Stats } from './policy'
import { holdsKnownValue, maskBlocks, maskDeep, maskText, newVault, restoreFields } from './vault'
import type { MaskTally, Vault } from './vault'
import type { Config } from '../types'

const NAME = 'secret-mask'

// Only the on/off override lives in $.state (it survives a hot reload). The
// shape tag changed when Session lost its `turns` field.
const sessionAtom = atom({ plugin: 'secret-mask', key: 'session' } as const, INITIAL, { shape: 'session-2' })

/**
 * Everything else is module memory, made fresh by each `register`: the vault
 * (the only place a secret's value is kept), the rules and the counts. A hot
 * reload or restart drops it on purpose; see AGENTS.md.
 */
type Ctx = {
  config: Config
  vault: Vault
  rules: Rules
  /** The environment's secret values, read once per load; module memory only, like the vault. */
  envValues: KnownValue[]
  user: ParsedPatterns | null
  stats: Stats
}

let ctx: Ctx = fresh(configFrom({}))

function fresh(config: Config): Ctx {
  return {
    config,
    vault: newVault(),
    rules: builtinRules(),
    envValues: [],
    user: null,
    stats: {
      secrets: {},
      masked: 0,
      restored: 0,
      denied: 0,
      patterns: { path: config.patternsFile, state: 'none', count: 0, values: 0, errors: [] },
      env: { count: 0, error: null },
    },
  }
}

/** 8 random uppercase hex digits for a placeholder. */
function mint(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(4))
  return Array.from(bytes, b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase()
}

function tally(t: MaskTally) {
  ctx.stats.masked += t.count
  for (const kind of t.added) ctx.stats.secrets[kind] = (ctx.stats.secrets[kind] ?? 0) + 1
}

/** Best effort: reporting must never throw out of a hook. Never pass a value here. */
function log($: EngineInterface, text: string) {
  try {
    $.ui.log(`${NAME}: ${text}`)
  } catch {
    // nothing to do
  }
}

async function active($: EngineInterface): Promise<boolean> {
  return isActive(ctx.config, await read($, sessionAtom))
}

/** The rules from the built-ins, the environment's values and the patterns file. */
function rebuildRules() {
  const base = withKnownValues(builtinRules(), ctx.envValues)
  ctx.rules = ctx.user === null ? base : withUserRules(base, ctx.user)
}

/**
 * Reads the environment once (`$.env.get` can't enumerate names) and keeps
 * the secret values in module memory. Its output goes nowhere else: not a
 * log, the store, status or an error. A failed read is reported by count and
 * reason only, and masking goes on with the other sources.
 */
async function loadEnv($: EngineInterface) {
  const status = ctx.stats.env
  try {
    const r = await $.process.run(['/usr/bin/env', '-0'], { timeoutMs: 10000 })
    if (r.exitCode !== 0) throw new Error(`/usr/bin/env exited with ${r.exitCode}`)
    ctx.envValues = envSecrets(parseEnv0(r.stdout))
    status.count = ctx.envValues.length
    status.error = r.isStdoutTruncated ? 'its output was cut at 4 MiB' : null
  } catch (err) {
    ctx.envValues = []
    status.count = 0
    // The engine's message about starting the command; it carries no output.
    status.error = err instanceof Error ? err.message.slice(0, 200) : 'unknown error'
    log($, `could not read the environment, so no values from it are masked (${status.error})`)
  }
  rebuildRules()
}

async function loadPatterns($: EngineInterface) {
  const path = expandHome(ctx.config.patternsFile, await $.env.get('HOME'))
  const status = ctx.stats.patterns
  status.path = path ?? ctx.config.patternsFile
  ctx.user = null
  status.values = 0
  rebuildRules()
  if (path === undefined) {
    status.errors = ['HOME is unset, so ~ cannot be expanded']
    return
  }
  let text: string
  try {
    text = await $.fs.read(path)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    status.state = 'none'
    status.errors = /ENOENT|no such file|not found/i.test(msg) ? [] : [`not read: ${msg.slice(0, 200)}`]
    return
  }
  const parsed = parsePatternsFile(text)
  ctx.user = parsed
  rebuildRules()
  status.state = parsed.errors.length === 0 ? 'loaded' : 'error'
  status.count = parsed.patterns.length
  status.values = parsed.values.length
  status.errors = parsed.errors
  if (parsed.errors.length > 0) log($, patternsLine(status))
}

/**
 * Output too large to keep inline is saved by core to a tool-results file
 * before any hook sees it; the result names it. Mask that file in place, but
 * only where its resolved path is a file directly in this session's own
 * tool-results folder under the resolved projects root. Anything else is
 * refused (a link out of the folder, another session's, a forged path).
 *
 * Fail closed: a file we may rewrite but could not read, mask or write back
 * (the engine refuses a read or write over 4 MiB, so a large file or a masked
 * text grown past that is a real case) is replaced by the withheld marker. If
 * even that write fails this throws, and `tool.call` withholds the result.
 */
async function maskPersisted($: EngineInterface, result: unknown) {
  if (typeof result !== 'object' || result === null) return
  const r = result as Record<string, unknown>
  for (const key of ['persistedOutputPath', 'rawOutputPath']) {
    const path = r[key]
    if (typeof path !== 'string') continue
    const real = await sessionToolResult($, path)
    if (real === undefined) {
      log($, 'refused to rewrite a saved tool output outside this session\'s tool-results folder; it may hold secrets')
      continue
    }
    try {
      const text = await $.fs.read(real)
      // A safe state on disk before any unbounded work (R4-1): if the hooks
      // worker is lost while masking, the file holds the marker, not the raw
      // text. A rejected marker write lands in the catch and is tried again.
      await $.fs.write(real, WITHHELD)
      const out = maskText(text, ctx.vault, ctx.rules, mint)
      await $.fs.write(real, out.count === 0 ? text : out.text)
      tally(out)
    } catch (err) {
      log($, `could not mask a saved tool output (${err instanceof Error ? err.name : 'error'}); replacing it with the withheld marker`)
      // A rejection here propagates: the caller withholds the whole result.
      await $.fs.write(real, WITHHELD)
    }
  }
}

/** The resolved path of a file in this session's tool-results folder, or undefined. */
async function sessionToolResult($: EngineInterface, path: string): Promise<string | undefined> {
  const configured = await $.env.get('CLAUDE_CONFIG_DIR')
  const home = await $.env.get('HOME')
  const config = configured ?? (home === undefined ? undefined : `${home}/.claude`)
  if (config === undefined) return undefined
  const root = await $.fs.stat(`${config.replace(/\/+$/, '')}/projects`, { resolve: true }).catch(() => undefined)
  const file = await $.fs.stat(path, { resolve: true }).catch(() => undefined)
  if (root?.realPath === undefined || file?.realPath === undefined || file.kind !== 'file') return undefined
  const sessionId = await $.session.id()
  return isSessionToolResult(file.realPath, root.realPath, sessionId) ? file.realPath : undefined
}

/** Why a mentioned file must be refused, or undefined to let it through. */
async function mentionVerdict($: EngineInterface, path: string): Promise<'secret' | 'unreadable' | 'too-large' | undefined> {
  let stat: Awaited<ReturnType<EngineInterface['fs']['stat']>>
  try {
    stat = await $.fs.stat(path)
  } catch (err) {
    // Only a path positively reported missing has nothing to attach.
    return isMissingPathError(err) ? undefined : 'unreadable'
  }
  if (stat.kind !== 'file') return undefined // nothing to attach
  if (stat.size > MAX_MENTION_BYTES) return 'too-large'
  let text: string
  try {
    text = await $.fs.read(path)
  } catch {
    return 'unreadable'
  }
  return holdsKnownValue(text, ctx.vault) || findSecrets(text, ctx.rules).length > 0 ? 'secret' : undefined
}

/** Best effort: tell the person on screen and in the log. Never pass a value here. */
function note($: EngineInterface, text: string) {
  // The engine prefixes toasts and log lines with the plugin name already.
  const bare = text.replace(/^secret-mask: /, '')
  log($, bare)
  try {
    $.ui.toast(bare)
  } catch {
    // nothing to do
  }
}

function maskString(text: string): string {
  const out = maskText(text, ctx.vault, ctx.rules, mint)
  tally(out)
  return out.text
}

export const register: Register = (on, options) => {
  ctx = fresh(configFrom(options))

  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: NAME,
      description: 'Show or set secret masking for this session, or run its self-test',
      argumentHint: '[on|off|status|test]',
    })
    await loadEnv($)
    await loadPatterns($)
    return next(e)
  })

  on('command.run', { command: NAME }, async ($, e) => {
    const cmd = parseArgs(e.args)
    if (cmd.kind === 'help') return { text: cmd.error ? `${cmd.error}\n${USAGE}` : USAGE }
    if (cmd.kind === 'test') {
      const out = selfTest(ctx.rules, ctx.config)
      const refused = ctx.stats.patterns.errors.length > 0
      const text = refused ? out.text.replace(/^Self-test passed/, 'Self-test FAILED (the patterns file has refused entries)') : out.text
      return { text: `${text}\n${patternsLine(ctx.stats.patterns)}` }
    }
    if (cmd.kind === 'set') await update($, sessionAtom, s => ({ ...s, mode: cmd.mode }))
    return { text: statusText(ctx.config, await read($, sessionAtom), ctx.stats) }
  })

  // The backstop: every row the conversation keeps, main and subagents, every
  // door. What the model reads and what the transcript file stores.
  on('session.append', async ($, e, next) => {
    if (!(await active($))) return next(e)
    const out = maskBlocks(e.message.content, ctx.vault, ctx.rules, mint)
    tally(out)
    return out.count === 0 ? next(e) : next({ ...e, message: { ...e.message, content: out.content } })
  }).catch(($, e, next) =>
    // Fail closed: a row we could not mask is stored with its text withheld.
    next.called ? next(e) : next({ ...e, message: { ...e.message, content: withheld(e.message.content) } }),
  )

  // The prompt as submitted, so the queue record matches the masked row. The
  // engine applies no text rewrite to a slash command or a turn-starting meta
  // prompt; their rows are masked at session.append.
  on('prompt.submit', async ($, e, next) => {
    if (e.command !== undefined || (e.isMeta && e.turnId === undefined)) return next(e)
    if (!(await active($))) return next(e)
    const text = maskString(e.text)
    const context = e.context?.map(maskString)
    return next({ ...e, text, ...(context ? { context } : {}) })
  }).catch(() => ({ drop: 'secret-mask could not mask this prompt, so it was not sent.' }))

  on('tool.call', async ($, e, next) => {
    let input = e
    let restored = 0
    const fields = restoreFieldsFor(String(e.tool), ctx.config)
    if (fields === 'all' || fields.length > 0) {
      const r = restoreFields(e, fields, ctx.vault)
      if (r.unknown.length > 0) {
        ctx.stats.denied++
        return { deny: unknownReason(r.unknown) }
      }
      input = r.input
      restored = r.count
      ctx.stats.restored += restored
    }
    const res = await next(input)
    // A result we put a secret into is masked even while masking is off.
    if (res.deny !== undefined) return res
    if (restored === 0 && !(await active($))) return res
    try {
      if (res.isError === true) {
        // An error's record is stored as made, so withhold it: the model reads
        // the masked text as the refusal and the record holds no secret.
        const text = typeof res.text === 'string' ? res.text : typeof res.result === 'string' ? res.result : ''
        const raw = typeof res.result === 'string' ? res.result : ''
        const masked = maskText(text, ctx.vault, ctx.rules, mint)
        const inRecord = raw === text ? masked : maskText(raw, ctx.vault, ctx.rules, mint)
        tally(masked)
        return masked.count + inRecord.count === 0 ? res : { deny: masked.text }
      }
      await maskPersisted($, res.result)
      const m = maskDeep(res.result, ctx.vault, ctx.rules, mint)
      tally(m)
      if (m.count === 0) return res
      // Our own result: core maps it for the model and records it as the
      // tool's result, so the screen and the transcript get the masked form.
      return { result: m.value as typeof res.result, ...(res.context ? { context: res.context } : {}) }
    } catch {
      // Masking failed: withhold the whole result (model copy and record).
      return { deny: WITHHELD }
    }
  }).catch(($, e, next) =>
    // Never replay what ran beneath: its result may hold the secret.
    next.called ? { deny: WITHHELD } : { deny: 'secret-mask: restoring this call failed, so it did not run.' },
  )

  on('session.send', async ($, e, next) => {
    if (!(await active($))) return next(e)
    return next({ ...e, text: maskString(e.text) })
  }).catch(($, e, next) => (next.called ? next(e) : { isDelivered: false, reason: 'secret-mask could not mask this message' }))

  // An @-mention's raw text is kept on disk by the engine whatever a hook
  // does to what the model reads, so refuse one that holds a secret, before
  // it is read. Media is not scanned; a text file that can't be checked is
  // refused (fail closed).
  on('prompt.mention', async ($, e, next) => {
    if (!ctx.config.refuseSecretMentions || isMediaPath(e.path) || !(await active($))) return next(e)
    const why = await mentionVerdict($, e.path)
    if (why === undefined) return next(e)
    const reason = mentionReason(e.mention, why)
    note($, reason)
    return { deny: reason }
  }).catch(($, e, next) => (next.called ? next(e) : { deny: mentionReason(e.mention, 'unreadable') }))

  // What the model reads for an injected attachment: a mentioned @file, a
  // reminder, a settings hook's context. The transcript keeps the engine's
  // own record of the attachment (its payload and rendering) as made.
  on('prompt.attachment', async ($, e, next) => {
    const r = await next(e)
    if (r.text === null || !(await active($))) return r
    const out = maskText(r.text, ctx.vault, ctx.rules, mint)
    if (out.count === 0) return r
    tally(out)
    return { ...r, text: out.text }
  }).catch(() => ({ text: WITHHELD }))

  on('prompt.context', async ($, e, next) => {
    const r = await next(e)
    if (!(await active($))) return r
    let changed = false
    const blocks = r.blocks.map(b => {
      const out = maskText(b.text, ctx.vault, ctx.rules, mint)
      if (out.count === 0) return b
      tally(out)
      changed = true
      return { ...b, text: out.text }
    })
    return changed ? { ...r, blocks } : r
  }).catch(($, e) => ({ blocks: e.blocks.map(b => ({ ...b, text: WITHHELD })) }))
}
