import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import { builtinRules, parsePatternsFile, withUserRules } from './detect'
import type { Rules } from './detect'
import {
  INITIAL,
  USAGE,
  configFrom,
  expandHome,
  isActive,
  parseArgs,
  patternsLine,
  restoreFieldsFor,
  selfTest,
  statusText,
  unknownReason,
  withheld,
} from './policy'
import type { Stats } from './policy'
import { maskBlocks, maskDeep, maskText, newVault, restoreFields } from './vault'
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
type Ctx = { config: Config; vault: Vault; rules: Rules; stats: Stats }

let ctx: Ctx = fresh(configFrom({}))

function fresh(config: Config): Ctx {
  return {
    config,
    vault: newVault(),
    rules: builtinRules(),
    stats: {
      secrets: {},
      masked: 0,
      restored: 0,
      denied: 0,
      patterns: { path: config.patternsFile, state: 'none', count: 0, errors: [] },
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

async function loadPatterns($: EngineInterface) {
  const path = expandHome(ctx.config.patternsFile, await $.env.get('HOME'))
  const status = ctx.stats.patterns
  status.path = path ?? ctx.config.patternsFile
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
  ctx.rules = withUserRules(builtinRules(), parsed)
  status.state = parsed.errors.length === 0 ? 'loaded' : 'error'
  status.count = parsed.patterns.length
  status.errors = parsed.errors
  if (parsed.errors.length > 0) log($, patternsLine(status))
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
    await loadPatterns($)
    return next(e)
  })

  on('command.run', { command: NAME }, async ($, e) => {
    const cmd = parseArgs(e.args)
    if (cmd.kind === 'help') return { text: cmd.error ? `${cmd.error}\n${USAGE}` : USAGE }
    if (cmd.kind === 'test') {
      const out = selfTest(ctx.rules, ctx.config)
      return { text: `${out.text}\n${patternsLine(ctx.stats.patterns)}` }
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
  }).catch(($, e, next) => next(e)) // fail open: session.append masks the row either way

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
    if (res.deny !== undefined || res.isError === true) return res
    if (restored === 0 && !(await active($))) return res
    const m = maskDeep(res.result, ctx.vault, ctx.rules, mint)
    tally(m)
    if (m.count === 0) return res
    // Our own result: core maps it for the model and records it as the
    // tool's result, so the screen and the transcript get the masked form.
    return { result: m.value as typeof res.result, ...(res.context ? { context: res.context } : {}) }
  }).catch(($, e, next) => (next.called ? next(e) : { deny: 'secret-mask: restoring this call failed, so it did not run.' }))

  on('session.send', async ($, e, next) => {
    if (!(await active($))) return next(e)
    return next({ ...e, text: maskString(e.text) })
  }).catch(($, e, next) => (next.called ? next(e) : { isDelivered: false, reason: 'secret-mask could not mask this message' }))

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
  })
}
