// Pure decisions and text: no `$`, no I/O. Config, the per-tool restore
// policy, the command parser, status and the self-test.
import { CANARIES, NEAR_MISSES } from './canaries'
import { findSecrets } from './detect'
import type { Rules } from './detect'
import { maskBlocks, maskDeep, maskText, newVault, restoreFields } from './vault'
import type { Config, Mode, Session } from '../types'

export const INITIAL: Session = { mode: null }

export const DEFAULT_PATTERNS_FILE = '~/.config/secret-mask/patterns.json'

export function configFrom(options: Record<string, unknown>): Config {
  const file = options.patternsFile
  return {
    enabled: options.enabled !== false,
    restoreIntoFiles: options.restoreIntoFiles === true,
    restoreInMcp: options.restoreInMcp === true,
    patternsFile: typeof file === 'string' && file.trim() !== '' ? file.trim() : DEFAULT_PATTERNS_FILE,
  }
}

export function isActive(config: Config, session: Session): boolean {
  return session.mode === null ? config.enabled : session.mode === 'on'
}

/**
 * Which fields of a tool call's input get placeholders restored: named
 * top-level fields, `'all'` string values (MCP), or none.
 */
export function restoreFieldsFor(tool: string, config: Config): readonly string[] | 'all' {
  switch (tool) {
    case 'Bash':
    case 'PowerShell':
    case 'Monitor':
      return ['command']
    case 'Write':
      return config.restoreIntoFiles ? ['content'] : []
    case 'Edit':
      return config.restoreIntoFiles ? ['old_string', 'new_string'] : []
    case 'NotebookEdit':
      return config.restoreIntoFiles ? ['new_source'] : []
  }
  if (tool.startsWith('mcp__')) return config.restoreInMcp ? 'all' : []
  return []
}

/** The deny reason for placeholders the mapping doesn't hold. Placeholders only, never values. */
export function unknownReason(tokens: readonly string[]): string {
  return (
    `secret-mask: ${tokens.join(', ')} ${tokens.length === 1 ? 'is' : 'are'} not in the current mapping ` +
    '(it was dropped by a reload or restart, or the placeholder was never issued). ' +
    'The call did not run. Read the secret again to get a new placeholder.'
  )
}

/** A file core saved a large tool output to: `<config>/projects/<dir>/<session>/tool-results/<file>`. */
export function isToolResultsFile(path: string): boolean {
  return !path.split('/').includes('..') && /\/projects\/[^/]+\/[^/]+\/tool-results\/[^/]+$/.test(path)
}

export function expandHome(path: string, home: string | undefined): string | undefined {
  if (path === '~' || path.startsWith('~/')) return home === undefined ? undefined : home + path.slice(1)
  return path
}

export type Command = { kind: 'set'; mode: Mode } | { kind: 'status' } | { kind: 'test' } | { kind: 'help'; error?: string }

export function parseArgs(args: string): Command {
  const word = args.trim().toLowerCase()
  if (word === '' || word === 'status') return { kind: 'status' }
  if (word === 'on' || word === 'off') return { kind: 'set', mode: word }
  if (word === 'test') return { kind: 'test' }
  if (word === 'help') return { kind: 'help' }
  return { kind: 'help', error: `Unknown argument: ${args.trim()}` }
}

export const USAGE = 'Usage: /secret-mask [on|off|status|test]'

export type PatternsStatus = {
  path: string
  /** `none`: no file (or unreadable, said in errors); `loaded`; `error`: read, with entries refused. */
  state: 'none' | 'loaded' | 'error'
  count: number
  errors: string[]
}

/** Counts since the module loaded. Kinds and numbers only. */
export type Stats = {
  /** Distinct secrets masked, by kind. */
  secrets: Record<string, number>
  masked: number
  restored: number
  denied: number
  patterns: PatternsStatus
}

export function patternsLine(p: PatternsStatus): string {
  if (p.state === 'none') return `Patterns file: no patterns file at ${p.path}${p.errors.length ? ` (${p.errors.join('; ')})` : ''}.`
  const head = `Patterns file: ${p.path}, ${p.count} pattern${p.count === 1 ? '' : 's'} loaded`
  return p.errors.length === 0 ? `${head}.` : `${head}; refused: ${p.errors.join('; ')}.`
}

export function statusText(config: Config, session: Session, stats: Stats): string {
  const state = isActive(config, session) ? 'on' : 'off'
  const source = session.mode === null ? 'from the enabled option' : 'set for this session'
  const kinds = Object.entries(stats.secrets)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, n]) => `${k} ${n}`)
  return [
    `Masking ${state} (${source}).${state === 'off' ? ' Placeholders already issued are still restored.' : ''}`,
    `Since load: ${stats.masked} masked, ${stats.restored} restored, ${stats.denied} denied.`,
    `Distinct secrets: ${kinds.length === 0 ? 'none' : kinds.join(', ')}.`,
    `Restored into: Bash/PowerShell/Monitor command${config.restoreIntoFiles ? ', file content' : ''}${config.restoreInMcp ? ', MCP arguments' : ''}.`,
    patternsLine(stats.patterns),
  ].join('\n')
}

/**
 * Runs the canaries through the same masking and restoring code the hooks
 * use, on a scratch vault. Reports kinds and outcomes; never a canary's value.
 */
export function selfTest(rules: Rules, config: Config): { isPassing: boolean; text: string } {
  const vault = newVault()
  let n = 0
  const mint = () => (++n).toString(16).toUpperCase().padStart(8, '0')
  const lines: string[] = []
  let misses = 0

  for (const c of CANARIES) {
    // A fresh vault per canary: several share a value, and a value the vault
    // already holds keeps its first kind.
    maskText(c.line, vault, rules, mint)
    const out = maskText(c.line, newVault(), rules, mint)
    const ok = !out.text.includes(c.value) && out.text.includes(`__SECRET_${c.kind}_`)
    if (!ok) misses++
    lines.push(`  ${ok ? 'ok  ' : 'MISS'} ${c.kind}${ok ? '' : ' NOT masked'}`)
  }

  const row = maskBlocks(
    [{ type: 'tool_result', tool_use_id: 'self-test', content: [{ type: 'text', text: CANARIES.map(c => c.line).join('\n') }] }],
    newVault(),
    rules,
    mint,
  )
  const rowText = JSON.stringify(row.content)
  const rowOk = CANARIES.every(c => !rowText.includes(c.value))

  const key = CANARIES[0]!
  const token = vault.byValue.get(key.value)
  let tripOk = false
  if (token !== undefined) {
    const restored = restoreFields({ tool: 'Bash', command: `echo ${token}` }, restoreFieldsFor('Bash', config), vault)
    const echoed = maskDeep({ stdout: restored.input.command.replace(/^echo /, '') }, vault, rules, mint)
    tripOk =
      restored.input.command === `echo ${key.value}` && JSON.stringify(echoed.value) === JSON.stringify({ stdout: token })
  }
  const unknown = restoreFields({ tool: 'Bash', command: 'echo __SECRET_AWS_KEY_ID_DEADBEEF__' }, ['command'], vault).unknown
  const unknownOk = unknown.length === 1

  const nearHits = NEAR_MISSES.filter(t => findSecrets(t, rules).length > 0).length
  const isPassing = misses === 0 && rowOk && tripOk && unknownOk && nearHits === 0

  const head =
    misses === 0 ? `all canaries masked (${CANARIES.length})` : `${misses} of ${CANARIES.length} canaries NOT masked`
  return {
    isPassing,
    text: [
      `Self-test ${isPassing ? 'passed' : 'FAILED'}: ${head}.`,
      ...lines,
      `  ${rowOk ? 'ok  ' : 'FAIL'} tool-result row masked`,
      `  ${tripOk ? 'ok  ' : 'FAIL'} round trip: placeholder restored into a Bash command, echoed output masked again`,
      `  ${unknownOk ? 'ok  ' : 'FAIL'} unknown placeholder refused`,
      `  ${nearHits === 0 ? 'ok  ' : 'FAIL'} near misses left alone (${NEAR_MISSES.length - nearHits} of ${NEAR_MISSES.length})`,
    ].join('\n'),
  }
}

export const WITHHELD = '[secret-mask: text withheld because masking failed]'

/** A row's writable text replaced by a fixed marker: the fail-closed answer when masking throws. */
export function withheld<B extends { type: string }>(content: readonly B[]): B[] {
  return content.map(b => {
    if (b.type === 'text') return { ...b, text: WITHHELD }
    if (b.type === 'tool_result') return { ...b, content: WITHHELD }
    return b
  })
}
