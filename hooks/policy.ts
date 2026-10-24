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
    refuseSecretMentions: options.refuseSecretMentions !== false,
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

/**
 * Whether a resolved path is a file directly in this session's tool-results
 * folder: `<projects root>/<project dir>/<session id>/tool-results/<file>`.
 * Both paths must already be resolved (`$.fs.stat(path, { resolve: true })`).
 */
export function isSessionToolResult(realPath: string, realProjectsRoot: string, sessionId: string): boolean {
  const root = realProjectsRoot.replace(/\/+$/, '')
  if (root === '' || !realPath.startsWith(`${root}/`)) return false
  const rest = realPath.slice(root.length + 1).split('/')
  return (
    rest.length === 4 &&
    rest.every(p => p !== '' && p !== '.' && p !== '..') &&
    rest[1] === sessionId &&
    rest[2] === 'tool-results'
  )
}

/** Files an @-mention attaches as media, which this mod does not scan. */
export function isMediaPath(path: string): boolean {
  return /\.(?:png|jpe?g|gif|webp|bmp|tiff?|heic|ico|pdf)$/i.test(path)
}

/** The largest file an @-mention check reads; a bigger one is refused. */
export const MAX_MENTION_BYTES = 5 * 1024 * 1024

/**
 * Whether a `$.fs.stat` rejection means the path is missing, and nothing
 * else. Checked live on 2.1.310: the engine rejects with a `HooksError`
 * whose message ends in the errno (`<plugin>: $.fs.stat(<path>) failed:
 * ENOENT`, `... failed: EACCES`), with no `code`. Any other failure (access,
 * I/O, not a directory) is not proof the file is absent.
 */
export function isMissingPathError(err: unknown): boolean {
  return err instanceof Error && err.name === 'HooksError' && /: ENOENT$/.test(err.message)
}

/** Why an @-mention was refused. Names the mention as typed, never a value. */
export function mentionReason(mention: string, why: 'secret' | 'unreadable' | 'too-large'): string {
  const what =
    why === 'secret'
      ? 'holds what looks like a secret'
      : why === 'unreadable'
        ? 'could not be checked for secrets'
        : `is larger than ${MAX_MENTION_BYTES / 1024 / 1024} MB, too large to check for secrets`
  return (
    `secret-mask: @${mention} was not attached because it ${what}. ` +
    "Claude Code keeps an @-mentioned file's raw text on disk. Have it read with the Read tool or cat instead: tool output is masked."
  )
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
  /** Exact values (`secrets`) loaded. */
  values: number
  errors: string[]
}

/** The environment read at load: how many values it gave, or why it could not be read. Never a value. */
export type EnvStatus = { count: number; error: string | null }

/** Counts since the module loaded. Kinds and numbers only. */
export type Stats = {
  /** Distinct secrets masked, by kind. */
  secrets: Record<string, number>
  masked: number
  restored: number
  denied: number
  patterns: PatternsStatus
  env: EnvStatus
}

export function patternsLine(p: PatternsStatus): string {
  if (p.state === 'none') return `Patterns file: no patterns file at ${p.path}${p.errors.length ? ` (${p.errors.join('; ')})` : ''}.`
  const head = `Patterns file: ${p.path}, ${p.count} pattern${p.count === 1 ? '' : 's'} loaded`
  return p.errors.length === 0 ? `${head}.` : `${head}; refused: ${p.errors.join('; ')}.`
}

export function knownLine(env: EnvStatus, patterns: PatternsStatus): string {
  const fromEnv =
    env.error === null
      ? `${env.count} from the environment`
      : env.count > 0
        ? `${env.count} from the environment (${env.error})`
        : `could not read the environment (${env.error}), so none from it`
  return `Known values: ${fromEnv}, ${patterns.values} from the patterns file.`
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
    knownLine(stats.env, stats.patterns),
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
