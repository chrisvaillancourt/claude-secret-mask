import { describe, expect, mock, test } from 'claude-code/testing'
import type { On } from 'claude-code'

import { CANARIES } from './canaries'
import { WITHHELD } from './policy'

const COMMAND = { origin: { kind: 'composer' as const }, presentation: { isFullscreen: false, columns: 120 } }
const KEY = 'AKIAFAKEFAKEFAKE0000'
const PH = /__SECRET_AWS_KEY_ID_[0-9A-F]{8}__/

/** The engine beneath the plugin. `ran` records each tool input that reached core. */
const SID = '0f0f0f0f-0000-4000-8000-000000000000'
const PERSISTED = `/home/t/.claude/projects/-x/${SID}/tool-results/b1.txt`

const world = (on: On, files: Record<string, string> = {}) => {
  const written: Record<string, string> = {}
  /** Symbolic links: a path and where it lands. */
  const links: Record<string, string> = {}
  on('session.id', () => ({ value: SID }))
  on('fs.stat', ($, e) => {
    const real = links[e.path] ?? e.path
    const isDir = real === '/home/t/.claude/projects'
    if (!isDir && files[real] === undefined) return { deny: `ENOENT: no such file, stat '${e.path}'` }
    return { value: { kind: isDir ? 'dir' : 'file', size: 1, mtimeMs: 0, isLink: e.path in links, ...(e.resolve ? { realPath: real } : {}) } }
  })
  /** Writes refused outright, and the longest text a write takes (the engine's is 4 MiB). */
  const unwritable = new Set<string>()
  let writeLimit = Infinity
  on('fs.write', ($, e) => {
    if (unwritable.has(e.path)) return { deny: `EACCES: permission denied, open '${e.path}'` }
    if (e.text.length > writeLimit) return { deny: 'refused: the text is over the 4194304-byte limit' }
    written[e.path] = e.text
    files[e.path] = e.text
    return { value: undefined }
  })
  on('session.start', ($, e) => ({ cwd: e.cwd }))
  on('command.register', ($, e) => ({ value: { command: e.name } }))
  const unreadable = new Set<string>()
  /** Files the engine refuses to read for size. */
  const oversize = new Set<string>()
  on('fs.read', ($, e) => {
    if (unreadable.has(e.path)) return { deny: `EACCES: permission denied, open '${e.path}'` }
    if (oversize.has(e.path)) return { deny: 'refused: the file is over the 4194304-byte limit' }
    const text = files[links[e.path] ?? e.path]
    return text === undefined ? { deny: `ENOENT: no such file, open '${e.path}'` } : { value: text }
  })
  mock.env(on, { HOME: '/home/t' })
  const session = mock.session(on)
  const ran: Record<string, unknown>[] = []
  let errorNext = false
  let persistNext: string | null = null
  on('tool.call', ($, e) => {
    ran.push({ ...e })
    const echoed = typeof (e as any).command === 'string' ? `ran: ${(e as any).command}` : 'ok'
    if (errorNext) {
      errorNext = false
      return { result: `Error: ${echoed}`, text: echoed, isError: true as const, ref: 2 }
    }
    if (persistNext !== null) {
      const path = persistNext
      persistNext = null
      files[links[path] ?? path] = `lots of output\n${echoed}\n`
      return { result: { stdout: 'lots of output', stderr: '', interrupted: false, persistedOutputPath: path }, text: 'lots', ref: 3 }
    }
    return { result: { stdout: echoed, stderr: '', interrupted: false }, text: echoed, ref: 1 }
  })
  on('session.send', ($, e) => ({ isDelivered: true as const, text: e.text }) as any)
  on('prompt.submit', ($, e) => ({ text: e.text }))
  on('prompt.context', ($, e) => ({ blocks: e.blocks }))
  on('prompt.attachment', ($, e) => ({ text: e.text }))
  const mentioned: string[] = []
  on('prompt.mention', ($, e) => {
    mentioned.push(e.path)
    return { type: 'file' as const }
  })
  return {
    unreadable,
    oversize,
    unwritable,
    limitWrites: (n: number) => (writeLimit = n),
    mentioned, session, ran, written, errorNext: () => (errorNext = true), persistNext: (path = PERSISTED) => (persistNext = path), links, files }
}

const start = ($: any) => $.session.start({ cwd: '/x', surface: 'terminal', isInteractive: true })

let uuid = 0
const append = ($: any, content: unknown[], door = 'tool-result', extra: Record<string, unknown> = {}) =>
  $.session.append({
    message: { type: 'user', role: 'user', content },
    door,
    origin: door === 'tool-result' ? { kind: 'tool', tool: 'Bash' } : { kind: 'engine' },
    uuid: `u${++uuid}`,
    ...extra,
  })

const stored = (w: ReturnType<typeof world>) => JSON.stringify(w.session.appended().map(r => r.message.content))

/** Masks the fake AWS key through a tool-result row and answers its placeholder. */
const learn = async ($: any, w: ReturnType<typeof world>) => {
  await append($, [{ type: 'tool_result', tool_use_id: 'tu0', content: `id=${KEY}` }])
  const ph = stored(w).match(PH)?.[0]
  expect(ph).toBeDefined()
  return ph!
}

const run = ($: any, args: string) => $.command.run({ command: 'secret-mask', args, ...COMMAND })

describe('masking rows', () => {
  test('a tool result row is stored masked, and the same secret keeps its placeholder', async ($, on) => {
    const w = world(on)
    await start($)
    await append($, [{ type: 'tool_result', tool_use_id: 'tu1', content: `a ${KEY}` }])
    await append($, [{ type: 'tool_result', tool_use_id: 'tu2', content: `b ${KEY}` }])
    const rows = stored(w)
    expect(rows.includes(KEY)).toBe(false)
    const tokens = rows.match(new RegExp(PH.source, 'g'))!
    expect(tokens.length).toBe(2)
    expect(tokens[0]).toBe(tokens[1])
  })

  test('every canary through every door, main and subagent, is stored masked', async ($, on) => {
    const w = world(on)
    await start($)
    const text = CANARIES.map(c => c.line).join('\n')
    for (const door of ['prompt', 'delivery', 'hook-context', 'attachment', 'compaction', 'tool-message']) {
      await append($, [{ type: 'text', text }], door)
    }
    await append($, [{ type: 'tool_result', tool_use_id: 'tu1', content: [{ type: 'text', text }] }], 'tool-result', {
      agentId: 'a1',
    })
    const rows = stored(w)
    for (const c of CANARIES) expect(rows.includes(c.value)).toBe(false)
  })

  test('a placeholder echoed back by the model is stored unchanged', async ($, on) => {
    const w = world(on)
    await start($)
    const ph = await learn($, w)
    await $.session.append({
      message: { type: 'assistant', role: 'assistant', content: [{ type: 'text', text: `I saw ${ph}.` }] },
      door: 'response',
      origin: { kind: 'model', model: 'claude-haiku-5-5' },
      uuid: 'resp1',
    })
    expect(w.session.appended().at(-1)!.message.content).toEqual([{ type: 'text', text: `I saw ${ph}.` }])
  })

  test('/secret-mask off stops masking new rows', async ($, on) => {
    const w = world(on)
    await start($)
    expect((await run($, 'off')).text).toContain('off (set for this session)')
    await append($, [{ type: 'text', text: KEY }], 'prompt')
    expect(stored(w).includes(KEY)).toBe(true)
  })

  test('the prompt as submitted is masked; a slash command line is left to the engine', async ($, on) => {
    world(on)
    await start($)
    const sent: any = await $.prompt.submit({ text: `use ${KEY}`, wait: false, origin: { kind: 'composer' } })
    expect(sent.text).toMatch(PH)
    expect(sent.text.includes(KEY)).toBe(false)
    const cmd: any = await $.prompt.submit({
      text: `/deploy ${KEY}`,
      command: { name: 'deploy', args: KEY },
      wait: false,
      origin: { kind: 'composer' },
    })
    expect(cmd.text).toBe(`/deploy ${KEY}`)
  })

  test('a message to another agent or session is masked', async ($, on) => {
    world(on)
    await start($)
    const sent: any = await $.session.send({ to: 'peer', text: `key ${KEY}`, origin: { kind: 'model' } })
    expect(sent.text.includes(KEY)).toBe(false)
    expect(sent.text).toMatch(PH)
  })

  test('context blocks are masked only where a secret is found', async ($, on) => {
    world(on)
    await start($)
    const out = await $.prompt.context({
      blocks: [
        { name: 'claudeMd', text: `deploy with ${KEY}` },
        { name: 'currentDate', text: 'today' },
      ],
    })
    expect(out.blocks[0]!.text.includes(KEY)).toBe(false)
    expect(out.blocks[1]).toEqual({ name: 'currentDate', text: 'today' })
  })
})

test('a mentioned file\'s attachment text is masked for the model, main and subagent', async ($, on) => {
  world(on)
  await start($)
  const main: any = await $.prompt.attachment({ type: 'file', text: `creds.txt:\naws_access_key_id = ${KEY}`, origin: { kind: 'engine' } } as any)
  expect(main.text.includes(KEY)).toBe(false)
  expect(main.text).toMatch(PH)
  const sub: any = await $.prompt.attachment({ type: 'file', text: `again ${KEY}`, origin: { kind: 'engine' }, agentId: 'a1' } as any)
  expect(sub.text.includes(KEY)).toBe(false)
  const none: any = await $.prompt.attachment({ type: 'todo_reminder', text: 'nothing here', origin: { kind: 'engine' } } as any)
  expect(none.text).toBe('nothing here')
})

describe('@-mentions', () => {
  const mention = ($: any, path: string) => $.prompt.mention({ mention: path.split('/').at(-1), path })

  test('a mentioned file holding a secret is refused before it is read, with no value in the reason', async ($, on) => {
    const w = world(on, { '/x/creds.txt': `aws_access_key_id = ${KEY}\n` })
    await start($)
    const r: any = await mention($, '/x/creds.txt')
    expect(w.mentioned).toEqual([])
    expect(r.deny).toContain('Read')
    expect(r.deny.includes(KEY)).toBe(false)
  })

  test('a file with no secret, a media file, and a missing file go through', async ($, on) => {
    const w = world(on, { '/x/notes.txt': 'nothing here\n' })
    await start($)
    await mention($, '/x/notes.txt')
    await mention($, '/x/pic.png')
    await mention($, '/x/missing.txt')
    expect(w.mentioned).toEqual(['/x/notes.txt', '/x/pic.png', '/x/missing.txt'])
  })

  test('a text file that exists but cannot be read is refused', async ($, on) => {
    const w = world(on, { '/x/locked.txt': 'x' })
    w.unreadable.add('/x/locked.txt')
    await start($)
    const r: any = await mention($, '/x/locked.txt')
    expect(w.mentioned).toEqual([])
    expect(r.deny).toContain('could not be checked')
  })

  test('refuseSecretMentions off, or masking off, lets it through', { options: { refuseSecretMentions: false } }, async ($, on) => {
    const w = world(on, { '/x/creds.txt': KEY })
    await start($)
    await mention($, '/x/creds.txt')
    expect(w.mentioned).toEqual(['/x/creds.txt'])
  })

  test('masking off lets a secret-bearing mention through', async ($, on) => {
    const w = world(on, { '/x/creds.txt': KEY })
    await start($)
    await run($, 'off')
    await mention($, '/x/creds.txt')
    expect(w.mentioned).toEqual(['/x/creds.txt'])
  })
})

describe('restoring tool input', () => {
  test('Bash gets the real value, and its result is masked again', async ($, on) => {
    const w = world(on)
    await start($)
    const ph = await learn($, w)
    const r: any = await $.tool.call({ tool: 'Bash', command: `echo ${ph}` })
    expect(w.ran.at(-1)!.command).toBe(`echo ${KEY}`)
    expect(JSON.stringify(r).includes(KEY)).toBe(false)
    expect(r.result.stdout).toBe(`ran: echo ${ph}`)
    expect(r.ref).toBeUndefined()
  })

  test('an errored result that echoes a secret is withheld with its masked text', async ($, on) => {
    const w = world(on)
    await start($)
    w.errorNext()
    const r: any = await $.tool.call({ tool: 'Bash', command: `cat creds; echo ${KEY}; exit 3` })
    expect(JSON.stringify(r).includes(KEY)).toBe(false)
    expect(r.deny ?? r.text).toMatch(PH)
  })

  test('a large output saved to a tool-results file is masked in that file', async ($, on) => {
    const w = world(on)
    await start($)
    w.persistNext()
    await $.tool.call({ tool: 'Bash', command: `echo ${KEY}` })
    expect(w.written[PERSISTED]).toBeDefined()
    expect(w.written[PERSISTED]!.includes(KEY)).toBe(false)
    expect(w.written[PERSISTED]).toMatch(PH)
  })

  test('a saved output too large to read is replaced by the withheld marker', async ($, on) => {
    const w = world(on)
    await start($)
    w.oversize.add(PERSISTED)
    w.persistNext()
    const r: any = await $.tool.call({ tool: 'Bash', command: `echo ${KEY}` })
    expect(w.files[PERSISTED]).toBe(WITHHELD)
    expect(JSON.stringify(r).includes(KEY)).toBe(false)
  })

  test('a saved output whose masked text is too large to write is replaced by the withheld marker', async ($, on) => {
    const w = world(on)
    await start($)
    // Core wrote the raw file; the masked text (a placeholder is longer than the key) is over the
    // limit, the marker under it.
    const raw = `lots of output\nran: echo ${KEY} ${KEY}\n`
    expect(raw.length > WITHHELD.length).toBe(true)
    w.limitWrites(raw.length)
    w.persistNext()
    const r: any = await $.tool.call({ tool: 'Bash', command: `echo ${KEY} ${KEY}` })
    expect(w.files[PERSISTED]).toBe(WITHHELD)
    expect(r.deny).toBeUndefined()
    expect(JSON.stringify(r).includes(KEY)).toBe(false)
  })

  test('when even the marker cannot be written, the whole result is withheld', async ($, on) => {
    const w = world(on)
    await start($)
    w.oversize.add(PERSISTED)
    w.unwritable.add(PERSISTED)
    w.persistNext()
    const r: any = await $.tool.call({ tool: 'Bash', command: `echo ${KEY}` })
    expect(r.deny).toBe(WITHHELD)
    expect(r.result).toBeUndefined()
  })

  test('a value found in a result is masked in every copy of the stored record', async ($, on) => {
    world(on)
    await start($)
    const X = 'FAKErepeated0000'
    const r: any = await $.tool.call({ tool: 'Bash', command: `printf 'echoed=${X}\\nOTHER_SECRET=${X}\\n'` })
    expect(JSON.stringify(r.result).includes(X)).toBe(false)
  })

  test('a numeric JSON secret is masked in the structured result, braces kept', async ($, on) => {
    world(on)
    await start($)
    const r: any = await $.tool.call({ tool: 'Bash', command: `printf '{"password":12340000}\\nechoed=12340000'` })
    const out = JSON.stringify(r.result)
    expect(out.includes('12340000')).toBe(false)
    expect(r.result.stdout).toMatch(/\{"password":__SECRET_SECRET_VALUE_[0-9A-F]{8}__\}/)
  })

  test('a saved output outside this session\'s tool-results folder is never rewritten', async ($, on) => {
    const w = world(on)
    await start($)
    // A symbolic link in the right folder that lands elsewhere.
    const link = `/home/t/.claude/projects/-x/${SID}/tool-results/link.txt`
    w.links[link] = '/home/t/creds.env'
    w.persistNext(link)
    await $.tool.call({ tool: 'Bash', command: `echo ${KEY}` })
    // The right suffix under another root, and another session's folder.
    w.persistNext(`/tmp/elsewhere/projects/-x/${SID}/tool-results/b2.txt`)
    await $.tool.call({ tool: 'Bash', command: `echo ${KEY}` })
    w.persistNext('/home/t/.claude/projects/-x/another-session/tool-results/b3.txt')
    await $.tool.call({ tool: 'Bash', command: `echo ${KEY}` })
    expect(Object.keys(w.written)).toEqual([])
  })

  test('copying ordinary metrics JSON through Bash keeps it valid and unchanged', async ($, on) => {
    world(on)
    await start($)
    const json = '{"token_count":12345678,"token_kind":"identifier","password_hint":"ask the administrator","request_id":"00000000-0000-4000-8000-000000000000"}'
    const r: any = await $.tool.call({ tool: 'Bash', command: `printf '%s' '${json}'` })
    expect(r.ref).toBe(1)
    const out = r.result.stdout.replace(/^ran: printf '%s' '/, '').replace(/'$/, '')
    expect(JSON.parse(out)).toEqual(JSON.parse(json))
  })

  test('an older reserved-shape placeholder denies the call', async ($, on) => {
    const w = world(on)
    await start($)
    const r: any = await $.tool.call({ tool: 'Bash', command: 'echo __SECRET_1FAKE_00000001__' })
    expect(w.ran.length).toBe(0)
    expect(r.deny ?? r.text).toContain('not in the current mapping')
  })

  test('when masking throws, nothing is stored raw: result, row and attachment are withheld', async ($, on) => {
    const w = world(on)
    await start($)
    // Past the vault's bound, masking throws.
    const keys = Array.from({ length: 10001 }, (_, i) => `AKIAFAKE${String(i).padStart(12, '0')}`).join(' ')
    const r: any = await $.tool.call({ tool: 'Bash', command: `echo ${keys}` })
    expect(JSON.stringify(r).includes('AKIAFAKE000000000001')).toBe(false)
    await append($, [{ type: 'tool_result', tool_use_id: 'tx', content: keys }])
    expect(stored(w).includes('AKIAFAKE000000000001')).toBe(false)
    const a: any = await $.prompt.attachment({ type: 'file', text: keys, origin: { kind: 'engine' } } as any)
    expect((a.text ?? '').includes('AKIAFAKE000000000001')).toBe(false)
  })

  test('a result with nothing to mask is passed through as core made it', async ($, on) => {
    world(on)
    await start($)
    const r: any = await $.tool.call({ tool: 'Bash', command: 'ls' })
    expect(r.ref).toBe(1)
  })

  test('an unknown placeholder in a restored field denies the call', async ($, on) => {
    const w = world(on)
    await start($)
    const r: any = await $.tool.call({ tool: 'Bash', command: 'echo __SECRET_AWS_KEY_ID_DEADBEEF__' })
    expect(w.ran.length).toBe(0)
    const reason = r.deny ?? r.text
    expect(reason).toContain('__SECRET_AWS_KEY_ID_DEADBEEF__')
    expect(reason).toContain('not in the current mapping')
  })

  test('file content is not restored by default', async ($, on) => {
    const w = world(on)
    await start($)
    const ph = await learn($, w)
    await $.tool.call({ tool: 'Write', file_path: '/x/a.env', content: `KEY=${ph}` })
    expect(w.ran.at(-1)!.content).toBe(`KEY=${ph}`)
  })

  test('file content is restored with restoreIntoFiles', { options: { restoreIntoFiles: true } }, async ($, on) => {
    const w = world(on)
    await start($)
    const ph = await learn($, w)
    await $.tool.call({ tool: 'Edit', file_path: '/x/a.env', old_string: `KEY=${ph}`, new_string: 'KEY=' })
    expect(w.ran.at(-1)!.old_string).toBe(`KEY=${KEY}`)
  })

  test('an Agent prompt and MCP arguments are not restored by default', async ($, on) => {
    const w = world(on)
    await start($)
    const ph = await learn($, w)
    await $.tool.call({ tool: 'Agent', description: 'd', prompt: `use ${ph}` } as any)
    expect(w.ran.at(-1)!.prompt).toBe(`use ${ph}`)
    await $.tool.call({ tool: 'mcp__srv__call', args: { token: ph } } as any)
    expect(JSON.stringify(w.ran.at(-1))).toContain(ph)
  })

  test('MCP arguments are restored with restoreInMcp', { options: { restoreInMcp: true } }, async ($, on) => {
    const w = world(on)
    await start($)
    const ph = await learn($, w)
    await $.tool.call({ tool: 'mcp__srv__call', args: { token: ph } } as any)
    expect(w.ran.at(-1)!.args).toEqual({ token: KEY })
  })

  test('restoring continues while masking is off', async ($, on) => {
    const w = world(on)
    await start($)
    const ph = await learn($, w)
    await run($, 'off')
    await $.tool.call({ tool: 'Bash', command: `echo ${ph}` })
    expect(w.ran.at(-1)!.command).toBe(`echo ${KEY}`)
  })

  test('subagent tool calls are restored too', async ($, on) => {
    const w = world(on)
    await start($)
    const ph = await learn($, w)
    await $.tool.call({ tool: 'Bash', command: `echo ${ph}`, agentId: 'a1' })
    expect(w.ran.at(-1)!.command).toBe(`echo ${KEY}`)
  })
})

describe('command', () => {
  test('status shows kinds and counts, never a value', async ($, on) => {
    const w = world(on)
    await start($)
    await learn($, w)
    const s = (await run($, 'status')).text
    expect(s).toContain('AWS_KEY_ID 1')
    expect(s.includes(KEY)).toBe(false)
    expect(s).toContain('no patterns file')
  })

  test('test runs the canaries and reports them masked', async ($, on) => {
    world(on)
    await start($)
    const s = (await run($, 'test')).text
    expect(s).toContain('all canaries masked')
    for (const c of CANARIES) expect(s.includes(c.value)).toBe(false)
  })

  test('the patterns file adds rules; an invalid one is reported', async ($, on) => {
    const w = world(on, {
      '/home/t/.config/secret-mask/patterns.json': JSON.stringify({
        patterns: [{ name: 'internal', regex: 'itk_[A-Z0-9]{8}' }, { name: 'bad', regex: '(' }],
      }),
    })
    await start($)
    await append($, [{ type: 'text', text: 'itk_FAKE0000' }], 'prompt')
    expect(stored(w)).toMatch(/__SECRET_INTERNAL_[0-9A-F]{8}__/)
    const s = (await run($, 'status')).text
    expect(s).toContain('1 pattern')
    expect(s).toContain('pattern "bad"')
  })

  test('test fails when the patterns file has refused entries', async ($, on) => {
    world(on, {
      '/home/t/.config/secret-mask/patterns.json': JSON.stringify({ patterns: [{ name: '1FAKE', regex: 'FAKECUSTOM[0-9]{8}' }] }),
    })
    await start($)
    const s = (await run($, 'test')).text
    expect(s).toContain('Self-test FAILED')
    expect(s).toContain('1FAKE')
  })

  test('an unknown argument answers with usage', async ($, on) => {
    world(on)
    await start($)
    expect((await run($, 'bogus')).text).toContain('Usage: /secret-mask')
  })
})
