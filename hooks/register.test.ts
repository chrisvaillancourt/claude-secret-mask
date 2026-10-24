import { describe, expect, mock, test } from 'claude-code/testing'
import type { On } from 'claude-code'

import { CANARIES } from './canaries'

const COMMAND = { origin: { kind: 'composer' as const }, presentation: { isFullscreen: false, columns: 120 } }
const KEY = 'AKIAFAKEFAKEFAKE0000'
const PH = /__SECRET_AWS_KEY_ID_[0-9A-F]{8}__/

/** The engine beneath the plugin. `ran` records each tool input that reached core. */
const world = (on: On, files: Record<string, string> = {}) => {
  on('session.start', ($, e) => ({ cwd: e.cwd }))
  on('command.register', ($, e) => ({ value: { command: e.name } }))
  on('fs.read', ($, e) => {
    const text = files[e.path]
    return text === undefined ? { deny: `ENOENT: no such file, open '${e.path}'` } : { value: text }
  })
  mock.env(on, { HOME: '/home/t' })
  const session = mock.session(on)
  const ran: Record<string, unknown>[] = []
  let errorNext = false
  on('tool.call', ($, e) => {
    ran.push({ ...e })
    const echoed = typeof (e as any).command === 'string' ? `ran: ${(e as any).command}` : 'ok'
    if (errorNext) {
      errorNext = false
      return { result: echoed, text: echoed, isError: true as const, ref: 2 }
    }
    return { result: { stdout: echoed, stderr: '', interrupted: false }, text: echoed, ref: 1 }
  })
  on('session.send', ($, e) => ({ isDelivered: true as const, text: e.text }) as any)
  on('prompt.submit', ($, e) => ({ text: e.text }))
  on('prompt.context', ($, e) => ({ blocks: e.blocks }))
  return { session, ran, errorNext: () => (errorNext = true) }
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

  test('an unknown argument answers with usage', async ($, on) => {
    world(on)
    await start($)
    expect((await run($, 'bogus')).text).toContain('Usage: /secret-mask')
  })
})
