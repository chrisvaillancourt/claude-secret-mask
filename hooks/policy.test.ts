import { describe, expect, test } from 'claude-code/testing'

import { CANARIES } from './canaries'
import { builtinRules } from './detect'
import { INITIAL, configFrom, expandHome, isActive, isSessionToolResult, parseArgs, restoreFieldsFor, selfTest, statusText, withheld } from './policy'

describe('policy', () => {
  test('parseArgs reads on, off, status, test and rejects the rest', async () => {
    expect(parseArgs('')).toEqual({ kind: 'status' })
    expect(parseArgs(' ON ')).toEqual({ kind: 'set', mode: 'on' })
    expect(parseArgs('off')).toEqual({ kind: 'set', mode: 'off' })
    expect(parseArgs('test')).toEqual({ kind: 'test' })
    expect(parseArgs('bogus')).toEqual({ kind: 'help', error: 'Unknown argument: bogus' })
  })

  test('a session override beats the enabled option', async () => {
    expect(isActive(configFrom({}), INITIAL)).toBe(true)
    expect(isActive(configFrom({ enabled: false }), INITIAL)).toBe(false)
    expect(isActive(configFrom({ enabled: false }), { mode: 'on' })).toBe(true)
    expect(isActive(configFrom({}), { mode: 'off' })).toBe(false)
  })

  test('configFrom fills defaults', async () => {
    expect(configFrom({})).toEqual({
      enabled: true,
      restoreIntoFiles: false,
      restoreInMcp: false,
      refuseSecretMentions: true,
      patternsFile: '~/.config/secret-mask/patterns.json',
    })
  })

  test('restoreFieldsFor follows the per-tool policy', async () => {
    const off = configFrom({})
    const on = configFrom({ restoreIntoFiles: true, restoreInMcp: true })
    expect(restoreFieldsFor('Bash', off)).toEqual(['command'])
    expect(restoreFieldsFor('PowerShell', off)).toEqual(['command'])
    expect(restoreFieldsFor('Monitor', off)).toEqual(['command'])
    expect(restoreFieldsFor('Write', off)).toEqual([])
    expect(restoreFieldsFor('Write', on)).toEqual(['content'])
    expect(restoreFieldsFor('Edit', on)).toEqual(['old_string', 'new_string'])
    expect(restoreFieldsFor('NotebookEdit', on)).toEqual(['new_source'])
    expect(restoreFieldsFor('mcp__srv__call', off)).toEqual([])
    expect(restoreFieldsFor('mcp__srv__call', on)).toBe('all')
    for (const t of ['Agent', 'SendMessage', 'Read', 'WebFetch', 'TaskCreate']) expect(restoreFieldsFor(t, on)).toEqual([])
  })

  test('isSessionToolResult accepts only a file directly in this session\'s tool-results folder', async () => {
    const root = '/h/.claude/projects'
    expect(isSessionToolResult('/h/.claude/projects/-x/s1/tool-results/b1.txt', root, 's1')).toBe(true)
    expect(isSessionToolResult('/h/.claude/projects/-x/s2/tool-results/b1.txt', root, 's1')).toBe(false)
    expect(isSessionToolResult('/tmp/a/projects/-x/s1/tool-results/b1.txt', root, 's1')).toBe(false)
    expect(isSessionToolResult('/h/.claude/projects/-x/s1/tool-results/sub/b1.txt', root, 's1')).toBe(false)
    expect(isSessionToolResult('/h/.claude/projects-evil/-x/s1/tool-results/b1.txt', root, 's1')).toBe(false)
    expect(isSessionToolResult('/etc/passwd', root, 's1')).toBe(false)
  })

  test('expandHome expands a leading ~ only', async () => {
    expect(expandHome('~/.config/x.json', '/home/t')).toBe('/home/t/.config/x.json')
    expect(expandHome('/etc/x.json', '/home/t')).toBe('/etc/x.json')
    expect(expandHome('~/x', undefined)).toBe(undefined)
  })

  test('statusText reports counts by kind and never a value', async () => {
    const text = statusText(configFrom({}), INITIAL, {
      secrets: { AWS_KEY_ID: 2, GITHUB_TOKEN: 1 },
      masked: 5,
      restored: 1,
      denied: 0,
      patterns: { path: '/home/t/p.json', state: 'error', count: 0, errors: ['pattern "x": can match an empty string'] },
    })
    expect(text).toContain('on (from the enabled option)')
    expect(text).toContain('AWS_KEY_ID 2')
    expect(text).toContain('GITHUB_TOKEN 1')
    expect(text).toContain('5 masked, 1 restored, 0 denied')
    expect(text).toContain('can match an empty string')
  })

  test('the self-test masks every canary, round-trips, and leaves near misses', async () => {
    const out = selfTest(builtinRules(), configFrom({}))
    expect(out.isPassing).toBe(true)
    for (const c of CANARIES) expect(out.text.includes(c.value)).toBe(false)
    expect(out.text).toContain('AWS_KEY_ID')
    expect(out.text).toContain('round trip')
    expect(out.text).toContain('near misses')
  })

  test('the self-test fails loudly when a rule set misses canaries', async () => {
    const out = selfTest({ patterns: [], allow: new Set(), allowPatterns: [] }, configFrom({}))
    expect(out.isPassing).toBe(false)
    expect(out.text).toContain('NOT masked')
    for (const c of CANARIES) expect(out.text.includes(c.value)).toBe(false)
  })

  test('withheld replaces text and tool results and keeps other blocks', async () => {
    const tu = { type: 'tool_use', id: 't', name: 'Bash', input: {} }
    expect(withheld([{ type: 'text', text: 'x' }, { type: 'tool_result', tool_use_id: 't', content: 'y' }, tu])).toEqual([
      { type: 'text', text: '[secret-mask: text withheld because masking failed]' },
      { type: 'tool_result', tool_use_id: 't', content: '[secret-mask: text withheld because masking failed]' },
      tu,
    ])
  })
})
