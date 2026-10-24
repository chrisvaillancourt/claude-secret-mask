import { describe, expect, test } from 'claude-code/testing'

import { CANARIES, NEAR_MISSES } from './canaries'
import { builtinRules, findSecrets, parsePatternsFile, withUserRules } from './detect'
import { MAX_SECRETS, PLACEHOLDER, maskBlocks, maskDeep, maskText, newVault, restoreFields, restoreText } from './vault'

/** Deterministic tokens: 00000001, 00000002, ... */
const counter = () => {
  let n = 0
  return () => (++n).toString(16).toUpperCase().padStart(8, '0')
}

const rules = builtinRules()

describe('detection', () => {
  test('every canary is found as its kind, whole', async () => {
    for (const c of CANARIES) {
      const spans = findSecrets(c.line, rules)
      expect(spans.map(s => [s.kind, s.value])).toEqual([[c.kind, c.value]])
    }
  })

  test('near misses are left alone', async () => {
    for (const text of NEAR_MISSES) expect(findSecrets(text, rules)).toEqual([])
  })

  test('the allow-list keeps a value readable', async () => {
    const parsed = parsePatternsFile(JSON.stringify({ allow: ['AKIAFAKEFAKEFAKE0000'], allowPatterns: ['^ghp_FAKE'] }))
    expect(parsed.errors).toEqual([])
    const r = withUserRules(rules, parsed)
    expect(findSecrets('AKIAFAKEFAKEFAKE0000', r)).toEqual([])
    expect(findSecrets(CANARIES[2]!.line, r)).toEqual([])
    expect(findSecrets('AKIAFAKEFAKEFAKE1111', r).length).toBe(1)
  })

  test('user patterns add kinds; bad entries are reported, not dropped silently', async () => {
    const parsed = parsePatternsFile(
      JSON.stringify({
        patterns: [
          { name: 'internal-token', regex: 'itk_[A-Za-z0-9]{8}' },
          { name: 'db pass', regex: 'DBPASS=(\\S{8,})', group: 1 },
          { name: 'broken', regex: '(' },
          { name: 'empty', regex: 'x*' },
        ],
      }),
    )
    expect(parsed.errors.length).toBe(2)
    expect(parsed.errors.join('\n')).toContain('broken')
    expect(parsed.errors.join('\n')).toContain('empty')
    const r = withUserRules(rules, parsed)
    expect(findSecrets('use itk_FAKE0000 now', r).map(s => [s.kind, s.value])).toEqual([['INTERNAL_TOKEN', 'itk_FAKE0000']])
    expect(findSecrets('DBPASS=FAKEfake00', r).map(s => [s.kind, s.value])).toEqual([['DB_PASS', 'FAKEfake00']])
  })

  test('a pattern whose name cannot be a placeholder kind is refused at load', async () => {
    const parsed = parsePatternsFile(JSON.stringify({ patterns: [{ name: '1FAKE', regex: 'FAKECUSTOM[0-9]{8}' }, { name: '---', regex: 'x[0-9]{4}' }] }))
    expect(parsed.patterns).toEqual([])
    expect(parsed.errors.length).toBe(2)
    expect(parsed.errors[0]).toContain('1FAKE')
  })

  test('a patterns file that is not JSON is one error', async () => {
    expect(parsePatternsFile('{nope').errors.length).toBe(1)
  })
})

describe('masking', () => {
  test('a secret is replaced by a placeholder that carries its kind', async () => {
    const v = newVault()
    const out = maskText('id AKIAFAKEFAKEFAKE0000 ok', v, rules, counter())
    expect(out.text).toBe('id __SECRET_AWS_KEY_ID_00000001__ ok')
    expect(out.count).toBe(1)
    expect(PLACEHOLDER.test('__SECRET_AWS_KEY_ID_00000001__')).toBe(true)
  })

  test('a repeated secret gets the same placeholder, in one text and across texts', async () => {
    const v = newVault()
    const mint = counter()
    const a = maskText('AKIAFAKEFAKEFAKE0000 and AKIAFAKEFAKEFAKE0000', v, rules, mint)
    expect(a.text).toBe('__SECRET_AWS_KEY_ID_00000001__ and __SECRET_AWS_KEY_ID_00000001__')
    const b = maskText('again AKIAFAKEFAKEFAKE0000', v, rules, mint)
    expect(b.text).toBe('again __SECRET_AWS_KEY_ID_00000001__')
    expect(v.byToken.size).toBe(1)
  })

  test('distinct secrets get distinct placeholders, and a colliding mint is retried', async () => {
    const v = newVault()
    const tokens = ['0000000A', '0000000A', '0000000B']
    const out = maskText('AKIAFAKEFAKEFAKE0000 AKIAFAKEFAKEFAKE1111', v, rules, () => tokens.shift()!)
    expect(out.text).toBe('__SECRET_AWS_KEY_ID_0000000A__ __SECRET_AWS_KEY_ID_0000000B__')
  })

  test('masking is idempotent and an echoed placeholder is left as is', async () => {
    const v = newVault()
    const mint = counter()
    const once = maskText('API_TOKEN=FAKEfakeFAKEfake00', v, rules, mint).text
    expect(once).toBe('API_TOKEN=__SECRET_SECRET_VALUE_00000001__')
    const twice = maskText(once, v, rules, mint)
    expect(twice.text).toBe(once)
    expect(twice.count).toBe(0)
    // A placeholder this vault never issued has no protection: it is scanned
    // like any text (here the assignment rule takes it as a value).
    const foreign = maskText('MY_TOKEN=__SECRET_GITHUB_TOKEN_DEADBEEF__', v, rules, mint)
    expect(foreign.text).toBe('MY_TOKEN=__SECRET_SECRET_VALUE_00000002__')
  })

  test('a known value inside foreign placeholder-shaped text is still masked', async () => {
    const v = newVault()
    const mint = counter()
    maskText('AKIAFAKEFAKEFAKE0000', v, rules, mint)
    const out = maskText('__SECRET_AKIAFAKEFAKEFAKE0000_DEADBEEF__ and __SECRET_X_AKIAFAKEFAKEFAKE0000__', v, rules, mint)
    expect(out.text.includes('AKIAFAKEFAKEFAKE0000')).toBe(false)
  })

  test('a secret nested inside another detected value is registered and masked bare elsewhere', async () => {
    const pass = 'FAKEpass0000'
    const one = maskText(`DATABASE_SECRET=postgres://app:${pass}@db.example/db\nechoed=${pass}`, newVault(), rules, counter())
    expect(one.text.includes(pass)).toBe(false)
    const deep = maskDeep({ stdout: `DATABASE_SECRET=postgres://app:${pass}@db.example/db`, stderr: `echoed=${pass}` }, newVault(), rules, counter())
    expect(JSON.stringify(deep.value).includes(pass)).toBe(false)
    const bearer = 'FAKEBearer0000example'
    const b = maskText(`API_TOKEN="Bearer ${bearer}"\nechoed=${bearer}`, newVault(), rules, counter())
    expect(b.text.includes(bearer)).toBe(false)
  })

  test('a newly found value is masked everywhere in the unit: before, after, across fields and blocks', async () => {
    const X = 'FAKErepeated0000'
    const one = maskText(`echoed=${X}\nOTHER_SECRET=${X}\nagain ${X}`, newVault(), rules, counter())
    expect(one.text).toBe('echoed=__SECRET_SECRET_VALUE_00000001__\nOTHER_SECRET=__SECRET_SECRET_VALUE_00000001__\nagain __SECRET_SECRET_VALUE_00000001__')

    const deep = maskDeep({ stdout: `echoed=${X}`, stderr: `DB_PASSWORD=${X}`, list: [X] }, newVault(), rules, counter())
    expect(JSON.stringify(deep.value).includes(X)).toBe(false)

    const blocks = maskBlocks(
      [
        { type: 'text', text: X },
        { type: 'tool_result', tool_use_id: 't', content: [{ type: 'text', text: X }] },
        { type: 'tool_result', tool_use_id: 'u', content: `token=${X}` },
      ],
      newVault(),
      rules,
      counter(),
    )
    expect(JSON.stringify(blocks.content).includes(X)).toBe(false)
  })

  test('a numeric JSON value is learned without the closing brace, and its bare copies are masked', async () => {
    const pin = '12340000'
    const one = maskText(`{"password":${pin}}\nechoed=${pin}`, newVault(), rules, counter())
    expect(one.text).toBe('{"password":__SECRET_SECRET_VALUE_00000001__}\nechoed=__SECRET_SECRET_VALUE_00000001__')
    const deep = maskDeep({ stdout: `{"db":{"password": ${pin}}}`, stderr: `echoed=${pin}` }, newVault(), rules, counter())
    expect(deep.value).toEqual({ stdout: '{"db":{"password": __SECRET_SECRET_VALUE_00000001__}}', stderr: 'echoed=__SECRET_SECRET_VALUE_00000001__' })
    const list = maskText(`{"tokens":[{"api_token":${pin}]}`, newVault(), rules, counter())
    expect(list.text).toBe('{"tokens":[{"api_token":__SECRET_SECRET_VALUE_00000001__]}')
  })

  test('a name with a leading underscore is checked like any other', async () => {
    const v = 'FAKEunderscore0000'
    expect(findSecrets(`_PASSWORD=${v}`, rules).map(s => s.value)).toEqual([v])
    expect(findSecrets(`{"_authToken": "${v}"}`, rules).map(s => s.value)).toEqual([v])
    expect(findSecrets(`__DB_SECRET=${v}`, rules).map(s => s.value)).toEqual([v])
    expect(findSecrets('{"_token_count":12345678,"_password_hint":"ask the administrator"}', rules)).toEqual([])
  })

  test('a dotenv password holding a brace is still taken whole', async () => {
    const pass = 'FAKE}pass{0000}'
    const out = maskText(`DB_PASSWORD=${pass}\nechoed=${pass}`, newVault(), rules, counter())
    expect(out.text).toBe('DB_PASSWORD=__SECRET_SECRET_VALUE_00000001__\nechoed=__SECRET_SECRET_VALUE_00000001__')
  })

  test('a PEM key split across lines is masked as one secret', async () => {
    const pem = CANARIES.find(c => c.kind === 'PRIVATE_KEY')!
    const out = maskText(pem.line, newVault(), rules, counter())
    expect(out.text).toBe('key file:\n__SECRET_PRIVATE_KEY_00000001__\nend of file')
  })

  test('a known value is masked even where no pattern would find it', async () => {
    const v = newVault()
    const mint = counter()
    maskText('DB_PASSWORD=FAKEfake0000x', v, rules, mint)
    // Printed alone, the value matches no pattern; the vault still knows it.
    expect(maskText('FAKEfake0000x\n', v, rules, mint).text).toBe('__SECRET_SECRET_VALUE_00000001__\n')
  })

  test('no canary survives masking', async () => {
    const v = newVault()
    const all = CANARIES.map(c => c.line).join('\n')
    const out = maskText(all, v, rules, counter()).text
    for (const c of CANARIES) expect(out.includes(c.value)).toBe(false)
  })

  test('maskBlocks masks text and tool_result content and leaves other blocks alone', async () => {
    const v = newVault()
    const image = { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'AKIAFAKEFAKEFAKE0000' } }
    const content = [
      { type: 'text', text: 'k AKIAFAKEFAKEFAKE0000' },
      { type: 'tool_result', tool_use_id: 'tu1', content: 'out AKIAFAKEFAKEFAKE0000' },
      { type: 'tool_result', tool_use_id: 'tu2', content: [{ type: 'text', text: 'AKIAFAKEFAKEFAKE0000' }, image] },
      { type: 'tool_use', id: 'tu3', name: 'Bash', input: { command: 'echo AKIAFAKEFAKEFAKE0000' } },
    ]
    const out = maskBlocks(content, v, rules, counter())
    expect(out.count).toBe(3)
    expect(out.content[0]).toEqual({ type: 'text', text: 'k __SECRET_AWS_KEY_ID_00000001__' })
    expect(out.content[1]).toEqual({ type: 'tool_result', tool_use_id: 'tu1', content: 'out __SECRET_AWS_KEY_ID_00000001__' })
    expect(out.content[2]).toEqual({
      type: 'tool_result',
      tool_use_id: 'tu2',
      content: [{ type: 'text', text: '__SECRET_AWS_KEY_ID_00000001__' }, image],
    })
    expect(out.content[3]).toBe(content[3])
  })

  test('maskDeep masks string values, never keys, and skips base64 payloads', async () => {
    const v = newVault()
    const out = maskDeep(
      { stdout: 'AKIAFAKEFAKEFAKE0000\n', stderr: '', interrupted: false, n: 3, AKIAFAKEFAKEFAKE0000: 'k', list: ['AKIAFAKEFAKEFAKE0000'], base64: 'AKIAFAKEFAKEFAKE0000' },
      v,
      rules,
      counter(),
    )
    expect(out.value).toEqual({
      stdout: '__SECRET_AWS_KEY_ID_00000001__\n',
      stderr: '',
      interrupted: false,
      n: 3,
      AKIAFAKEFAKEFAKE0000: 'k',
      list: ['__SECRET_AWS_KEY_ID_00000001__'],
      base64: 'AKIAFAKEFAKEFAKE0000',
    })
    expect(out.count).toBe(2)
  })
})

describe('restoring', () => {
  test('a known placeholder is restored to the exact value', async () => {
    const v = newVault()
    const masked = maskText('AKIAFAKEFAKEFAKE0000', v, rules, counter()).text
    expect(restoreText(`aws --key ${masked}`, v)).toEqual({ text: 'aws --key AKIAFAKEFAKEFAKE0000', count: 1, unknown: [] })
  })

  test('any reserved-shape token not in the vault is unknown, older issued forms included', async () => {
    const v = newVault()
    expect(restoreText('echo __SECRET_1FAKE_00000001__ __SECRET_X_Y_0000000A__', v).unknown).toEqual([
      '__SECRET_1FAKE_00000001__',
      '__SECRET_X_Y_0000000A__',
    ])
  })

  test('the vault refuses to grow past its bound', async () => {
    const keys = Array.from({ length: MAX_SECRETS + 1 }, (_, i) => `AKIAFAKE${String(i).padStart(12, '0')}`).join(' ')
    expect(() => maskText(keys, newVault(), rules, counter())).toThrow()
  })

  test('an unknown placeholder is reported, not guessed', async () => {
    const v = newVault()
    const out = restoreText('echo __SECRET_AWS_KEY_ID_DEADBEEF__', v)
    expect(out.unknown).toEqual(['__SECRET_AWS_KEY_ID_DEADBEEF__'])
    expect(out.count).toBe(0)
  })

  test('restoreFields restores only the named fields, or every string for "all"', async () => {
    const v = newVault()
    const p = maskText('AKIAFAKEFAKEFAKE0000', v, rules, counter()).text
    const input = { tool: 'Bash', command: `echo ${p}`, description: `print ${p}` }
    const out = restoreFields(input, ['command'], v)
    expect(out.input).toEqual({ tool: 'Bash', command: 'echo AKIAFAKEFAKEFAKE0000', description: `print ${p}` })
    expect(out.count).toBe(1)

    const mcp = { tool: 'mcp__x__y', tool_use_id: 'tu1', args: { headers: [`Bearer ${p}`] } }
    const deep = restoreFields(mcp, 'all', v)
    expect(deep.input).toEqual({ tool: 'mcp__x__y', tool_use_id: 'tu1', args: { headers: ['Bearer AKIAFAKEFAKEFAKE0000'] } })
  })
})
