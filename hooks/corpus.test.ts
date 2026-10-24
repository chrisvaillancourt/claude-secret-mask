import { describe, expect, test } from 'claude-code/testing'

import { builtinRules } from './detect'
import { maskDeep, maskText, newVault, restoreText } from './vault'

// The standing detection corpus: README "What gets masked" is the contract,
// and every row here is checked against it. A row is one masking unit (a
// string, or several strings masked together as one tool result). `mask`
// lists the exact values that must be masked; everything else must come back
// byte-identical, and restoring the output must give the input back. Every
// repro from a past review is a row. Fixtures are fake (FAKE, 0000).

type Format = 'dotenv' | 'ini' | 'yaml' | 'json' | 'cli' | 'vendor' | 'unit' | 'out-of-contract'
type Row = { format: Format; name: string; input: string | string[]; mask: string[] }

const SG = `SG.${'FAKEfake0000FAKEfake00'}.${'FAKEfake0000FAKEfake0000FAKEfake0000FAKEfak'}`
const PEM_JSON = '-----BEGIN PRIVATE KEY-----\\nFAKEfakeFAKEfakeFAKEfake0000\\n-----END PRIVATE KEY-----\\n'

export const CORPUS: readonly Row[] = [
  // dotenv and shell
  { format: 'dotenv', name: 'R3: a brace inside an unquoted value is part of it', input: 'DB_PASSWORD=FAKE}pass{0000}\nechoed=FAKE}pass{0000}', mask: ['FAKE}pass{0000}'] },
  { format: 'dotenv', name: 'R3-3: leading underscore', input: '_PASSWORD=FAKEunderscore0000', mask: ['FAKEunderscore0000'] },
  { format: 'dotenv', name: 'R3-3: double leading underscore', input: '__DB_SECRET=FAKEunderscore0000', mask: ['FAKEunderscore0000'] },
  { format: 'dotenv', name: 'export, eight characters', input: 'export PGPASSWORD=fakepass', mask: ['fakepass'] },
  { format: 'dotenv', name: 'R1: bare keyword name', input: 'token=FAKEfake0000example', mask: ['FAKEfake0000example'] },
  { format: 'dotenv', name: 'R1: double-quoted value with spaces', input: 'DB_PASSWORD="FAKE password 0000"', mask: ['FAKE password 0000'] },
  { format: 'dotenv', name: 'R1: single-quoted value with a comma', input: "DB_PASSWORD='FAKEfake,0000example'", mask: ['FAKEfake,0000example'] },
  { format: 'dotenv', name: 'R1: all lowercase value', input: 'DB_PASSWORD=fakeexamplepassword', mask: ['fakeexamplepassword'] },
  { format: 'dotenv', name: 'R1: all numeric value', input: 'DB_PASSWORD=0000123400001234', mask: ['0000123400001234'] },
  { format: 'dotenv', name: 'AWS secret access key', input: 'AWS_SECRET_ACCESS_KEY=FAKEfakeFAKEfakeFAKEfake0000', mask: ['FAKEfakeFAKEfakeFAKEfake0000'] },
  { format: 'dotenv', name: 'an unquoted value ends at a comment', input: 'DB_PASSWORD=FAKEfake0000x # rotate monthly', mask: ['FAKEfake0000x'] },
  { format: 'dotenv', name: 'an unquoted value runs to the end of the line; its first word is learned too', input: 'API_TOKEN=FAKEtoken0000 run\necho FAKEtoken0000', mask: ['FAKEtoken0000 run', 'FAKEtoken0000'] },
  { format: 'dotenv', name: 'compose environment list item', input: 'environment:\n  - POSTGRES_PASSWORD=FAKEcompose0000', mask: ['FAKEcompose0000'] },
  { format: 'dotenv', name: 'declare -x from export -p', input: 'declare -x GITHUB_TOKEN="FAKEdeclare0000"', mask: ['FAKEdeclare0000'] },
  { format: 'dotenv', name: 'Java properties dotted name', input: 'spring.datasource.password=FAKEprops0000', mask: ['FAKEprops0000'] },
  { format: 'dotenv', name: 'CRLF line ending is not part of the value', input: 'DB_PASSWORD=FAKEcrlf0000\r\nNEXT=1\r\n', mask: ['FAKEcrlf0000'] },
  { format: 'dotenv', name: 'R2: URL password inside a secret assignment, then bare', input: 'DATABASE_SECRET=postgres://app:FAKEpass0000@db.example/db\nechoed=FAKEpass0000', mask: ['postgres://app:FAKEpass0000@db.example/db', 'FAKEpass0000'] },
  { format: 'dotenv', name: 'R2: Bearer inside a quoted assignment, then bare', input: 'API_TOKEN="Bearer FAKEBearer0000example"\nechoed=FAKEBearer0000example', mask: ['Bearer FAKEBearer0000example', 'FAKEBearer0000example'] },
  { format: 'dotenv', name: 'R1: repeated before and after the assignment', input: 'echoed=FAKErepeated0000\nOTHER_SECRET=FAKErepeated0000\nagain FAKErepeated0000', mask: ['FAKErepeated0000'] },
  { format: 'dotenv', name: 'negative: references', input: 'password=${DB_PASSWORD}\napi_key=${API_KEY}\ntoken=$GITHUB_TOKEN', mask: [] },
  { format: 'dotenv', name: 'negative: filler', input: 'SECRET_KEY=************************', mask: [] },
  { format: 'dotenv', name: 'negative: R2 metadata names', input: 'token_count=12345678\ntoken_kind="identifier"\npassword_hint="ask the administrator"\nGITHUB_TOKEN_PATH=/home/example/.config/token', mask: [] },
  { format: 'dotenv', name: 'negative: token_expiry_seconds and _token_count', input: 'token_expiry_seconds=36000000\n_token_count=12345678', mask: [] },
  { format: 'dotenv', name: 'negative: a UUID under an ordinary name', input: 'request_id=00000000-0000-4000-8000-000000000000', mask: [] },
  { format: 'dotenv', name: 'negative: seven characters', input: 'DB_PASSWORD=FAKE000', mask: [] },
  { format: 'dotenv', name: 'negative: a comparison is not an assignment', input: 'token == FAKEcompare0000', mask: [] },

  // INI and credentials files
  {
    format: 'ini',
    name: 'AWS credentials file',
    input: '[default]\naws_access_key_id = AKIAFAKEFAKEFAKE0000\naws_secret_access_key = FAKEfakeFAKEfakeFAKEfake0000abcd\naws_session_token = FAKEsessionTOKEN0000fakeFAKE\nregion = us-east-1\n',
    mask: ['AKIAFAKEFAKEFAKE0000', 'FAKEfakeFAKEfakeFAKEfake0000abcd', 'FAKEsessionTOKEN0000fakeFAKE'],
  },
  { format: 'ini', name: 'section and spaced key', input: '[database]\nhost = db.example\npassword = FAKEini0000pass\n', mask: ['FAKEini0000pass'] },
  { format: 'ini', name: '.npmrc registry auth token', input: '//registry.example.com/:_authToken=FAKEnpmrc0000legacy', mask: ['FAKEnpmrc0000legacy'] },
  { format: 'ini', name: 'TOML quoted string', input: '[service]\napi_key = "FAKEtoml0000key"', mask: ['FAKEtoml0000key'] },
  { format: 'ini', name: 'negative: a subscript in code', input: 'token = tokens[index]', mask: [] },
  { format: 'ini', name: 'negative: a call in code', input: '    password = get_password(user)', mask: [] },
  { format: 'ini', name: 'negative: ordinary keys', input: '[default]\nregion = us-east-1\noutput = json\npassword_hint = ask the admin', mask: [] },

  // YAML
  { format: 'yaml', name: 'R1: password: value', input: 'password: FAKEfake0000example', mask: ['FAKEfake0000example'] },
  { format: 'yaml', name: 'R3-3: _authToken', input: '_authToken: FAKEyarn0000token', mask: ['FAKEyarn0000token'] },
  { format: 'yaml', name: 'list item mapping', input: 'users:\n  - password: FAKElist0000yaml\n    name: app', mask: ['FAKElist0000yaml'] },
  { format: 'yaml', name: 'nested, double-quoted with spaces', input: 'db:\n  password: "FAKE quoted 0000"\n  user: app', mask: ['FAKE quoted 0000'] },
  { format: 'yaml', name: 'single-quoted', input: "secret: 'FAKEsingle0000'", mask: ['FAKEsingle0000'] },
  { format: 'yaml', name: 'plain value ends at a comment', input: 'password: FAKEyaml0000 # rotate monthly', mask: ['FAKEyaml0000'] },
  { format: 'yaml', name: 'an anchor before the value is skipped', input: 'password: &pw FAKEanchor0000', mask: ['FAKEanchor0000'] },
  { format: 'yaml', name: 'HTTP header at line start', input: 'X-Api-Key: FAKEheader0000key', mask: ['FAKEheader0000key'] },
  { format: 'yaml', name: 'JSON-style line, quoted value', input: '"api_token": "FAKEfake0000example",', mask: ['FAKEfake0000example'] },
  { format: 'yaml', name: 'JSON-style fragment, number before a comma', input: '  "pin_token": 12340000,\n  "other": 1', mask: ['12340000'] },
  { format: 'yaml', name: 'R4 matrix: JSON-style fragment, no space after a quoted key', input: '"pin_token":12345678\necho 12345678', mask: ['12345678'] },
  { format: 'yaml', name: 'R4 matrix: JSON-style fragment, number before closing brackets', input: '"PASSWORD":12345678]}\necho 12345678', mask: ['12345678'] },
  { format: 'yaml', name: 'R4 matrix: JSON-style fragment, a negative exponent', input: '  "api_token":-1.23e+45,', mask: ['-1.23e+45'] },
  { format: 'yaml', name: 'negative: templates, references, placeholders', input: 'password: "{{ .Values.dbPassword }}"\napi_key: <your-api-key-here>\ntoken: $GITHUB_TOKEN\npassword: ${{ secrets.DB_PASSWORD }}', mask: [] },
  { format: 'yaml', name: 'negative: tags, aliases, block scalars, flow collections', input: 'password: !Ref DbPassword00\ntoken: *default_token\nsecret: |\nkey: {a: b}', mask: [] },
  { format: 'yaml', name: 'negative: ordinary values', input: 'token_type: "bearer"\nmax_tokens: 128000000\ntoken_kind: identifier', mask: [] },
  { format: 'yaml', name: 'negative: a call in an object literal', input: '  token: generateToken(user),', mask: [] },

  // JSON
  { format: 'json', name: 'R3-2: numeric value, then a bare copy', input: '{"password":12340000}\nechoed=12340000', mask: ['12340000'] },
  { format: 'json', name: 'R3-2: nested numeric value', input: '{"db":{"password": 12340000}}', mask: ['12340000'] },
  { format: 'json', name: 'numeric value in an array of objects', input: '{"tokens":[{"api_token":12340000}]}', mask: ['12340000'] },
  { format: 'json', name: 'R1: compact api_key', input: '{"api_key":"FAKEfake0000example"}', mask: ['FAKEfake0000example'] },
  { format: 'json', name: 'key and value on different lines', input: '{\n  "client_secret":\n    "FAKEfakeFAKEfake00"\n}', mask: ['FAKEfakeFAKEfake00'] },
  { format: 'json', name: 'R3-3: _authToken key', input: '{"_authToken": "FAKEunderscore0000"}', mask: ['FAKEunderscore0000'] },
  { format: 'json', name: 'NDJSON line', input: '{"level":"info","token":"FAKEndjson0000one"}\n{"level":"info","msg":"ok"}', mask: ['FAKEndjson0000one'] },
  { format: 'json', name: 'the rest of a log line', input: '2026-10-24T00:00:00Z INFO {"user":"app","password":"FAKElogtail0000"}', mask: ['FAKElogtail0000'] },
  { format: 'json', name: 'the rest of a log line after a bracketed timestamp', input: '[2026-10-24 00:00:00] INFO {"password":"FAKElogtail0001"}', mask: ['FAKElogtail0001'] },
  { format: 'json', name: 'a body after HTTP headers', input: 'HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"data": {"access_token": "FAKEaccess0000token", "expires_in": 3600}}', mask: ['FAKEaccess0000token'] },
  { format: 'json', name: 'R5-3: brackets in a header line do not use up the scan before the body', input: `HTTP/1.1 200 OK\nX-Trace: [[[[[[[[\nContent-Type: application/json\n\n${JSON.stringify({ token: ['FAKE_HTTP_SMALL_0000'], padding: 'x'.repeat(1024) })}\nechoed=FAKE_HTTP_SMALL_0000`, mask: ['FAKE_HTTP_SMALL_0000'] },
  { format: 'json', name: 'R5-3: a body over 1 MiB after headers', input: `HTTP/1.1 200 OK\nContent-Type: application/json\n\n${JSON.stringify({ token: ['FAKE_EMBEDDED_0000'], padding: 'x'.repeat(1100000) })}\nechoed=FAKE_EMBEDDED_0000`, mask: ['FAKE_EMBEDDED_0000'] },
  { format: 'json', name: 'escaped string: as written and decoded', input: '{"password":"FAKE\\"quoted\\"0000"}\nplain FAKE"quoted"0000', mask: ['FAKE\\"quoted\\"0000', 'FAKE"quoted"0000'] },
  { format: 'json', name: 'strings in an array under a secret key', input: '{"token": ["FAKEarray0000one", "FAKEarray0000two"]}', mask: ['FAKEarray0000one', 'FAKEarray0000two'] },
  { format: 'json', name: 'a dotenv line inside a JSON string', input: '[{"Config":{"Env":["PATH=/usr/bin","POSTGRES_PASSWORD=FAKEdocker0000env"]}}]', mask: ['FAKEdocker0000env'] },
  { format: 'json', name: 'R5-1: an escaped backslash in an assignment inside a JSON string', input: '{"Env":["PASSWORD=FAKE\\\\path0000"]}\nbare FAKE\\path0000', mask: ['FAKE\\\\path0000', 'FAKE\\path0000'] },
  { format: 'json', name: 'R5-1: escaped quotes in an assignment inside a JSON string array', input: '{"Env":["PATH=/bin","API_TOKEN=\\"FAKE quoted 0000\\""]}', mask: ['FAKE quoted 0000'] },
  { format: 'json', name: 'R5-1: a unicode escape inside an assignment in a JSON string', input: '["DB_PASSWORD=FAKE\\u0041uni0000"]\nbare FAKEAuni0000', mask: ['FAKE\\u0041uni0000', 'FAKEAuni0000'] },
  { format: 'json', name: 'R5-1: an escaped flag value in a JSON args array', input: '{"args":["--password=FAKE\\\\slash0000","-v"]}', mask: ['FAKE\\\\slash0000'] },
  { format: 'json', name: 'service account private key', input: `{"type":"service_account","private_key_id":"0000fake","private_key":"${PEM_JSON}"}`, mask: [PEM_JSON] },
  { format: 'json', name: 'negative: R2 ordinary metrics', input: '{"token_count":12345678,"token_kind":"identifier","password_hint":"ask the administrator","request_id":"00000000-0000-4000-8000-000000000000"}', mask: [] },
  { format: 'json', name: 'negative: R3-3 _token_count', input: '{"_token_count":12345678,"_password_hint":"ask the administrator"}', mask: [] },
  { format: 'json', name: 'negative: a short numeric PIN', input: '{"pin_token": 1234, "password": 1234567}', mask: [] },
  { format: 'json', name: 'negative: booleans and null', input: '{"token": null, "auth": true, "secret": false}', mask: [] },

  // Command-line flags
  { format: 'cli', name: 'equals form', input: 'mysql --password=FAKEcli0000pass -h db', mask: ['FAKEcli0000pass'] },
  { format: 'cli', name: 'space form', input: 'tool --api-key FAKEcli0000key --verbose', mask: ['FAKEcli0000key'] },
  { format: 'cli', name: 'quoted value', input: 'tool --token "FAKE cli 0000"', mask: ['FAKE cli 0000'] },
  { format: 'cli', name: 'in a ps line', input: '  501 12345 node server.js --db-password=FAKEps0000pass', mask: ['FAKEps0000pass'] },
  { format: 'cli', name: 'ends at a shell operator', input: 'run --token=FAKEshell0000op;next', mask: ['FAKEshell0000op'] },
  { format: 'cli', name: 'R5-2: an escaped quote before the minimum length', input: 'tool --password="FAK\\"E0000x"\nbare FAK"E0000x', mask: ['FAK\\"E0000x', 'FAK"E0000x'] },
  { format: 'cli', name: 'R5-2: an escaped quote after the minimum length', input: 'tool --password="FAKElong0000\\"tail0000"', mask: ['FAKElong0000\\"tail0000'] },
  { format: 'cli', name: 'R5-2: an escaped quote in the space form', input: "tool --token \"FAKE\\\"sp0000\" --next 'single quoted'", mask: ['FAKE\\"sp0000'] },
  { format: 'cli', name: 'R6-1: an escaped space in an unquoted value (printf %q)', input: 'tool --password=FAKE\\ space0000\nbare FAKE space0000', mask: ['FAKE\\ space0000', 'FAKE space0000'] },
  { format: 'cli', name: 'R6-1: an escaped space after a long prefix', input: 'tool --token=FAKElongprefix0000\\ tail0000\nbare FAKElongprefix0000 tail0000', mask: ['FAKElongprefix0000\\ tail0000', 'FAKElongprefix0000 tail0000'] },
  { format: 'cli', name: 'R6-1: an escaped space in the space form, then the next flag', input: 'tool --api-key FAKE\\ sp0000x --verbose', mask: ['FAKE\\ sp0000x'] },
  { format: 'cli', name: 'R6-1: a backslash-newline inside double quotes', input: 'tool --password="FAKE\\\ncontinued0000"\nbare FAKEcontinued0000', mask: ['FAKE\\\ncontinued0000', 'FAKEcontinued0000'] },
  { format: 'cli', name: 'negative: flag values that are not secrets', input: 'tool --token-file /path/to/token --password-stdin --no-auth somewhere/long\ntool --password --verbose', mask: [] },

  // Vendor formats
  { format: 'vendor', name: 'Stripe webhook secret', input: 'signing secret whsec_FAKEfakeFAKEfake0000abcd ok', mask: ['whsec_FAKEfakeFAKEfake0000abcd'] },
  { format: 'vendor', name: 'SendGrid key', input: `key ${SG} ok`, mask: [SG] },
  { format: 'vendor', name: 'AWS key glued to underscores', input: 'key_AKIAFAKEFAKEFAKE0000_suffix', mask: ['AKIAFAKEFAKEFAKE0000'] },
  { format: 'vendor', name: 'R1: Bearer, mixed case', input: 'authorization: bEaReR FAKEfake0000example', mask: ['FAKEfake0000example'] },
  { format: 'vendor', name: 'URL password', input: 'postgres://app:FAKEpass0000@db.example.com/db', mask: ['FAKEpass0000'] },
  { format: 'vendor', name: 'URL password, percent-encoded, then decoded bare', input: 'postgres://app:FAKE%40pass0000@db/x\necho FAKE@pass0000', mask: ['FAKE%40pass0000', 'FAKE@pass0000'] },
  { format: 'vendor', name: 'negative: a prefix glued to a letter', input: 'xghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000', mask: [] },
  { format: 'vendor', name: 'negative: a bare UUID', input: 'id 00000000-0000-4000-8000-000000000000', mask: [] },

  // Several strings masked as one unit (a tool result's stdout and stderr)
  { format: 'unit', name: 'R2: URL password across stdout and stderr', input: ['DATABASE_SECRET=postgres://app:FAKEpass0000@db.example/db', 'echoed=FAKEpass0000'], mask: ['postgres://app:FAKEpass0000@db.example/db', 'FAKEpass0000'] },
  { format: 'unit', name: 'R3-2: numeric JSON across stdout and stderr', input: ['{"db":{"password": 12340000}}', 'echoed=12340000'], mask: ['12340000'] },
  { format: 'unit', name: 'R1: found in a later field, masked in an earlier one', input: ['echoed=FAKErepeated0000', 'DB_PASSWORD=FAKErepeated0000'], mask: ['FAKErepeated0000'] },

  // Out of contract (README): pinned so a change is a decision, not an accident.
  { format: 'out-of-contract', name: 'an assignment in the middle of a line', input: 'connecting with password=FAKEmidline0000 now', mask: [] },
  { format: 'out-of-contract', name: 'a URL query string', input: 'GET /api?user=app&api_key=FAKEquery0000key HTTP/1.1', mask: [] },
  { format: 'out-of-contract', name: 'R4 matrix: no space after an unquoted YAML key', input: 'PASSWORD:12345678}', mask: [] },
  { format: 'out-of-contract', name: 'invalid JSON gets no JSON handling', input: '{"tokens":[{"api_token":12340000]}', mask: [] },
]

/**
 * Rows a detector change is known to fail, kept as red assertions (each must
 * still fail) until the change that fixes them lands. Empty: every row passes.
 */
const PENDING = new Set<string>([])

const RESERVED = /__SECRET_[A-Za-z0-9_]+?_[0-9A-F]{8}__/g

/** The input with every listed value (earliest, then longest) replaced by a mark. */
function expected(text: string, values: readonly string[]): string {
  const spans: [number, number][] = []
  for (const v of values) for (let at = text.indexOf(v); at !== -1; at = text.indexOf(v, at + 1)) spans.push([at, at + v.length])
  spans.sort((a, b) => a[0] - b[0] || b[1] - a[1])
  let out = ''
  let at = 0
  for (const [s, e] of spans) {
    if (s < at) continue
    out += `${text.slice(at, s)}\u0000`
    at = e
  }
  return out + text.slice(at)
}

/** Why a row fails, or undefined when it passes. */
function check(row: Row): string | undefined {
  const counter = (() => {
    let n = 0
    return () => (++n).toString(16).toUpperCase().padStart(8, '0')
  })()
  const vault = newVault()
  const inputs = typeof row.input === 'string' ? [row.input] : row.input
  let outputs: string[]
  try {
    outputs = typeof row.input === 'string' ? [maskText(row.input, vault, builtinRules(), counter).text] : (maskDeep(row.input, vault, builtinRules(), counter).value as string[])
  } catch (err) {
    return `masking threw: ${String(err)}`
  }
  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i]!
    const output = outputs[i]!
    for (const v of row.mask) if (output.includes(v)) return `${JSON.stringify(v)} survived: ${JSON.stringify(output)}`
    const want = expected(input, row.mask)
    const got = output.replace(RESERVED, '\u0000')
    if (got !== want) return `masked differently: got ${JSON.stringify(output)}`
    const back = restoreText(output, vault).text
    if (back !== input) return `did not round-trip: ${JSON.stringify(back)}`
  }
  return undefined
}

describe('detection corpus', () => {
  test('row names are unique', async () => {
    expect(new Set(CORPUS.map(r => `${r.format}: ${r.name}`)).size).toBe(CORPUS.length)
  })

  for (const row of CORPUS) {
    const id = `${row.format}: ${row.name}`
    if (PENDING.has(id)) {
      test(`(pending redesign, must still fail) ${id}`, async () => {
        expect(check(row)).not.toBe(undefined)
      })
    } else {
      test(id, async () => {
        // Cut: a large row's whole output would not fit the test report.
        expect(check(row)?.slice(0, 300)).toBe(undefined)
      })
    }
  }
})
