// Obviously fake secrets in each supported format. The tests and the
// `/secret-mask test` self-test both run them, so they live in the module.
// None of these is a real credential: each is built from FAKE/fake/0000.

export type Canary = {
  /** The placeholder kind the canary must be masked as. */
  kind: string
  /** The secret itself: what must not survive masking. */
  value: string
  /** A line of output holding it, as a tool would print it. */
  line: string
}

const F = 'FAKEfake'

const PEM = ['-----BEGIN RSA PRIVATE KEY-----', `${F}${F}${F}${F}`, `${F}${F}0000`, '-----END RSA PRIVATE KEY-----'].join('\n')

export const CANARIES: readonly Canary[] = [
  { kind: 'AWS_KEY_ID', value: 'AKIAFAKEFAKEFAKE0000', line: 'aws_access_key_id = AKIAFAKEFAKEFAKE0000' },
  {
    kind: 'SECRET_VALUE',
    value: `${F}${F}${F}${F}${F}`,
    line: `AWS_SECRET_ACCESS_KEY=${F}${F}${F}${F}${F}`,
  },
  { kind: 'GITHUB_TOKEN', value: `ghp_${F}${F}${F}${F}0000`, line: `token: ghp_${F}${F}${F}${F}0000 (repo scope)` },
  { kind: 'GITLAB_TOKEN', value: `glpat-${F}${F}0000`, line: `glpat-${F}${F}0000` },
  { kind: 'SLACK_TOKEN', value: `xoxb-0000000000-0000000000-${F}${F}`, line: `SLACK=xoxb-0000000000-0000000000-${F}${F}` },
  {
    kind: 'ANTHROPIC_KEY',
    value: `sk-ant-api03-${F}${F}${F}-0000`,
    line: `using key sk-ant-api03-${F}${F}${F}-0000 for the request`,
  },
  { kind: 'OPENAI_KEY', value: `sk-proj-${F}${F}${F}${F}0000`, line: `client = OpenAI("sk-proj-${F}${F}${F}${F}0000")` },
  { kind: 'GOOGLE_API_KEY', value: `AIza${F}${F}${F}${F}000`, line: `?key=AIza${F}${F}${F}${F}000&q=x` },
  { kind: 'NPM_TOKEN', value: `npm_${F}${F}${F}${F}0000`, line: `//registry.npmjs.org/:_authToken=npm_${F}${F}${F}${F}0000` },
  { kind: 'HF_TOKEN', value: `hf_${F}${F}${F}${F}00`, line: `HF hf_${F}${F}${F}${F}00` },
  {
    kind: 'JWT',
    value: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJGQUtFIn0.RkFLRUZBS0VGQUtF',
    line: 'cookie: session=eyJhbGciOiJub25lIn0.eyJzdWIiOiJGQUtFIn0.RkFLRUZBS0VGQUtF; Path=/',
  },
  { kind: 'PRIVATE_KEY', value: PEM, line: `key file:\n${PEM}\nend of file` },
  { kind: 'BEARER_TOKEN', value: `${F}${F}0000`, line: `Authorization: Bearer ${F}${F}0000` },
  { kind: 'URL_PASSWORD', value: 'FAKEpass0000', line: 'DATABASE=postgres://app:FAKEpass0000@db.example.com:5432/app' },
  { kind: 'SECRET_VALUE', value: `${F}${F}00`, line: `{\n  "client_secret":\n    "${F}${F}00"\n}` },
  // The assignment forms the README names, and the boundaries of the rule.
  { kind: 'SECRET_VALUE', value: 'FAKEfake0000example', line: 'password: FAKEfake0000example' },
  { kind: 'SECRET_VALUE', value: 'FAKEfake0000example', line: 'token=FAKEfake0000example' },
  { kind: 'SECRET_VALUE', value: 'FAKEfake0000example', line: '{"api_key":"FAKEfake0000example"}' },
  { kind: 'SECRET_VALUE', value: 'FAKEfake0000example', line: '"api_token": "FAKEfake0000example",' },
  { kind: 'SECRET_VALUE', value: 'FAKE password 0000', line: 'DB_PASSWORD="FAKE password 0000"' },
  { kind: 'SECRET_VALUE', value: 'FAKEfake,0000example', line: "DB_PASSWORD='FAKEfake,0000example'" },
  { kind: 'SECRET_VALUE', value: 'fakeexamplepassword', line: 'DB_PASSWORD=fakeexamplepassword' },
  { kind: 'SECRET_VALUE', value: '0000123400001234', line: 'DB_PASSWORD=0000123400001234' },
  { kind: 'SECRET_VALUE', value: 'fakepass', line: 'export PGPASSWORD=fakepass' },
  { kind: 'BEARER_TOKEN', value: 'FAKEfake0000example', line: 'authorization: bEaReR FAKEfake0000example' },
  { kind: 'AWS_KEY_ID', value: 'AKIAFAKEFAKEFAKE0000', line: 'key_AKIAFAKEFAKEFAKE0000_suffix' },
]

/** Text that looks close to a secret and must be left alone. */
export const NEAR_MISSES: readonly string[] = [
  'AKIAFAKEFAKEFAKE000 is one character short',
  'token_expiry_seconds=3600',
  'password=${DB_PASSWORD}',
  'api_key=${API_KEY}',
  'token: $GITHUB_TOKEN',
  'password: "{{ .Values.dbPassword }}"',
  'token_type="bearer"',
  'token_count=12345678',
  'token_kind="identifier"',
  'password_hint="ask the administrator"',
  'GITHUB_TOKEN_PATH=/home/example/.config/token',
  'max_tokens: 128000000',
  '{"token_count":12345678,"token_kind":"identifier","password_hint":"ask the administrator","request_id":"00000000-0000-4000-8000-000000000000"}',
  'ghp_tooShort0000',
  'the token is refreshed every hour',
  'SECRET_KEY=************************',
  'api_key: <your-api-key-here>',
  'sk-ant-short',
]
