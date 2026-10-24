# secret-mask

A Claude Code mod (function-hook plugin) for reversible secret masking. Secrets in what reaches the model (tool output above all) are replaced with stable placeholders such as `__SECRET_AWS_KEY_ID_3F9A1C7E__`. When the model uses a placeholder in a shell command, the mod puts the real value back just before the command runs. The model can work with a credential it never reads.

This is masking on the paths the mod API lets a plugin rewrite, not a vault or an exfiltration firewall. Read [What it does not cover](#what-it-does-not-cover) before you rely on it.

## Behavior

- **Detects** secrets from three sources, in order: known values (secret-named environment variables, values in your patterns file, and anything already found), known token formats, and secret-named assignments in a fixed list of formats. See [What gets masked](#what-gets-masked). You can add your own patterns, exact values and an allow-list in a file outside the repo (see [Patterns file](#patterns-file)).
- **Masks** in the main conversation and in subagents:
  - every row the conversation keeps (`session.append`, all doors: your prompt, tool results, deliveries from other agents and sessions, hook context, compaction summaries, the model's own text). Attachment rows are the exception: see the next point and [What it does not cover](#what-it-does-not-cover). This is what the model reads and what the transcript file stores.
  - `@`-mentions (`prompt.mention`): a text file holding a detectable secret is refused before it is read, unless `refuseSecretMentions` is off.
  - what the model reads for each injected attachment (`prompt.attachment`): a file you mention with `@`, reminders, a settings hook's context. Checked live: the model quoted an `@file` line as a placeholder.
  - the prompt as you submit it (`prompt.submit`), so the queued record matches.
  - the tool's structured result (`tool.call`), which the screen draws and the transcript stores beside the model's copy. A failed tool's result that holds a secret is withheld and replaced by its masked text, so the stored error record is masked too.
  - the file Claude Code saves a large Bash output to (`tool-results/` in the session folder): the mod masks that file in place after the tool runs. It rewrites only a file whose resolved path lies directly in this session's own `tool-results` folder; anything else (a symbolic link out of it, another session's folder) is left alone and logged. A saved file it can't mask in place is replaced by the withheld marker instead: Claude Code refuses a plugin's read or write over 4 MiB, so an output file over 4 MiB, or one whose masked text grows past 4 MiB, is withheld, not masked (the model's inline preview of the output is still masked). If even the marker can't be written, the whole tool result is withheld.
  - messages sent to other agents or sessions (`session.send`).
  - the first message's context blocks (`prompt.context`: CLAUDE.md and the like), only when a secret is found there.
- **Placeholders** are stable per secret for as long as the mod stays loaded, are made of ASCII word characters (inert if they ever reach a shell unrestored), and carry the kind of secret so the model knows what it holds.
- **Restores** placeholders in tool-call input just before the tool runs:

  | Tool | Fields restored |
  | --- | --- |
  | Bash, PowerShell, Monitor | `command` |
  | Write, Edit, NotebookEdit | `content`, `old_string`, `new_string`, `new_source`, only when `restoreIntoFiles` is on (default off: a placeholder is written to the file as is) |
  | MCP tools (`mcp__*`) | every string argument, only when `restoreInMcp` is on (default off) |
  | Agent, Task, SendMessage, everything else | never |

  If a restored field holds anything shaped like a placeholder (`__SECRET_..._<8 hex>__`) that the mod can't resolve (from before a reload or restart, an older version, or made up), the call is denied with a reason that says so. A tool result that echoes a restored secret is masked again, to the same placeholder.
- **The mapping** (secret to placeholder) lives in the mod's own memory only. It is never written to disk, `$.state`, `$.store`, logs, status lines, command output or deny reasons. A hot reload, a restart or `--resume` drops it: placeholders already in the conversation then can't be restored, and calls that need them are denied. `/clear` keeps it.
- **If masking fails** (a bug, or more than 10,000 distinct secrets in one load), nothing is stored raw: the tool result is withheld (the model reads a fixed `[secret-mask: text withheld because masking failed]`, and the stored record holds the same), a row or attachment holds that marker, a prompt is dropped with a message, and a saved output file is overwritten with the marker (so is one that can't be read or written back; if that write fails too, the tool result is withheld).
- **Off** (`/secret-mask off`) stops masking new content. Placeholders already issued are still restored, so work in flight doesn't run commands with placeholder text.
- **Costs** no model calls and no tokens beyond the placeholders themselves. It runs one `/usr/bin/env -0` at session start and on reload. Each row and tool result is scanned with regular expressions in the mod's process; large outputs take proportionally longer.

## What gets masked

Secrets come from three sources, in this order of trust. Anything not listed here is out of contract: the mod does not look for it, and a miss there is a missing feature, not a bug in a listed format.

### 1. Known values

Exact strings, masked wherever they appear, also inside a larger token.

- **Your environment.** At session start and on reload the mod reads Claude Code's own environment once (it runs `/usr/bin/env -0`). A variable counts when its name matches `(KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH|CREDENTIAL|PRIVATE|OAUTH)` followed by `_` or the end of the name, case-insensitive (`GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `PGPASSWORD`, `NPM_AUTH`), and its value is at least 8 characters. The password of a connection URL in any variable's value (`DATABASE_URL=postgres://app:<password>@db/app`) counts too, as written and percent-decoded, if it is at least 8 characters. The placeholder's kind is `ENV_` and the variable's name (`__SECRET_ENV_GITHUB_TOKEN_3F9A1C7E__`). This over-matches on purpose (`SSH_AUTH_SOCK`'s socket path is masked too): the values are exact, so the round trip is lossless. The values stay in the mod's memory like every other secret; if the environment can't be read, `/secret-mask status` says so and the other sources still work.
- **Your patterns file.** Exact values listed under `secrets` (see [Patterns file](#patterns-file)), at least 8 characters.
- **Discovered values.** Whatever sources 2 and 3 find becomes a known value: its bare copies are masked in the same tool result or row and in every later one.

### 2. Known token formats

Anchored on the vendor's prefix or shape, anywhere in any text: AWS access key IDs (`AKIA`, `ASIA`, `ABIA`, `ACCA`), GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), GitLab (`glpat-`), Slack tokens (`xox?-`) and webhook URLs, Anthropic (`sk-ant-`) and OpenAI (`sk-`, `sk-proj-`) keys, Stripe keys (`sk_live_`, `rk_test_`, ...) and webhook secrets (`whsec_`), SendGrid keys (`SG.<22>.<43>`), Google API keys (`AIza`), npm (`npm_`), Hugging Face (`hf_`), JWTs, PEM private key blocks, the token after `Bearer `, and the password in a URL (`scheme://user:<password>@`, also percent-decoded). A prefix must not follow a letter or digit (`xghp_...` is not a token), but may follow `_`, `-`, `=` or `/`.

### 3. Secret-named assignments, in these formats only

A name counts when its final segment, split on `_`, `.`, `-` and camelCase, is `password`, `passwd`, `pwd`, `secret`, `token`, `key`, `apikey`, `credential(s)`, `auth` or `passphrase`, or ends with one of the longer words (`PGPASSWORD`, `refreshtoken`). Leading underscores are part of the name. So `DB_PASSWORD`, `api_key`, `GITHUB_TOKEN`, `clientSecret`, `aws_secret_access_key`, `aws_session_token`, `_PASSWORD` and `_authToken` count; `token_count`, `_token_count`, `token_kind`, `password_hint`, `GITHUB_TOKEN_PATH` and `token_expiry_seconds` don't. Names ending in `key` that hold no secret (`sort_key`, `cache_key`) are masked too. A value counts when it is at least 8 characters and is not a reference or filler: `$VAR`, `${VAR}`, `${{ expression }}`, `{{ template }}`, `<placeholder>`, or one character repeated (`********`).

Each format has its own parser and its own value boundary. The line formats match only at the start of a line, after indentation and an optional YAML list dash (`- `):

| Format | Line | Value |
| --- | --- | --- |
| dotenv, shell, `.properties`, TOML | `NAME=value`, `export NAME=value`, `declare -x NAME="value"`, `NAME = value` | `"double"` (backslash escapes) or `'single'` quoted: the quoted text, whole. Unquoted: to the end of the line or a ` #` comment, trailing spaces dropped; a `}` or `,` inside is part of it. When an unquoted value holds a space, its first shell word (up to a space or `;` `&` `\|` `<` `>` `(` `)`) is registered as well, for `NAME=value command ...` lines. |
| INI, credentials files, `.npmrc` | `name = value`, `//registry.example/:_authToken=value` | As for dotenv. Covers `~/.aws/credentials` (`aws_secret_access_key`, `aws_session_token`). |
| YAML | `name: value`, `"name": value`, `- name: value` | `"double"` or `'single'` quoted: the quoted text. Plain: to the end of the line or a ` #` comment. An `&anchor` before the value is skipped. Block scalars (`\|`, `>`), tags (`!Ref x`), aliases (`*x`) and flow collections (`{...}`, `[...]`) are not read. After a quoted key (a JSON-style line in text that isn't JSON as a whole) a plain value drops one trailing `,`. |
| JSON | the whole text, a line (NDJSON), the rest of a line from its first `{` or `[`, or the text from its first line that starts with `{` or `[`, whichever `JSON.parse` accepts | A string or a number directly under a secret-named key, or in an array directly under one, at any depth. A string is registered as written in the text and as decoded; a number as its exact source text. Each string value in the document is also read with the line formats (`"Env": ["DB_PASSWORD=..."]`). Text that doesn't parse gets no JSON handling; the line formats still apply to it. |
| Command-line flags | `--name=value`, `--name value`, anywhere in a line | Quoted: the quoted text. Unquoted: one shell word. A value after a space must not start with `-`. Names starting `no-` are flags, not assignments. |

The minimum of 8 characters applies to a JSON number's source text as well, so a short numeric PIN (`"pin_token": 1234`) is not masked. In the line formats an unquoted value that is a call or subscript (`token = tokens[i]`, `password: getPassword(),`) is code, not a secret, and is left alone.

**Out of contract:** assignments in the middle of a line (`curl ... -d password=x`, URL query strings, log lines like `user=x password=y`), single-dash flags (`-pPASSWORD`, `-u user:pass`), HTTP headers other than `Authorization: Bearer` unless they start a line (`X-Api-Key: ...` does), XML, `.netrc` and `.pgpass` lines, multi-line YAML or dotenv values, code assignments other than calls and subscripts at the start of a line (`password = self.password` reads as INI and is masked), and any generic "looks random" detection. Add a pattern or a value to your patterns file for anything here that matters to you.

There is no generic keyword or entropy rule beyond the formats above: the model must still be able to read identifiers like `token_expiry_seconds` and ordinary config.

## What it does not cover

These routes reach the model, the screen or the disk without passing through anything a mod can rewrite. A secret there is not masked.

- **`@file` attachments on disk.** The model reads the masked text, but Claude Code keeps its own record of the attachment as made, and the API gives a mod no way to rewrite it. Checked live on 2.1.310: the transcript held the raw value in the attachment row's payload (`attachment.content.file.content`) and in the transcript's record of the request (an `api-request-blob` row holding the attachment's rendering). Requests built from that record (compaction, `$.model.fork`) and other plugins reading `$.session.messages` may get the raw text (not checked). So by default (`refuseSecretMentions`) the mod refuses an `@`-mention of a text file that holds a secret it can detect, before the file is read, and says to read it with a tool (`cat`, Read) instead, whose output is masked. That check does not cover formats the patterns miss (the file is then attached raw), media files (images and PDFs are not scanned), a file that changes between the check and the read, or a managed plugin that skips the hook. A text file the mod can't read, can't inspect for any reason other than its being missing, or over 5 MB, is refused.
- **The screen before the rewrite.** Claude Code may draw a row just before `session.append` rewrites it, and streams the model's reply as it is written. The structured tool result is masked before it is drawn (checked live, see below).
- **What runs with the real value.** Restoring happens before Claude Code's permission check, so the permission prompt, the auto-mode classifier (a model) and PreToolUse hooks see the restored command, and so does the process: a command that writes the secret to a file writes the real value. A command that transforms the secret (`base64`, `rev`, splitting it) prints a form no pattern recognises. Masking keeps a secret from being read in plain sight; it does not stop a model that sets out to reveal it.
- **Thinking and tool-use blocks** are pinned by the engine and can't be rewritten. The model can only write what it has read, so this matters only for a secret that came in by an uncovered route.
- **Images, PDFs and other media** are not scanned.
- **The system prompt and tool descriptions** are not scanned.
- **History loaded by `--resume`, teleport or a saved subagent transcript** is not re-scanned.
- **Large outputs of tools other than Bash.** Claude Code saves an output too large to keep inline to a file before any hook runs. The mod masks the file a Bash (or MCP raw output) result names; another tool's saved file is left as written.
- **Managed plugins seated above it.** An organization's plugin in the `prepend` tier runs before every user plugin and can pass an event on past them. On the machine this was checked on, a managed plugin did that for `prompt.context` (every session), for one row appended at startup, and in one review run for `prompt.attachment`, so the model then read an `@file` raw. The debug log names each case: `secret-mask: ... bypassed by <plugin>`, and Claude Code shows `its <event> hook was skipped`.
- **Slash-command arguments** reach the command unmasked (its rows in the conversation are masked). The prompt-history line (up-arrow) is not verified.
- **Discovery is not retroactive across rows.** A value is learned when a pattern first finds it (environment and patterns-file values are known from the start). A bare copy stored in an earlier row (before it was found) stays raw in that row; copies after it are masked. Within one row or one tool result, every copy is masked.
- **A literal reserved token blocks a command.** Anything shaped like a placeholder (`__SECRET_<KIND>_<8 hex>__`) that this load didn't issue is denied in a restored field, so an ordinary command that mentions one, such as searching a file for a placeholder string, is denied without running.
- **Secrets split by line wraps or across blocks**, values shorter than the thresholds, unusual encodings, and anything [out of contract](#3-secret-named-assignments-in-these-formats-only).
- **Other plugins** can see and reintroduce secrets, and nothing protects you when the mod is off, fails to load, or is skipped.

### Cut from v0.1

- Masking the model's streamed reply (`turn.step`). The model only writes what it read, so this matters only for secrets that came in by an uncovered route.
- Masking slash-command arguments at `command.run` and skill bodies at `skill.prompt` (their rows are masked at `session.append`).
- A reveal command, friendly labels in placeholders, and placeholders that stay the same across restarts.
- Not verified: whether masking a Read result changes how a later Edit of the same file checks what was read; the prompt-history (up-arrow) line.

## Command

`/secret-mask [on|off|status|test]`

- `status` (the default): whether masking is on and why, how many known values were loaded from the environment and the patterns file (or why the environment could not be read), how many distinct secrets were masked by kind, and how many masks, restores and denials happened since the mod loaded. Never values.
- `on` / `off`: set masking for this session; overrides the `enabled` option.
- `test`: runs built-in canary secrets (obviously fake) and your patterns file through the same masking and restoring code the hooks use, on a scratch mapping, and reports what was masked, what round-tripped and which near-misses were left alone.

## Options

| Option | Default | What it does |
| --- | --- | --- |
| `enabled` | `true` | Mask in new sessions. `/secret-mask on\|off` overrides it per session. |
| `restoreIntoFiles` | `false` | Also restore placeholders into Write, Edit and NotebookEdit content, which writes the real secret into the file. |
| `restoreInMcp` | `false` | Also restore placeholders into MCP tool arguments. |
| `refuseSecretMentions` | `true` | While masking is on, refuse an `@`-mention of a text file holding a detectable secret (see below). |
| `patternsFile` | `~/.config/secret-mask/patterns.json` | Your own patterns, exact values and allow-list. A missing file is fine; an invalid one is reported by `status` and `test`. |

## Patterns file

JSON, outside any repository:

```json
{
  "patterns": [
    { "name": "internal-token", "regex": "itk_[A-Za-z0-9]{32}" },
    { "name": "db-password", "regex": "DB_PASS=(\\S{8,})", "group": 1 }
  ],
  "secrets": [
    { "name": "staging-db", "value": "an-exact-secret-value" }
  ],
  "allow": ["a-literal-value-that-is-not-secret"],
  "allowPatterns": ["^sk_test_"]
}
```

- `patterns`: `name` (it becomes the placeholder's kind: uppercased, other characters turned to `_`, at most 24 characters, and it must start with a letter; a name that can't is refused and reported), `regex`, optional `flags` (`i`, `m`, `s`, `u`) and `group` (mask only that capture group). A pattern that can match an empty string is refused.
- `secrets`: exact values, masked wherever they appear. `name` is optional (it becomes the kind, as for patterns; `SECRET` without one); `value` must be at least 8 characters and must not contain `__SECRET_`. A value that can't be used is refused and reported.
- `allow`: exact values never masked, from any source (an environment value included). `allowPatterns`: values matching any of these are never masked.

The file is read at session start and on reload.

## Live checks

Checked on Claude Code 2.1.310 with `claude -p --plugin-dir . --model haiku` and one interactive session driven through a pty, using the fake key `AKIAFAKEFAKEFAKE0000` in a file:

- **What the model saw:** `cat creds.txt` came back as `aws_access_key_id = __SECRET_AWS_KEY_ID_4C05790D__`, and the model repeated the placeholder.
- **What ran:** the model ran `printf '%s\n' __SECRET_AWS_KEY_ID_4C05790D__ > ran.txt`; `ran.txt` held `AKIAFAKEFAKEFAKE0000`. Its `cat ran.txt` came back masked again.
- **What the transcript stored:** no copy of the key anywhere in the transcript file: tool_use inputs hold the placeholder (the model's own words), tool_result rows and the `toolUseResult` records hold the masked output, the prompt row and queue records hold the masked prompt. The same held for the `stream-json` output and the debug log.
- **What the screen showed:** the Bash row drew `aws_access_key_id=__SECRET_AWS_KEY_ID_4C99A82F__`; the raw key appeared nowhere in the bytes the terminal received.
- **Errors and large outputs:** before the fix, a failing command's error record and a large output's saved file kept the raw key; both are masked now (re-checked live).
- **Unknown placeholder:** `echo __SECRET_AWS_KEY_ID_DEADBEEF__` was denied with the reason above and did not run.
- `/secret-mask status` and `/secret-mask test` ran in the interactive session; the self-test passed.
- **After review fixes:** a file holding `password: ...`, a quoted value with spaces, and one value both before and after its `OTHER_SECRET=` assignment came back fully masked in the model's copy and in the stored `toolUseResult` (the same placeholder for every copy). A large output's saved file in this session's `tool-results` folder was still rewritten masked. An `@file` mention reached the model masked; its raw record on disk is described above.
- **Round-2 fixes:** with `refuseSecretMentions` on, `@creds.txt` was refused before it was read: the transcript held no attachment row and no copy of the key, and the model read the file with Read instead and saw the placeholder. Ordinary metrics JSON (`token_count`, `token_kind`, `password_hint`) came back through Bash unchanged, and the model's Write of it was byte-for-byte valid JSON. A patterns file naming a pattern `1FAKE` was reported as refused by `/secret-mask test` (which then fails), its other pattern still masked, and `echo __SECRET_1FAKE_00000001__` was denied without running.

## Install

```sh
claude plugin marketplace add chrisvaillancourt/claude-secret-mask
claude plugin install secret-mask@secret-mask --scope user
```

Or from inside Claude Code: `/plugin install secret-mask --marketplace chrisvaillancourt/claude-secret-mask`.

To work on it locally, add your clone as the marketplace instead (`claude plugin marketplace add <path to clone>`). The plugin is read from that folder; after editing, run `/reload-plugins`.

## Update

```sh
claude plugin marketplace update secret-mask
claude plugin update secret-mask@secret-mask
```

Then restart Claude Code.

## Develop

```sh
scripts/check.sh
```

It runs `claude plugin validate .`, `claude plugin test .` and a TypeScript check. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).

## License

MIT. See [LICENSE](LICENSE).
