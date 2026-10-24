# secret-mask

A Claude Code mod (function-hook plugin) for reversible secret masking. Secrets in what reaches the model (tool output above all) are replaced with stable placeholders such as `__SECRET_AWS_KEY_ID_3F9A1C7E__`. When the model uses a placeholder in a shell command, the mod puts the real value back just before the command runs. The model can work with a credential it never reads.

This is masking on the paths the mod API lets a plugin rewrite, not a vault or an exfiltration firewall. Read [What it does not cover](#what-it-does-not-cover) before you rely on it.

## Behavior

- **Detects** well-known token formats: AWS access key IDs, GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), GitLab, Slack tokens and webhooks, Anthropic and OpenAI keys, Stripe, Google API keys, npm, Hugging Face, JWTs, PEM private key blocks, `Authorization: Bearer` values and passwords in URLs. It also masks the value of an assignment whose name contains `secret`, `token`, `password`, `passwd`, `passphrase`, `pwd`, `api_key`, `access_key`, `private_key`, `credential`, `auth_key` or `signing_key` (`password: ...`, `token=...`, `AWS_SECRET_ACCESS_KEY=...`, `"api_token": "..."`) when the value is at least 8 characters. A quoted value is taken whole, spaces and commas included. The only values left alone are references and filler: `$VAR`, `${VAR}`, `{{ template }}`, `<placeholder>`, and one character repeated (`********`). Names like `tokenizer=...` are masked too: the rule errs toward masking. You can add your own patterns and an allow-list in a file outside the repo (see [Patterns file](#patterns-file)). There is no generic entropy detector.
- **Masks** in the main conversation and in subagents:
  - every row the conversation keeps (`session.append`, all doors: your prompt, tool results, deliveries from other agents and sessions, hook context, compaction summaries, the model's own text). Attachment rows are the exception: see the next point and [What it does not cover](#what-it-does-not-cover). This is what the model reads and what the transcript file stores.
  - what the model reads for each injected attachment (`prompt.attachment`): a file you mention with `@`, reminders, a settings hook's context. Checked live: the model quoted an `@file` line as a placeholder.
  - the prompt as you submit it (`prompt.submit`), so the queued record matches.
  - the tool's structured result (`tool.call`), which the screen draws and the transcript stores beside the model's copy. A failed tool's result that holds a secret is withheld and replaced by its masked text, so the stored error record is masked too.
  - the file Claude Code saves a large Bash output to (`tool-results/` in the session folder): the mod masks that file in place after the tool runs. It rewrites only a file whose resolved path lies directly in this session's own `tool-results` folder; anything else (a symbolic link out of it, another session's folder) is left alone and logged.
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

  If a restored field holds a placeholder the mod can't resolve (from before a reload or restart), the call is denied with a reason that says so. A tool result that echoes a restored secret is masked again, to the same placeholder.
- **The mapping** (secret to placeholder) lives in the mod's own memory only. It is never written to disk, `$.state`, `$.store`, logs, status lines, command output or deny reasons. A hot reload, a restart or `--resume` drops it: placeholders already in the conversation then can't be restored, and calls that need them are denied. `/clear` keeps it.
- **Off** (`/secret-mask off`) stops masking new content. Placeholders already issued are still restored, so work in flight doesn't run commands with placeholder text.
- **Costs** no model calls and no tokens beyond the placeholders themselves. Each row and tool result is scanned with regular expressions in the mod's process; large outputs take proportionally longer.

## What it does not cover

These routes reach the model, the screen or the disk without passing through anything a mod can rewrite. A secret there is not masked.

- **`@file` attachments on disk.** The model reads the masked text, but Claude Code keeps its own record of the attachment as made, and the API gives a mod no way to rewrite it. Checked live on 2.1.310: the transcript held the raw value in the attachment row's payload (`attachment.content.file.content`) and in the transcript's record of the request (an `api-request-blob` row holding the attachment's rendering). Requests built from that record (compaction, `$.model.fork`) and other plugins reading `$.session.messages` may get the raw text (not checked). To keep a secret file off disk, have the model read it with a tool (`cat`, Read) instead of mentioning it.
- **The screen before the rewrite.** Claude Code may draw a row just before `session.append` rewrites it, and streams the model's reply as it is written. The structured tool result is masked before it is drawn (checked live, see below).
- **What runs with the real value.** Restoring happens before Claude Code's permission check, so the permission prompt, the auto-mode classifier (a model) and PreToolUse hooks see the restored command, and so does the process: a command that writes the secret to a file writes the real value. A command that transforms the secret (`base64`, `rev`, splitting it) prints a form no pattern recognises. Masking keeps a secret from being read in plain sight; it does not stop a model that sets out to reveal it.
- **Thinking and tool-use blocks** are pinned by the engine and can't be rewritten. The model can only write what it has read, so this matters only for a secret that came in by an uncovered route.
- **Images, PDFs and other media** are not scanned.
- **The system prompt and tool descriptions** are not scanned.
- **History loaded by `--resume`, teleport or a saved subagent transcript** is not re-scanned.
- **Large outputs of tools other than Bash.** Claude Code saves an output too large to keep inline to a file before any hook runs. The mod masks the file a Bash (or MCP raw output) result names; another tool's saved file is left as written.
- **Managed plugins seated above it.** An organization's plugin in the `prepend` tier runs before every user plugin and can pass an event on past them. On the machine this was checked on, the organization's built-in plugin did that for `prompt.context` (every session) and for one row appended at startup, so neither reached this mod. The debug log names each case: `secret-mask: ... bypassed by <plugin>`, and Claude Code shows `its <event> hook was skipped`.
- **Slash-command arguments** reach the command unmasked (its rows in the conversation are masked). The prompt-history line (up-arrow) is not verified.
- **Secrets split by line wraps or across blocks**, values shorter than the thresholds, unusual encodings, and formats the patterns don't know.
- **Other plugins** can see and reintroduce secrets, and nothing protects you when the mod is off, fails to load, or is skipped.

### Cut from v0.1

- Masking the model's streamed reply (`turn.step`). The model only writes what it read, so this matters only for secrets that came in by an uncovered route.
- Reading secret values from environment variables by name (`$.env.get` needs literal names, so this would be a fixed list). `env` and `printenv` output is covered by the assignment rule; a bare `printenv SOME_SECRET` of a format no pattern knows is not.
- Masking slash-command arguments at `command.run` and skill bodies at `skill.prompt` (their rows are masked at `session.append`).
- A reveal command, friendly labels in placeholders, and placeholders that stay the same across restarts.
- Not verified: whether masking a Read result changes how a later Edit of the same file checks what was read; the prompt-history (up-arrow) line.

## Command

`/secret-mask [on|off|status|test]`

- `status` (the default): whether masking is on and why, how many distinct secrets were masked by kind, and how many masks, restores and denials happened since the mod loaded. Never values.
- `on` / `off`: set masking for this session; overrides the `enabled` option.
- `test`: runs built-in canary secrets (obviously fake) and your patterns file through the same masking and restoring code the hooks use, on a scratch mapping, and reports what was masked, what round-tripped and which near-misses were left alone.

## Options

| Option | Default | What it does |
| --- | --- | --- |
| `enabled` | `true` | Mask in new sessions. `/secret-mask on\|off` overrides it per session. |
| `restoreIntoFiles` | `false` | Also restore placeholders into Write, Edit and NotebookEdit content, which writes the real secret into the file. |
| `restoreInMcp` | `false` | Also restore placeholders into MCP tool arguments. |
| `patternsFile` | `~/.config/secret-mask/patterns.json` | Your own patterns and allow-list. A missing file is fine; an invalid one is reported by `status` and `test`. |

## Patterns file

JSON, outside any repository:

```json
{
  "patterns": [
    { "name": "internal-token", "regex": "itk_[A-Za-z0-9]{32}" },
    { "name": "db-password", "regex": "DB_PASS=(\\S{8,})", "group": 1 }
  ],
  "allow": ["a-literal-value-that-is-not-secret"],
  "allowPatterns": ["^sk_test_"]
}
```

- `patterns`: `name` (letters, digits, `-` and `_`; it becomes the placeholder's kind), `regex`, optional `flags` (`i`, `m`, `s`, `u`) and `group` (mask only that capture group). A pattern that can match an empty string is refused.
- `allow`: exact values never masked. `allowPatterns`: values matching any of these are never masked.

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
