# Security model

The agent driving these tools can be prompt-injected, so execkit treats every
tool **argument** as untrusted. Anything dangerous to the host or filesystem is
controlled by the **operator at startup** through environment variables, never by
a per-call agent argument. An injected agent cannot change where the audit log is
written, which directory SSH keys come from, or the session limits.

## Operator settings

| Env var | Purpose | Default |
|---|---|---|
| `EXECKIT_MCP_AUDIT` | append a JSONL audit log of every command here | off |
| `EXECKIT_MCP_AUDIT_DIR` | one JSONL file per session in this directory (`<session_id>-<open_ms>.jsonl`); takes precedence over `EXECKIT_MCP_AUDIT` | off |
| `EXECKIT_MCP_AUDIT_RETENTION_DAYS` | delete per-session log files older than N days at startup (dir mode only); `0` disables | `14` |
| `EXECKIT_MCP_EXEC_TIMEOUT` | default `session_exec` timeout in seconds (clamped 1-3600); `timeout_secs` overrides per call | `120` |
| `EXECKIT_MCP_KEY_DIR` | SSH keys must canonicalize to inside this dir; its `config` file supplies `Host` aliases | `~/.ssh` |
| `EXECKIT_MCP_KNOWN_HOSTS` | execkit-managed SSH host-key verification file (TOFU; rejects changed keys) | `~/.execkit/known_hosts` |
| `EXECKIT_MCP_INSECURE_ACCEPT_ANY_HOSTKEY` | **DANGEROUS** disable host-key checks | unset |
| `EXECKIT_MCP_MAX_SESSIONS` | soft cap on concurrent live sessions | `64` |
| `EXECKIT_MCP_SESSION_TTL` | reap sessions idle longer than N seconds; `0` disables | `1800` |
| `EXECKIT_MCP_POLICY_FILE` | JSON `allow`/`deny` (program names) + `deny_patterns` (regex) the agent cannot edit; advisory | off |

`EXECKIT_MCP_KEY_DIR` and `EXECKIT_MCP_KNOWN_HOSTS` default off the home
directory, which resolves by priority (`$HOME`, then the passwd database), so the
defaults are correct even when `$HOME` is unset. Run `execkit-mcp doctor` to see
what each one resolves to on your machine.

## What is enforced where

- **Host keys are verified by default** (TOFU against `known_hosts`; a changed key
  is rejected as a likely MITM). Pin an exact key with `fingerprint`, or set the
  insecure env var only for throwaway hosts.
- **`key_path` is sandboxed** to `EXECKIT_MCP_KEY_DIR`; traversal or out-of-bounds
  paths are rejected with a generic error that does not leak path existence.
- **The audit destination is operator-chosen**, never a tool argument, so an
  injected agent cannot write to arbitrary files.
- **Docker** sessions reach any container the daemon can see. Grant Docker access
  deliberately and scope the context.
- The server speaks MCP on **stdout**; all diagnostics go to **stderr**.

## Secret redaction

Output (stdout and stderr), the echoed `command` field, the audit log and the
live notifications are all redacted before they leave execkit. Matches become
`[REDACTED]`. Redaction runs before output budgets, so a secret cannot survive by
being cut in half.

| Covered | Examples |
|---|---|
| AWS access key ids | `AKIA...` |
| GitHub tokens | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_` |
| GitLab personal access tokens | `glpat-...` |
| Slack tokens | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` |
| Stripe live secret keys | `sk_live_...` |
| Google API keys | `AIza...` |
| Anthropic API keys | `sk-ant-...` |
| OpenAI-style keys | `sk-...`, `sk-proj-...` (32+ characters) |
| JSON Web Tokens | `eyJ....eyJ....sig` |
| PEM private keys | the whole `-----BEGIN ... PRIVATE KEY-----` block, not just the header |
| Passwords in URLs | `postgres://user:[REDACTED]@db` (user and host are kept) |
| Bearer tokens | `Authorization: Bearer [REDACTED]` (the word `Bearer` is kept; tokens of 16+ characters) |
| Secret-named `key=value` / `key: value` pairs | `password`, `passwd`, `secret`, `token`, `api_key`, `access_key`, `private_key`, including prefixed names like `DB_PASSWORD` or `AWS_SECRET_ACCESS_KEY` (values of 4+ characters that end at whitespace, a quote, the end of the line or one of `;&\|)`; a comma does not end a value, so a trailing `,` is redacted with it) |
| Values the session assigned to secret-named variables | after `export DB_PASS=hunter2hunter2`, the literal `hunter2hunter2` is redacted wherever it appears later in that session (names containing `token`, `secret`, `passw`, `api_key`, `private_key`, `credential` or `auth`; values of 6+ characters) |

| Not covered | Why |
|---|---|
| Arbitrary high-entropy strings | no fixed shape; matching them would redact hashes, ids and base64 data too |
| Encoded, reversed or split secrets | `base64`, `rev` or `cut` output no longer has the shape |
| Secrets with no recognisable shape and no secret-named variable | for example a password printed from a file the session never assigned |
| Values assigned outside the session | a variable set in a login profile or by another process is not learned |
| Secret-named values that look like code | a value containing `(`, `<`, `[` or `{`, or running into one (`token: Option<String>`, `access_key = cfg.get("x")`), is left alone so source code stays readable; a real password containing those characters is missed too |

Redacted output is not file-accurate. Redaction can also hit ordinary code: a
secret-named field with a bare identifier as its value, such as TypeScript
`password: string`, comes back as `password: [REDACTED]`. Never write command
output back to a file (for example `cat`-ing a file and saving what came back);
edit files in place with `sed`, `patch` or similar instead.

Redaction is a safety net for accidental leaks, not a guarantee. An agent that
wants to exfiltrate a secret can encode it first. Keep secrets the agent should
not see out of the environment it can reach.

## The fence is advisory, not a sandbox

`allow` / `deny` command lists are defense in depth, not a jail. Matching on
command strings is trivially bypassable (`env rm`, `$(echo rm)`, base64,
`bash -c "..."`). Name matching looks at the first word of each pipeline segment,
so `deny: ["curl"]` blocks `curl` and `/usr/bin/curl` but not `env curl` or
`sudo curl`. Treat the fence as a guardrail against accidents and obvious
mistakes. A denial names the rule or pattern that matched, so the agent can see
why a command did not run.

The real security boundary is the operating system: run the agent's shell as a
**least-privilege user**, in a **container**, or on a **scoped SSH account**, so
that even a fully compromised agent can only reach what that account can. execkit
gives you visibility and undo on top of that boundary; it does not replace it.

## Operator command policy

Point `EXECKIT_MCP_POLICY_FILE` at a JSON file to set an allow/deny fence the
agent cannot edit (unlike the per-call `allow`/`deny`, which the agent supplies):

```json
{
  "allow": ["git", "ls", "npm"],
  "deny": ["rm", "dd", "shutdown"],
  "deny_patterns": ["\\brm\\b", "kubectl\\s+delete", "git\\s+push\\s+.*--force"]
}
```

- `allow` (program names): if non-empty, only these may run. Empty/absent = all.
- `deny` (program names): always blocked; deny wins over allow.
- `deny_patterns` (regex over the whole command): for what names cannot express.

Prefer a `deny_pattern` over a name `deny` for anything that matters: name
matching only sees the program name per pipeline segment, so `deny: ["rm"]` misses
`sudo rm` and `xargs rm`, while `deny_patterns: ["\\brm\\b"]` catches them. In JSON
the regex backslashes double up (`\\b`); use `(?i)` for case-insensitive matching.

A blocked command never runs; it is recorded in the audit log, shown in `watch`,
and pushed to the client as a warning. This is an ADVISORY guardrail, not a
sandbox: string matching is trivially bypassable (`env rm`, base64, `bash -c`).
The real boundary is a least-privilege user, a container, or a scoped SSH account.
