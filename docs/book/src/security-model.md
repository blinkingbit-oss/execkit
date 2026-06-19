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
| `EXECKIT_MCP_KEY_DIR` | SSH `key_path` must canonicalize to inside this dir | `~/.ssh` |
| `EXECKIT_MCP_KNOWN_HOSTS` | SSH host-key verification file (TOFU; rejects changed keys) | `~/.ssh/known_hosts` |
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

## The fence is advisory, not a sandbox

`allow` / `deny` command lists are defense in depth, not a jail. Matching on
command strings is trivially bypassable (`/bin/rm`, `$(echo rm)`, base64,
`bash -c "..."`). Treat the fence as a guardrail against accidents and obvious
mistakes.

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
sandbox: string matching is trivially bypassable (`/bin/rm`, base64, `bash -c`).
The real boundary is a least-privilege user, a container, or a scoped SSH account.
