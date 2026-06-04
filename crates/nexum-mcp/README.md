# nexum-mcp

An [MCP](https://modelcontextprotocol.io) server (stdio) that exposes
[`nexum`](../nexum) shell sessions to any MCP-capable agent — Claude Code,
Cursor, Gemini CLI, and others.

## Tools

| Tool | Args | Returns |
|---|---|---|
| `session_create` | `transport` (`"local"`/`"ssh"`), and for ssh: `host`, `user`, `password` or `key_path`, optional `port`; optional `allow`/`deny` command lists, `audit_path` | `{ "session_id": "..." }` |
| `session_exec` | `session_id`, `command` | structured `ExecResult` JSON: `stdout`, `stderr` (split!), `exit_code`, `duration_ms`, `cwd`, `truncated` |
| `session_destroy` | `session_id` | `{ "destroyed": true }` |

Sessions are **stateful** — `cd`/env persist across `session_exec` calls. Output
is ANSI-stripped, secret-redacted, and bounded; commands pass the optional policy
fence before running.

## Install

```bash
cargo install nexum-mcp        # or build from source: cargo build -p nexum-mcp
```

## Wire it into an agent

**Claude Code / Cursor / Gemini CLI** — add to your MCP config (e.g.
`~/.config/claude/mcp.json` or the client's MCP settings):

```json
{
  "mcpServers": {
    "nexum": {
      "command": "nexum-mcp"
    }
  }
}
```

Then the agent can call `session_create` → `session_exec` → `session_destroy`.

## Example session (what the agent sees)

```jsonc
// session_create {"transport":"local"}              -> {"session_id":"sess_1"}
// session_exec   {"session_id":"sess_1","command":"npm run build"}
//   -> {"stdout":"…","stderr":"Error: Cannot find module 'webpack'",
//       "exit_code":1,"duration_ms":3420,"cwd":"/home/u/app","truncated":false}
```

## Security notes

- The server speaks MCP on **stdout**; all diagnostics go to **stderr**.
- For SSH, `session_create` currently uses a permissive host-key policy
  (`AcceptAny`) for convenience — pin a known-hosts file before using it against
  hosts you care about (planned). Run the agent and SSH user with least privilege.
- Use `allow`/`deny` and `audit_path` for a basic safety + audit posture.

Apache-2.0.
