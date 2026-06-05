# execkit-mcp

An [MCP](https://modelcontextprotocol.io) server (stdio) that exposes
[`execkit`](../execkit) shell sessions to any MCP-capable agent - Claude Code,
Cursor, Gemini CLI, and others.

## Tools

| Tool | Args | Returns |
|---|---|---|
| `session_create` | `transport` (`"local"`/`"ssh"`), and for ssh: `host`, `user`, `password` or `key_path`, optional `port`, `fingerprint` (pin host key); optional `allow`/`deny` command lists | `{ "session_id": "..." }` |
| `session_exec` | `session_id`, `command` | structured `ExecResult` JSON: `stdout`, `stderr` (split!), `exit_code`, `duration_ms`, `cwd`, `truncated` |
| `session_destroy` | `session_id` | `{ "destroyed": true }` |

Sessions are **stateful** - `cd`/env persist across `session_exec` calls. Output
is ANSI-stripped, secret-redacted, and bounded; commands pass the optional policy
fence before running.

## Install

```bash
cargo install execkit-mcp        # or build from source: cargo build -p execkit-mcp
```

## Wire it into an agent

**Claude Code / Cursor / Gemini CLI** - add to your MCP config (e.g.
`~/.config/claude/mcp.json` or the client's MCP settings):

```json
{
  "mcpServers": {
    "execkit": {
      "command": "execkit-mcp"
    }
  }
}
```

Then the agent can call `session_create` -> `session_exec` -> `session_destroy`.

## Example session (what the agent sees)

```jsonc
// session_create {"transport":"local"}              -> {"session_id":"sess_1"}
// session_exec   {"session_id":"sess_1","command":"npm run build"}
//   -> {"stdout":"...","stderr":"Error: Cannot find module 'webpack'",
//       "exit_code":1,"duration_ms":3420,"cwd":"/home/u/app","truncated":false}
```

## Security model

The agent driving these tools can be prompt-injected, so tool arguments are
**untrusted**. Anything dangerous to the host/filesystem is therefore controlled
by the **operator at startup** (env vars), not by per-call agent arguments:

| Env var | Purpose | Default |
|---|---|---|
| `EXECKIT_MCP_AUDIT` | append a JSONL audit log of every command here | off |
| `EXECKIT_MCP_KEY_DIR` | SSH `key_path` must canonicalize to inside this dir | `~/.ssh` |
| `EXECKIT_MCP_KNOWN_HOSTS` | SSH host-key verification file (TOFU; rejects changed keys) | `~/.ssh/known_hosts` |
| `EXECKIT_MCP_INSECURE_ACCEPT_ANY_HOSTKEY` | **DANGEROUS** - disable host-key checks | unset |

- **Host keys are verified by default** (TOFU against known_hosts; a changed key
  is rejected as a likely MITM). Pass a `fingerprint` to require an exact key, or
  set the insecure env var only for throwaway/test hosts.
- **`key_path` is sandboxed** to `EXECKIT_MCP_KEY_DIR`; out-of-bounds/traversal paths
  are rejected with a generic error (no path-existence leak).
- **Audit destination is operator-chosen**, never a tool argument (prevents an
  injected agent from writing to arbitrary files).
- The server speaks MCP on **stdout**; all diagnostics go to **stderr**.
- Use `allow`/`deny` for a command fence, and run the agent + SSH user with least
  privilege. The fence is advisory - defense in depth, not a sandbox.

Apache-2.0.
