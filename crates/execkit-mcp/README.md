# execkit-mcp

An [MCP](https://modelcontextprotocol.io) server (stdio) that exposes
[`execkit`](../execkit) shell sessions to any MCP-capable agent - Claude Code,
Cursor, Gemini CLI, and others.

## Tools

| Tool | Args | Returns |
|---|---|---|
| `session_create` | `transport` (`"local"`/`"ssh"`/`"docker"`); for ssh: `host`, `user`, `password` or `key_path`, optional `port`, `fingerprint` (pin host key); for docker: `container` (running name/id); optional `allow`/`deny` command lists | `{ "session_id": "..." }` |
| `session_exec` | `session_id`, `command`, optional `budget` (shape output: grep/tail/head/head_tail + max_chars) | structured `ExecResult` JSON: `stdout`, `stderr` (split!), `exit_code`, `duration_ms`, `cwd`, `truncated` |
| `session_destroy` | `session_id` | `{ "destroyed": true }` |
| `session_checkpoint` | `session_id`, optional `label` | `{ "checkpoint_id": "..." }` |
| `session_checkpoints` | `session_id` | `[{ id, label, created }]` |
| `session_restore` | `session_id`, optional `checkpoint_id` | `{ restored_to, files_changed }` |

Sessions are **stateful** - `cd`/env persist across `session_exec` calls. Output
is ANSI-stripped, secret-redacted, and bounded; commands pass the optional policy
fence before running.

## Checkpoints (remote only)

On SSH/Docker sessions execkit can snapshot the workspace before changing commands
and restore it on demand - a filesystem "undo." It undoes FILES only, never side
effects (DB writes, network, installs).

Two requirements: **`git` on the remote host**, and an explicit **`workspace`**.
Without a `workspace`, checkpoints and auto-snapshot are disabled - execkit will
**not** default to the cwd or home directory (snapshotting `$HOME` is slow and
would capture secrets). Set `workspace` to the project dir you want undo for (use
`$HOME` explicitly if you really mean it).

Control it via `session_create`:
- `workspace` (root - REQUIRED to enable checkpoints)
- `auto_snapshot` (default true; effective only with a workspace)
- `paths` (sub-dirs under the root)
- `checkpoint_ignores` (extra gitignore-style patterns; added to the built-in
  defaults: `.git`, `node_modules`, build dirs, caches, `.ssh`, `.aws`, ...)

If git is absent, auto-snapshot disables itself and checkpoint calls return a clear
"install git on the remote" error.

WARNING: `session_restore` is destructive. It reverts tracked files AND deletes ALL
untracked files and directories anywhere under the workspace (via git clean), not
only files created since the checkpoint. Do not restore if untracked files in the
workspace must be preserved.

## Output budgets

Pass `budget` to `session_exec` (or `output_budget` to `session_create` for a
session default) to shape output and protect the agent's context window:

```jsonc
// keep the last 200 lines of a noisy build
{ "session_id": "...", "command": "npm run build",
  "budget": { "keep": { "mode": "tail", "n": 200 } } }

// grep a 50k-line log for errors, with 2 lines of context
{ "session_id": "...", "command": "cat big.log",
  "budget": { "grep": { "pattern": "error|fail", "context": 2 } } }
```

Shaping is line-based, client-side, and runs AFTER secret redaction; it never
changes the exit code or side effects. When applied, the result includes a
`budget` report: per-stream `mode`, `lines_total`, `lines_kept`.

## Install

```bash
pip install execkit-mcp          # the server binary, shipped as a wheel (no Rust toolchain)
cargo install execkit-mcp        # ...or via cargo (or build from source: cargo build -p execkit-mcp)
```

## Wire it into an agent

`execkit-mcp` is a stdio MCP server - register the installed binary with your
client. (`cargo install` puts it at `~/.cargo/bin/execkit-mcp`; use the full path
if it isn't on the client's PATH.)

**Claude Code** - one command:

```bash
claude mcp add execkit -- execkit-mcp        # add `-s user` to enable it everywhere
```

**Cursor** (`~/.cursor/mcp.json`) and **Gemini CLI** (`~/.gemini/settings.json`) -
add the same block:

```json
{
  "mcpServers": {
    "execkit": { "command": "execkit-mcp" }
  }
}
```

To turn on auditing or other operator settings, add an `env` block:

```json
{
  "mcpServers": {
    "execkit": {
      "command": "execkit-mcp",
      "env": { "EXECKIT_MCP_AUDIT": "/var/log/execkit.jsonl" }
    }
  }
}
```

Then the agent can call `session_create` -> `session_exec` -> `session_destroy`.

## Example session (what the agent sees)

```jsonc
// session_create {"transport":"local"}              -> {"session_id":"1_local"}
// session_exec   {"session_id":"1_local","command":"npm run build"}
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
| `EXECKIT_MCP_AUDIT_DIR` | write one JSONL file per session into this directory (`<session_id>-<open_ms>.jsonl`); takes precedence over `EXECKIT_MCP_AUDIT` when both are set | off |
| `EXECKIT_MCP_AUDIT_RETENTION_DAYS` | delete per-session log files older than this many days at startup (dir mode only); `0` disables | `14` |
| `EXECKIT_MCP_KEY_DIR` | SSH `key_path` must canonicalize to inside this dir | `~/.ssh` |
| `EXECKIT_MCP_KNOWN_HOSTS` | SSH host-key verification file (TOFU; rejects changed keys) | `~/.ssh/known_hosts` |
| `EXECKIT_MCP_INSECURE_ACCEPT_ANY_HOSTKEY` | **DANGEROUS** - disable host-key checks | unset |
| `EXECKIT_MCP_MAX_SESSIONS` | soft cap on concurrent live sessions | `64` |
| `EXECKIT_MCP_SESSION_TTL` | reap sessions idle longer than this many seconds (frees the process + cap slot); `0` disables | `1800` (30 min) |

- **Host keys are verified by default** (TOFU against known_hosts; a changed key
  is rejected as a likely MITM). Pass a `fingerprint` to require an exact key, or
  set the insecure env var only for throwaway/test hosts.
- **`key_path` is sandboxed** to `EXECKIT_MCP_KEY_DIR`; out-of-bounds/traversal paths
  are rejected with a generic error (no path-existence leak).
- **Audit destination is operator-chosen**, never a tool argument (prevents an
  injected agent from writing to arbitrary files).
- **Docker** sessions run `docker exec` against any container the daemon can see,
  so the agent reaches whatever your `docker` context exposes. Grant the server
  Docker access only when you want that, and scope the daemon/context accordingly.
- The server speaks MCP on **stdout**; all diagnostics go to **stderr**.
- Use `allow`/`deny` for a command fence, and run the agent + SSH user with least
  privilege. The fence is advisory - defense in depth, not a sandbox.

## Watch live activity (read-only)

Point `EXECKIT_MCP_AUDIT` at a file, then watch it from another terminal:

```bash
execkit-mcp watch /var/log/execkit.jsonl   # or just: execkit-mcp watch  (uses $EXECKIT_MCP_AUDIT)
```

`watch` also accepts a directory - it tails every `*.jsonl` file in it and picks
up new session files as they appear:

```bash
execkit-mcp watch /var/log/execkit/        # or: execkit-mcp watch  (uses $EXECKIT_MCP_AUDIT_DIR)
```

`watch` is a live, read-only TUI: the agent's sessions on the left, the selected
session's shell transcript on the right (prompt, command, stdout, stderr in red,
exit status) - rendered like a normal shell, not JSON. Switch sessions with `1`-`9`
or the arrow keys, scroll with PgUp/PgDn, quit with `q`. It only ever reads the
log and never touches a session. Because the data comes from the server (not the
client), it works the same under any MCP client (Claude Code, Cursor, Gemini, ...).

For a headless or background view - no terminal required, pipeable - use
`--follow` instead of the TUI. It prints each command and its output as a line,
prefixed with the session id, as it happens:

```bash
execkit-mcp watch --follow /var/log/execkit/
# [1_local]              /home/u $ npm run build
# [1_local]              x exit 1  (3420ms)
# [2_ssh_deploy@web-01]  /srv $ systemctl restart app
```

Session ids are self-identifying - `<n>_local`, `<n>_ssh_<user>@<host>[:port]`,
or `<n>_docker_<container>` - so the audit filenames and the stream read clearly
at a glance.

Apache-2.0.
