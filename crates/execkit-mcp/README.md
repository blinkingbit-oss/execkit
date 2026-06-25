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

Then check the install and your environment:

```bash
execkit-mcp --version
execkit-mcp doctor               # reports audit, SSH, and Docker readiness
```

## Wire it into an agent

`execkit-mcp` is a stdio MCP server - register the installed binary with your
client. The fastest way is to let it print the config with the right binary path
already filled in:

```bash
execkit-mcp setup claude         # or: cursor | gemini
```

(`cargo install` puts the binary at `~/.cargo/bin/execkit-mcp`; use the full path
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
| `EXECKIT_MCP_POLICY_FILE` | JSON `allow`/`deny` (program names) + `deny_patterns` (regex) the agent cannot edit; advisory | off |
| `EXECKIT_MCP_WATCH_WEB` | Start the read-only browser viewer (loopback + URL token) and surface its URL via an MCP notification; the URL is stable across restarts so an open tab reconnects | off |
| `EXECKIT_MCP_WATCH_PORT` | Port for the viewer (the URL must stay stable for reconnect); falls back to a random port if taken | 7878 |
| `EXECKIT_MCP_WATCH_OPEN` | Also auto-open the browser at the viewer URL (default: just show the link) | off |

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

### Live viewer in your browser

`execkit-mcp watch --serve [--open] <audit-file-or-dir>` serves the transcript as
a local web page (127.0.0.1 only, single-use URL token in the link). Add `--open`
to launch your browser at it. The MCP server also starts it automatically when
`EXECKIT_MCP_WATCH_WEB` is set (it prints the link and pushes it as a
notification; the link is stable across restarts so an open tab reconnects).

Reading the page:

- **Sidebar** - sessions grouped by transport (`local`, `ssh`, `docker`) in
  collapsible accordions. The number on a **group** header is the count of
  sessions in it (`ssh (2)`); the number on a **session** row is its **command
  count** - how many commands ran (`deploy@web-01 (7)`), with the exact count on
  hover. The active session is highlighted with a dot.
- **Transcript colors** (legend in the header): the prompt line `cwd $ command`
  is cyan (`cmd`), stdout is default (`out`), stderr and failing exits are red
  (`err`), a clean exit is green (`ok`), and session/markers are dimmed. Each
  command shows its exit code and duration. **Click a legend item** to show/hide
  that line type (e.g. click `out` to hide stdout and skim just the commands and
  errors).
- **Search** - press `/` to find within the current transcript; matches are
  highlighted with a running `n / m` count, `Enter` / `Shift+Enter` (or the
  next/prev buttons) step through them, and `Esc` clears. Press `e` (or "next
  err") to jump to the next error/blocked line.
- **Bottom status bar** - the connection state (`connected` /
  `disconnected - retrying`) on the left. On the right it shows details of the
  currently selected session - its id, transport, command count, live/closed
  state, and absolute last-activity time - and stays there as you browse. Click
  it to copy the session id. An action (e.g. `Exported 1_local.md`, `Renamed
  to ...`, `Pinned to top`) flashes briefly, then the bar reverts to the
  session's details.
- **History** - past sessions from `EXECKIT_MCP_AUDIT_DIR` (one file per session)
  appear under "History", newest first, each with a relative time (`5m ago`;
  hover for the absolute last-activity timestamp); click one to view its
  transcript read-only. The list and last-activity times refresh automatically.
  Requires dir-mode auditing; with a single `EXECKIT_MCP_AUDIT` file there is no
  per-session history.
- **Per-session actions** (the 3-dots menu on a row): **Rename** (inline edit; a
  display alias only), **Pin** to the top, **Keep** (retain in history past the
  trim limit), **Export** to `.txt` / `.log` / `.md` / `.json`, and
  **Screenshot** to `.png`.

Renames, pins, keeps, and the sidebar width persist in `~/.execkit/viewer-state.json`
(mode 0600). That file is the viewer's only write surface: it holds display
metadata only and can never affect a session, command, or the audit log. The page
itself is read-only - it only reads the audit stream and that one metadata file.

### In the agent's client (no terminal, no audit log)

The server also pushes each command to your MCP client as it runs, as standard
MCP notifications - so a host agent can show its own shell activity live without
anyone opening a `watch` terminal. Every `session_exec` emits:

- a **log notification** (`notifications/message`) carrying the full shell
  transcript - `info` on success, `warning` on a non-zero exit; and
- a **progress notification** (`notifications/progress`) with a one-line summary,
  when the client supplied a `progressToken` for the call.

This needs no `EXECKIT_MCP_AUDIT*` setup - the server advertises the `logging`
capability and streams unconditionally. It reveals nothing new: the client
already receives the same stdout/stderr in the tool result, redacted and bounded.
How (or whether) the activity is surfaced is up to the client.

## Operator command policy (advisory)

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

Apache-2.0.
