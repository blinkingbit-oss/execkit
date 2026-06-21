# Auditing and the watch viewer

execkit can record everything an agent does in the shell, and let you watch it
live.

## The audit log

Point the server at a destination and every `open` / `exec` / `close` event is
appended as JSON, with the session id, transport, an epoch-millisecond timestamp,
and the command plus its (redacted, bounded) output.

- `EXECKIT_MCP_AUDIT=/var/log/execkit.jsonl` writes one shared file for all
  sessions.
- `EXECKIT_MCP_AUDIT_DIR=/var/log/execkit/` writes one file per session, named
  `<session_id>-<open_ms>.jsonl`. This mode takes precedence when both are set.
- `EXECKIT_MCP_AUDIT_RETENTION_DAYS` (default 14, `0` disables) prunes per-session
  files older than N days at startup. Files with a future-skewed mtime are never
  deleted.

The audit destination is operator-chosen and never a tool argument, so an
injected agent cannot redirect or suppress it.

## The watch viewer

Point `watch` at the audit file or directory from another terminal:

```bash
execkit-mcp watch /var/log/execkit.jsonl   # or: execkit-mcp watch  (uses $EXECKIT_MCP_AUDIT)
execkit-mcp watch /var/log/execkit/        # a directory; uses $EXECKIT_MCP_AUDIT_DIR
```

It is a live, read-only TUI: the agent's sessions on the left, the selected
session's shell transcript on the right (prompt, command, stdout, stderr in red,
exit status), rendered like a normal shell rather than JSON. Switch sessions with
`1`-`9` or the arrow keys, scroll with PgUp/PgDn, quit with `q`. It only ever
reads the log. Because the data comes from the server, it works the same under
any MCP client.

### Headless follow mode

For a pipeable, no-TTY view, use `--follow` instead of the TUI. It prints each
command and its output as a line prefixed with the session id, as it happens:

```bash
execkit-mcp watch --follow /var/log/execkit/
# [1_local] /home/u $ npm run build
# [1_local] x exit 1  (3420ms)
# [2_ssh_deploy@web-01] /srv $ systemctl restart app
```

## Live notifications in the client

Even with no audit log configured, the server streams each command to the MCP
client as it runs, so a host agent can surface its own shell activity without
anyone opening a separate terminal. Every `session_exec` emits:

- a **log notification** (`notifications/message`) carrying the full shell
  transcript, `info` on success and `warning` on a non-zero exit; and
- a **progress notification** (`notifications/progress`) with a one-line summary,
  when the call supplied a `progressToken`.

This reveals nothing new: the client already receives the same output in the tool
result, redacted and bounded. How the activity is surfaced is up to the client.
