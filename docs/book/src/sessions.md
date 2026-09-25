# Sessions

A session is a live shell that outlives a single tool call. The agent opens one,
runs as many commands as it likes against it (state carries over), and closes it.

## The tools

| Tool | Arguments | Returns |
|---|---|---|
| `session_create` | `transport` (`"local"` / `"ssh"` / `"docker"`) plus transport options (see [Transports](./transports.md)); optional `allow` / `deny` lists; optional `output_budget` | `{ "session_id": "..." }` |
| `session_exec` | `session_id`, `command`, optional `budget`, optional `timeout_secs` | structured `ExecResult` |
| `session_list` | none | `[{ session_id, transport, idle_secs }]` |
| `session_destroy` | `session_id` | `{ "destroyed": true }` |

Remote sessions add `session_checkpoint`, `session_checkpoints`, and
`session_restore`; see [Checkpoints](./checkpoints.md).

## State persists

Sessions are stateful. `cd`, exported variables, and shell state carry across
`session_exec` calls, the way a real terminal works:

```jsonc
// session_exec {"session_id":"a3f9-1_local","command":"cd /srv/app && export ENV=prod"}
// session_exec {"session_id":"a3f9-1_local","command":"pwd"}   -> stdout: "/srv/app"
// session_exec {"session_id":"a3f9-1_local","command":"echo $ENV"} -> stdout: "prod"
```

This is the difference between a shell and a series of unrelated strangers: an
agent that runs `cd packages/api` and then `npm test` gets the test run in
`packages/api`, not back in the home directory.

## Structured results

`session_exec` returns an `ExecResult` as JSON, not a blob:

```jsonc
// session_exec {"session_id":"a3f9-1_local","command":"npm run build"}
{
  "command": "npm run build",
  "stdout": "...",
  "stderr": "Error: Cannot find module 'webpack'",
  "exit_code": 1,
  "duration_ms": 3420,
  "cwd": "/home/u/app",
  "truncated": false,
  "timed_out": false
}
```

stdout and stderr are **split**, so the agent never has to guess whether output
was an error. The exit code is authoritative. Output is ANSI-stripped and
secret-redacted before it is returned, and bounded so one command cannot flood
the agent's context (see [Output budgets](./output-budgets.md)). When output was
cut and no budget was passed, the result also carries a `hint` saying a budget
would shape it.

## What a command can contain

Each command is sent to the shell base64-encoded and run with `eval`, so the text
reaches the shell exactly as written. Comments, a trailing `&`, heredocs, `!`,
tabs, very long commands and even syntax errors behave the way they would in a
terminal; none of them hang the session. The target needs `base64` on its `PATH`.

Commands are **non-interactive**. stdin is `/dev/null`, so anything that waits for
input (a password prompt, a REPL, an editor, a pager) gets end-of-file instead of
hanging. Use non-interactive flags: `sudo -n`, `apt-get -y`, `git --no-pager`.
Shell history is off, so commands are never written to a history file.

## Timeouts

Every `session_exec` has a timeout: `timeout_secs` on the call, or the operator
default `EXECKIT_MCP_EXEC_TIMEOUT` (120 seconds if unset). Both are clamped to
1-3600 seconds.

When a command runs past it, execkit sends Ctrl-C, waits for the shell to come
back, and returns a normal result:

```jsonc
// session_exec {"session_id":"a3f9-1_local","command":"sleep 30","timeout_secs":2}
{
  "command": "sleep 30",
  "stdout": "",
  "stderr": "execkit: timed out after 2s; sent Ctrl-C. The shell session is intact (cwd/env kept). ...",
  "exit_code": 124,
  "duration_ms": 2052,
  "cwd": "/tmp",
  "truncated": false,
  "timed_out": true
}
```

The session keeps its cwd and env and accepts the next command. Only a command
that ignores Ctrl-C ends the session (see below).

### Long-running jobs

For builds, test suites or deploys that may outlast the timeout, start the job in
the background and poll its log:

```jsonc
// session_exec {"session_id":"a3f9-1_local","command":"nohup make release > /tmp/release.log 2>&1 &"}
// session_exec {"session_id":"a3f9-1_local","command":"tail -n 20 /tmp/release.log"}
```

The first call returns at once. Later calls read the log. The job keeps running
between calls because the session's shell stays open.

## When a session closes on its own

The server closes a session and frees its slot when:

- the shell exits, because a command ran `exit` or a failing command hit `set -e`;
- a timed-out command ignores Ctrl-C, so the shell can no longer be trusted to
  frame output correctly;
- it sits idle past the TTL (below).

The `session_exec` that caused it returns a tool error that says the session was
closed. After that, any call with the old id returns
`unknown session_id '...'; call session_list to see live sessions`. The agent can
call `session_list` at any time to see which sessions are open and how long each
has been idle.

## Session ids are self-identifying

Ids read as `<run>-<n>_local`, `<run>-<n>_ssh_<user>@<host>[:port]`, or
`<run>-<n>_docker_<container>`, for example `a3f9-1_local`. `<run>` is a short
random prefix for each server process, so ids from different runs are unlikely to
collide in a shared audit directory. The rest keeps logs and the
[watch viewer](./auditing-and-watch.md) legible at a glance. Agent-provided host/user/container names are sanitized
before they appear in an id or a filename.

## Lifecycle and limits

Sessions are reaped when idle (default 30 minutes) to free the process and a slot
against the concurrent-session cap (default 64). Both are operator-tunable; see
the [Security model](./security-model.md). Always `session_destroy` when done.
