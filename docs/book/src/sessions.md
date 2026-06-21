# Sessions

A session is a live shell that outlives a single tool call. The agent opens one,
runs as many commands as it likes against it (state carries over), and closes it.

## The tools

| Tool | Arguments | Returns |
|---|---|---|
| `session_create` | `transport` (`"local"` / `"ssh"` / `"docker"`) plus transport options (see [Transports](./transports.md)); optional `allow` / `deny` lists; optional `output_budget` | `{ "session_id": "..." }` |
| `session_exec` | `session_id`, `command`, optional `budget` | structured `ExecResult` |
| `session_destroy` | `session_id` | `{ "destroyed": true }` |

Remote sessions add `session_checkpoint`, `session_checkpoints`, and
`session_restore`; see [Checkpoints](./checkpoints.md).

## State persists

Sessions are stateful. `cd`, exported variables, and shell state carry across
`session_exec` calls, the way a real terminal works:

```jsonc
// session_exec {"session_id":"1_local","command":"cd /srv/app && export ENV=prod"}
// session_exec {"session_id":"1_local","command":"pwd"}   -> stdout: "/srv/app"
// session_exec {"session_id":"1_local","command":"echo $ENV"} -> stdout: "prod"
```

This is the difference between a shell and a series of unrelated strangers: an
agent that runs `cd packages/api` and then `npm test` gets the test run in
`packages/api`, not back in the home directory.

## Structured results

`session_exec` returns an `ExecResult` as JSON, not a blob:

```jsonc
// session_exec {"session_id":"1_local","command":"npm run build"}
{
  "stdout": "...",
  "stderr": "Error: Cannot find module 'webpack'",
  "exit_code": 1,
  "duration_ms": 3420,
  "cwd": "/home/u/app",
  "truncated": false
}
```

stdout and stderr are **split**, so the agent never has to guess whether output
was an error. The exit code is authoritative. Output is ANSI-stripped and
secret-redacted before it is returned, and bounded so one command cannot flood
the agent's context (see [Output budgets](./output-budgets.md)).

## Session ids are self-identifying

Ids read as `<n>_local`, `<n>_ssh_<user>@<host>[:port]`, or
`<n>_docker_<container>`, so logs and the [watch viewer](./auditing-and-watch.md)
are legible at a glance. Agent-provided host/user/container names are sanitized
before they appear in an id or a filename.

## Lifecycle and limits

Sessions are reaped when idle (default 30 minutes) to free the process and a slot
against the concurrent-session cap (default 64). Both are operator-tunable; see
the [Security model](./security-model.md). Always `session_destroy` when done.
