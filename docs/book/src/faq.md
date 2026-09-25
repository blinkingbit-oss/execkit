# FAQ

## Does execkit replace the agent's built-in shell?

No. execkit is an MCP server: it **adds** tools (`session_create`, `session_exec`,
`session_destroy`, ...) to whatever the agent already has. It does not hook, wrap,
or intercept the client's native shell tool (Claude Code's `Bash`, for example).
After you wire it in, the agent's tool list is "native tools **plus** execkit's
tools." Both are live at once.

## Should I use execkit instead of my agent's built-in sandbox?

Use both. A built-in shell or sandbox is the right tool for quick local commands
in the project the agent is working on. execkit adds what those usually don't
have: sessions on remote hosts over SSH and inside Docker containers, a JSONL
audit trail with a live viewer, redacted and budgeted output, and checkpoints you
can restore on remote workspaces. It is not a sandbox itself; see
[Security model](./security-model.md).

## How does the agent decide to use execkit instead of running commands locally?

It is the model choosing from its tool list; there is no automatic rerouting. The
choice is driven by:

- **Tool descriptions and the server's instructions.** execkit ships an
  instructions string ("call `session_create` to get a session, `session_exec` to
  run commands...") that tells the model what the tools are for.
- **Your project instructions** (for example `CLAUDE.md`).
- **The task.** For anything the native shell cannot do (SSH to a remote host,
  exec inside a Docker container, a session with persistent `cwd`/`env`, workspace
  checkpoints), execkit is the only tool that can, so the model reaches for it. For
  a quick local command, the native shell is the path of least resistance unless
  you steer the model.

So out of the box, plugging in execkit makes it available, not mandatory.

## How do I make the agent always use execkit?

Three levels, weakest to strongest:

**1. Instruct it.** Add a line to `CLAUDE.md` (or the client's system/project
prompt): "Run all shell commands through the execkit session tools, not the
built-in shell." This steers the model; it does not guarantee.

**2. Remove the alternative.** Disable the client's built-in shell tool so execkit
is the only shell path the model has. In Claude Code, deny the `Bash` tool in
`settings.json`:

```json
{
  "permissions": {
    "deny": ["Bash"],
    "allow": ["mcp__execkit__*"]
  }
}
```

A **bare** tool name like `"Bash"` removes the tool from the model's context
entirely: the model never sees it and never attempts it. (This is different from a
**scoped** rule like `"Bash(rm *)"`, which leaves `Bash` available and only blocks
matching calls at execution time.) The `allow` line explicitly permits every
execkit tool so the model reaches for those instead. On Windows, also deny
`"PowerShell"`, the other built-in shell surface:

```json
{ "permissions": { "deny": ["Bash", "PowerShell"], "allow": ["mcp__execkit__*"] } }
```

For a one-session override instead of durable settings, use the CLI flag:
`claude --disallowedTools Bash`.

**3. Isolate at deployment.** Run the agent where it has no local shell to the
machine that matters, and only execkit's SSH/Docker transport reaches it. Now
execkit is not a preference. It is the only door.

## What do execkit's safety features actually cover?

Only commands that go **through** execkit. The audit log, secret redaction, the
`allow`/`deny` fence, and checkpoints apply to `session_exec` calls. If the agent
runs something via its own native shell, execkit never sees it. This is why
"make execkit the only path" (options 2 and 3 above) matters: enforcement comes
from removing the competing path, not from execkit trapping calls.

And even for commands it does see, the command fence is **advisory, not a
sandbox**: string matching is bypassable. The real boundary is the operating
system: a least-privilege user, a container, or a scoped SSH account. See the
[Security model](./security-model.md).

## Is any of this specific to Claude Code?

No. "MCP servers add capabilities; they do not hijack the host's existing tools"
is true of every MCP client. Only the step that disables the native shell is
client-specific; how the agent chooses a tool is the same everywhere.

## My command timed out. Is the session gone?

No. A command that runs past its timeout (120 seconds by default over MCP, or
`timeout_secs` on the call) is interrupted with Ctrl-C and returned with
`timed_out: true` and exit code 124. The session keeps its cwd and env. For jobs
that take longer, start them in the background and poll the log:

```bash
nohup ./long-job.sh > /tmp/job.log 2>&1 &
tail -n 20 /tmp/job.log
```

See [Sessions](./sessions.md#timeouts).

## Why can't I answer a prompt, use `sudo`, or open an editor?

Commands run with stdin set to `/dev/null`, so nothing can wait for keyboard
input. A prompt gets end-of-file and usually fails at once instead of hanging the
session. Use non-interactive forms: `sudo -n` (with a NOPASSWD rule for what the
agent may run), `apt-get -y`, `git --no-pager`, `GIT_EDITOR=true`.

## The agent says "unknown session_id". What happened?

The session was closed: the agent destroyed it, the shell exited (`exit`, or a
failing command under `set -e`), a timed-out command ignored Ctrl-C, or it was
idle past `EXECKIT_MCP_SESSION_TTL`. The agent can call `session_list` to see
which sessions are open, and `session_create` to start a new one.
