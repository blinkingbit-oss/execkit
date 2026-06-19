# execkit

Stateful, structured, safe shell sessions for AI agents, on real infrastructure.

When you give an AI agent a raw shell, you get a black box: one-shot commands
with no memory between them, a wall of mixed stdout and stderr the agent has to
guess its way through, secrets landing in plaintext, no record of what ran, and
no way to undo a mistake. execkit replaces that with a session abstraction built
for agents.

- **Stateful sessions.** `cd` and environment persist across calls, like a real
  terminal, instead of every command starting fresh from home.
- **Structured results.** Each command returns split stdout/stderr, an exit code,
  duration, and cwd as data the agent can act on, not a blob to parse.
- **Safe by default.** Output is ANSI-stripped, secret-redacted, and bounded so a
  noisy build cannot blow the agent's context window or leak credentials.
- **Real transports.** Local shell, SSH, and Docker, with host-key verification
  and a sandboxed key directory.
- **Undo.** Git-backed workspace checkpoints let you snapshot before a risky
  change and restore on demand (files only, not side effects).
- **Observability.** An append-only audit log, a live read-only viewer, and live
  MCP notifications so you can watch what the agent does in the shell.

## Two ways to use it

- **As an MCP server** (`execkit-mcp`): a stdio [Model Context
  Protocol](https://modelcontextprotocol.io) server that any MCP-capable agent
  (Claude Code, Cursor, Gemini CLI, and others) can drive directly. Start at
  [Installation](./installation.md).
- **As a Rust library** (`execkit`): embed sessions in your own program. See the
  [Rust library](./rust-library.md) page. A [Python SDK](./python-sdk.md) wraps
  the same core.

## A note on safety

The agent driving these tools can be prompt-injected, so execkit treats every
tool argument as untrusted. Anything dangerous to the host is controlled by the
operator at startup (environment variables), never by a per-call agent argument.
The command allow/deny fence is advisory defense-in-depth, not a sandbox: the
real boundary is running the agent as a least-privilege user, in a container, or
on a scoped SSH account. See the [Security model](./security-model.md).

execkit is Apache-2.0 licensed. Source:
<https://github.com/blinkingbit-oss/execkit>.
