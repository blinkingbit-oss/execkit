# CLI reference

`execkit-mcp` with no arguments is the stdio MCP server an agent launches.
Everything below is for a human at a terminal.

## Commands

```text
execkit-mcp                          Run the MCP server on stdio (default)
execkit-mcp setup <client>           Print the config to wire execkit into a client
                                     client: claude | cursor | gemini
execkit-mcp doctor                   Check the local environment and print a report
execkit-mcp watch [--follow] <path>  Live, read-only viewer over the audit log
execkit-mcp --version                Print version
execkit-mcp --help                   Print help
```

### `setup <client>`

Prints a ready MCP config block with this binary's absolute path filled in, and
for Claude Code the `claude mcp add` one-liner. It prints rather than edits your
client's live config, so it cannot corrupt one. See
[Wiring into an agent](./wiring-into-an-agent.md).

### `doctor`

Reports the resolved audit destination and its writability, the SSH key directory
and `known_hosts` (with the env var that overrides each), and whether the Docker
daemon is reachable. Use it after install to catch setup problems before an agent
connects. See [Installation](./installation.md).

### `watch [--follow] <path>`

A live read-only viewer over the audit log; a file or a directory. `--follow`
gives a headless, pipeable stream instead of the TUI. See
[Auditing and the watch viewer](./auditing-and-watch.md).

## Environment

These configure the server (operator-controlled, not agent arguments). Full table
and rationale on the [Security model](./security-model.md) page.

```text
EXECKIT_MCP_AUDIT                  Append a JSONL audit log of every command here
EXECKIT_MCP_AUDIT_DIR             One JSONL file per session in this directory
EXECKIT_MCP_AUDIT_RETENTION_DAYS  Prune per-session files older than N days (default 14)
EXECKIT_MCP_KEY_DIR               Directory SSH keys must live under (default ~/.ssh)
EXECKIT_MCP_KNOWN_HOSTS           SSH known_hosts file (default ~/.ssh/known_hosts)
EXECKIT_MCP_MAX_SESSIONS          Soft cap on concurrent live sessions (default 64)
EXECKIT_MCP_SESSION_TTL           Reap sessions idle longer than N seconds (default 1800)
EXECKIT_MCP_POLICY_FILE           JSON allow/deny + deny_patterns the agent cannot edit (advisory)
```
