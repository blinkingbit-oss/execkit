# Wiring into an agent

`execkit-mcp` is a stdio MCP server. You register the installed binary with your
client once, and the agent gains `session_create`, `session_exec`, and the rest.

The fastest path is to let execkit print the exact config with the binary's
absolute path already filled in:

```bash
execkit-mcp setup claude     # or: cursor | gemini
```

It prints a ready-to-use block (and, for Claude Code, the one-line command). It
deliberately does not edit your client's config file for you, so it can never
corrupt one; you paste the block into the right place.

## Claude Code

One command:

```bash
claude mcp add execkit -- execkit-mcp        # add `-s user` to enable it everywhere
```

## Cursor and Gemini CLI

Cursor reads `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project); Gemini CLI
reads `~/.gemini/settings.json`. Add the same block to either:

```json
{
  "mcpServers": {
    "execkit": { "command": "execkit-mcp" }
  }
}
```

If the binary is not on the client's `PATH`, use the absolute path that
`execkit-mcp setup` printed.

## Turning on operator settings

Anything that affects the host (auditing, SSH key location, session limits) is
configured by you, the operator, through environment variables in the client
config, not by the agent. Add an `env` block:

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

See the [Security model](./security-model.md) for the full list of settings and
why they live with the operator. Once wired, the agent calls `session_create` ->
`session_exec` -> `session_destroy`; see [Sessions](./sessions.md).
