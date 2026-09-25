# Wiring into an agent

`execkit-mcp` is a stdio MCP server. You register the installed binary with your
client once, and the agent gains `session_create`, `session_exec`, and the rest.

The fastest path is to let execkit print the exact config with the binary's
absolute path already filled in:

```bash
execkit-mcp setup claude     # or: cursor | gemini | codex | vscode | windsurf
```

It prints a ready-to-use block (and, for Claude Code, the one-line command). It
deliberately does not edit your client's config file for you, so it can never
corrupt one; you paste the block into the right place.

## Zero-install with uv

If you have [uv](https://docs.astral.sh/uv/), skip the install and let the client
start execkit through `uvx`. This block works in any client that uses the
`mcpServers` format:

```json
{
  "mcpServers": {
    "execkit": { "command": "uvx", "args": ["execkit-mcp"] }
  }
}
```

Don't run `setup` through `uvx`: the path it prints points into uv's cache.

## Claude Code

One command:

```bash
claude mcp add execkit -- execkit-mcp        # add `-s user` to enable it everywhere
```

## Cursor, Gemini CLI and Windsurf

Cursor reads `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project), Gemini CLI
reads `~/.gemini/settings.json`, and Windsurf reads
`~/.codeium/windsurf/mcp_config.json`. Add the same block to any of them:

```json
{
  "mcpServers": {
    "execkit": { "command": "execkit-mcp" }
  }
}
```

If the binary is not on the client's `PATH`, use the absolute path that
`execkit-mcp setup` printed.

## Codex CLI and VS Code

These use different formats. Codex reads TOML from `~/.codex/config.toml`:

```toml
[mcp_servers.execkit]
command = "execkit-mcp"
```

VS Code reads `.vscode/mcp.json` in the workspace, with a `servers` key:

```json
{
  "servers": {
    "execkit": { "type": "stdio", "command": "execkit-mcp" }
  }
}
```

`execkit-mcp setup codex` and `execkit-mcp setup vscode` print these with the
absolute path filled in.

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
