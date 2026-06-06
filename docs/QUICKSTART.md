# Quickstart

Two ways to use execkit: as a **Rust library**, or as an **MCP server** an AI agent
drives directly.

## A) Drive it from an AI agent (MCP)

Build the server and point your agent at it.

```bash
cargo build -p execkit-mcp --release
```

Add to your MCP client config (Claude Code, Cursor, Gemini CLI):

```json
{
  "mcpServers": {
    "execkit": { "command": "/path/to/target/release/execkit-mcp" }
  }
}
```

The agent now has three tools: `session_create` -> `session_exec` -> `session_destroy`.
`session_exec` returns a structured result (split stdout/stderr, exit code, cwd),
already secret-redacted and bounded. See [`crates/execkit-mcp/README.md`](../crates/execkit-mcp/README.md)
for the operator security settings (host-key verification, key dir, audit, limits).

## B) Use it as a Rust library

```toml
[dependencies]
execkit = "0.1"                                   # local + SSH + Docker
# execkit = { version = "0.1", default-features = false }  # local + Docker only (no SSH; no russh/tokio)
```

```rust
use execkit::{Session, Policy};

fn main() -> Result<(), execkit::Error> {
    let mut s = Session::local()?
        .with_policy(Policy { allow: vec![], deny: vec!["rm".into()] });

    let r = s.exec("echo hi; echo err 1>&2; cd /tmp")?;
    // r.stdout == "hi", r.stderr == "err", r.exit_code == 0, r.cwd == "/tmp"

    println!("{} (exit {})", r.stdout, r.exit_code);
    Ok(())
}
```

Runnable examples:

```bash
cargo run --example local
EXECKIT_SSH="user:password@host:22" cargo run --example ssh
```

## What you get

- **Persistent, stateful sessions** - `cd`/env stick across commands.
- **Structured `ExecResult`** - stdout/stderr split, exit code, duration, cwd.
- **Safe by default** - advisory command fence, secret redaction, bounded output,
  SSH host-key verification.
- **One API, many transports** - local PTY, SSH, and Docker; same `ExecResult`.

See [`README.md`](../README.md) for the full picture.
