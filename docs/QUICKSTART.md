# Quickstart

Two ways to use execkit: as an **MCP server** an AI agent drives directly, or as a
**Rust or Python library**.

## A) Drive it from an AI agent (MCP)

### 1. Install

Zero-install with [uv](https://docs.astral.sh/uv/): nothing to install up front.
Put this block in your MCP client config and the client starts execkit through
`uvx`:

```json
{
  "mcpServers": {
    "execkit": { "command": "uvx", "args": ["execkit-mcp"] }
  }
}
```

Or install the server (a wheel; no Rust toolchain needed):

```bash
pip install execkit-mcp
```

### 2. Wire it into your client

`setup` prints the config for your client with the binary's absolute path filled
in. It prints and does not edit files, so paste the block where it says:

```bash
execkit-mcp setup claude     # or: cursor | gemini | codex | vscode | windsurf
```

For Claude Code this is one command:

```bash
claude mcp add execkit -- execkit-mcp        # add `-s user` to enable it everywhere
```

(With the `uvx` block above you can skip this step. Don't run `setup` through
`uvx`: it would print a path inside uv's cache.)

### 3. Check your environment

```bash
execkit-mcp doctor
```

`doctor` reports the audit destination, the SSH key directory, execkit's
`known_hosts` file, Docker reachability and the operator policy, and tells you
which env var to set for anything that is off.

The agent now has `session_create` -> `session_exec` -> `session_destroy`, plus
`session_list` and `session_checkpoint`/`session_checkpoints`/`session_restore`
for remote workspace undo. `session_exec` returns a structured result (split
stdout/stderr, exit code, cwd, `timed_out`), already secret-redacted and bounded.
See [`crates/execkit-mcp/README.md`](../crates/execkit-mcp/README.md) for the
operator security settings (host-key verification, key dir, audit, limits).

## B) Use it as a library

### Python

```bash
pip install execkit
```

```python
from execkit import Session

with Session.local() as s:
    r = s.exec("echo hi; echo err >&2; cd /tmp")
    print(r.stdout, r.exit_code, r.cwd, r.stderr)   # hi 0 /tmp err
```

### Rust

```toml
[dependencies]
execkit = "0.9"                                   # local + SSH + Docker
# execkit = { version = "0.9", default-features = false }  # local + Docker only (no SSH; no russh/tokio)
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

## Other ways to install the server

```bash
# prebuilt binary (Linux/macOS, x86_64 + arm64):
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/blinkingbit-oss/execkit/releases/latest/download/execkit-mcp-installer.sh | sh

# with cargo:
cargo install execkit-mcp
```

### Build from source

```bash
cargo build -p execkit-mcp --release     # binary at target/release/execkit-mcp
target/release/execkit-mcp setup claude  # prints config with this binary's path
```

Runnable library examples from a checkout:

```bash
cargo run --example local
EXECKIT_SSH="user:password@host:22" cargo run --example ssh
```

See [`README.md`](../README.md) for the full picture.
