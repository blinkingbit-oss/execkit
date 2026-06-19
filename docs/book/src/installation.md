# Installation

`execkit-mcp` ships as a prebuilt binary. Pick whichever fits your toolchain:

```bash
pip install execkit-mcp      # a wheel; no Rust toolchain needed
cargo install execkit-mcp    # ...or via cargo
```

Building from source instead:

```bash
cargo build -p execkit-mcp --release   # binary at target/release/execkit-mcp
```

## Verify the install

```bash
execkit-mcp --version
execkit-mcp doctor
```

`doctor` reports what is configured and what is missing before you ever wire an
agent in: whether an audit destination is set and writable, where the SSH key
directory and `known_hosts` resolve to, and whether the Docker daemon is
reachable. A typical run:

```text
execkit-mcp 0.7.2
[ -- ] binary: /home/you/.cargo/bin/execkit-mcp

[ -- ] audit: off (set EXECKIT_MCP_AUDIT or EXECKIT_MCP_AUDIT_DIR to record + watch activity)
[ ok ] ssh key dir: /home/you/.ssh (override: EXECKIT_MCP_KEY_DIR)
[ ok ] known_hosts: /home/you/.ssh/known_hosts
[ ok ] docker: daemon reachable
```

Each `[warn]` or `[ -- ]` line tells you what to set. None of these are required
to start, they just enable optional features (auditing, SSH, Docker).

## Where the binary lives

`cargo install` puts it at `~/.cargo/bin/execkit-mcp`. If that is not on your MCP
client's `PATH`, use the full path when you register it (the next page shows how,
and `execkit-mcp setup` fills the absolute path in for you).

Next: [Wiring into an agent](./wiring-into-an-agent.md).
