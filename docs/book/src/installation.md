# Installation

`execkit-mcp` ships as a prebuilt binary. Pick whichever fits your toolchain.

**Zero-install with uv.** Nothing to install up front: the MCP client starts
execkit through `uvx`, which fetches the PyPI package `execkit-mcp` on first use.
See [Wiring into an agent](./wiring-into-an-agent.md) for the config block. To try
it from a terminal:

```bash
uvx execkit-mcp --version
```

**Installed:**

```bash
pip install execkit-mcp      # a wheel; no Rust toolchain needed
cargo install execkit-mcp    # ...or via cargo
```

A prebuilt-binary installer script for Linux and macOS is attached to each
[GitHub release](https://github.com/blinkingbit-oss/execkit/releases).

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
directory and `known_hosts` resolve to, whether the Docker daemon is reachable,
and whether an operator policy file is loaded. A typical run:

```text
execkit-mcp 0.9.0
[ -- ] binary: /home/you/.cargo/bin/execkit-mcp

[ -- ] audit: off (set EXECKIT_MCP_AUDIT or EXECKIT_MCP_AUDIT_DIR to record + watch activity)
[ ok ] ssh key dir: /home/you/.ssh (override: EXECKIT_MCP_KEY_DIR)
[ -- ] known_hosts: /home/you/.execkit/known_hosts (absent; created on first SSH connect via TOFU)
[ ok ] docker: daemon reachable
[ -- ] policy: off (set EXECKIT_MCP_POLICY_FILE to enable)
```

Each `[warn]` or `[ -- ]` line tells you what to set. None of these are required
to start, they just enable optional features (auditing, SSH, Docker).

## Requirements on the target

Whatever the transport, the machine or container the agent works on needs a POSIX
shell and `base64` (part of coreutils and busybox). Checkpoints on SSH and Docker
sessions also need `git` there.

## Where the binary lives

`cargo install` puts it at `~/.cargo/bin/execkit-mcp`. If that is not on your MCP
client's `PATH`, use the full path when you register it (the next page shows how,
and `execkit-mcp setup` fills the absolute path in for you).

Next: [Wiring into an agent](./wiring-into-an-agent.md).
