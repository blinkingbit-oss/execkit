# Python SDK

`execkit-py` wraps the same Rust core with a Python API, published to PyPI as
`execkit`.

```bash
pip install execkit
```

```python
from execkit import Session, Policy

with Session.local(policy=Policy(deny=["rm"])) as s:
    r = s.exec("echo hi; echo err >&2; cd /tmp")
    print(r.stdout, r.exit_code, r.cwd, r.stderr)   # hi 0 /tmp err
```

The result object mirrors the Rust `ExecResult`: `command`, split `stdout` /
`stderr`, `exit_code`, `duration_ms`, `cwd`, `truncated` and `timed_out`, already
ANSI-stripped and secret-redacted. State persists across `exec` calls on the same
session.

## Timeouts

`timeout=` on a session constructor sets the default per-command timeout in
seconds (30 if omitted); `exec(cmd, timeout=...)` overrides it for one call:

```python
with Session.local(timeout=60) as s:
    r = s.exec("sleep 10", timeout=1)
    print(r.timed_out, r.exit_code)   # True 124
    print(s.exec("echo still here").stdout)
```

A timed-out command is interrupted with Ctrl-C and the session keeps going. Only
a command that ignores Ctrl-C raises `execkit.Timeout`; a command that exits the
shell raises `execkit.ShellExited`. Both are subclasses of `SessionUnusable`: open
a new session after either. `s.is_poisoned` tells you the same thing.

stdin is closed, so commands that would prompt get end-of-file instead of
hanging. Use non-interactive flags such as `sudo -n`.

## Other transports

SSH and Docker sessions work through `Session.ssh(...)` / `Session.docker(...)`
with the same options as [Transports](./transports.md). Output budgets are
keyword arguments (`tail`, `head`, `grep`, `max_chars`) on the session
constructors and on `exec`. Checkpoints are not exposed in the Python SDK yet;
use the Rust library or the MCP server for those.

Wheels ship for Linux and macOS, so no Rust toolchain is needed to install.
