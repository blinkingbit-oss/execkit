# Python SDK

`execkit-py` wraps the same Rust core with a Python API, published to PyPI as
`execkit`.

```bash
pip install execkit
```

```python
from execkit import Session, Policy

s = Session.local(policy=Policy(allow=[], deny=["rm"]))
r = s.exec("echo hi; echo err 1>&2; cd /tmp")
print(r.stdout, r.exit_code, r.cwd)   # "hi" 0 "/tmp"
s.close()
```

The result object mirrors the Rust `ExecResult`: split `stdout` / `stderr`,
`exit_code`, `duration_ms`, `cwd`, and `truncated`, already ANSI-stripped and
secret-redacted. State persists across `exec` calls on the same session.

SSH and Docker sessions work through `Session.ssh(...)` / `Session.docker(...)`
with the same options as [Transports](./transports.md). Output budgets are
keyword arguments (`tail`, `head`, `grep`, `max_chars`) on the session
constructors and on `exec`. Checkpoints are not exposed in the Python SDK yet;
use the Rust library or the MCP server for those.

Wheels ship for Linux and macOS, so no Rust toolchain is needed to install.
