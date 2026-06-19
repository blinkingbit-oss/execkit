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
s.destroy()
```

The result object mirrors the Rust `ExecResult`: split `stdout` / `stderr`,
`exit_code`, `duration_ms`, `cwd`, and `truncated`, already ANSI-stripped and
secret-redacted. State persists across `exec` calls on the same session.

SSH and Docker sessions, output budgets, and checkpoints map onto the same
methods described in [Sessions](./sessions.md), [Transports](./transports.md),
[Output budgets](./output-budgets.md), and [Checkpoints](./checkpoints.md).

Wheels ship for Linux and macOS, so no Rust toolchain is needed to install.
