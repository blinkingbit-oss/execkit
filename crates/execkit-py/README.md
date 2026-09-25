# execkit (Python)

Stateful, structured, **safe** shell sessions for AI agents - over local shells,
SSH, and Docker. Native bindings to the [execkit](https://github.com/blinkingbit-oss/execkit)
Rust core.

```bash
pip install execkit
```

```python
from execkit import Session

with Session.local() as s:
    r = s.exec("echo hi; echo err >&2; cd /tmp")
    print(r.stdout, r.exit_code, r.cwd, r.stderr)   # hi 0 /tmp err
```

State (cwd, env) persists across `exec` calls. Every result is a structured
`ExecResult` (split stdout/stderr, exit code, cwd, duration, `truncated`,
`timed_out`), already secret-redacted and output-bounded. Pass a `Policy` for an
advisory command fence: `Session.local(policy=Policy(deny=["rm"]))`.

## Timeouts

`Session.local(timeout=...)` sets the default per-command timeout in seconds, and
`exec(cmd, timeout=...)` overrides it for one call. A command that outlives it is
interrupted with Ctrl-C and returned with `timed_out=True` and `exit_code == 124`.
The session keeps its cwd and env:

```python
with Session.local() as s:
    r = s.exec("sleep 10", timeout=1)
    print(r.timed_out, r.exit_code)   # True 124
```

Only a command that ignores Ctrl-C raises `execkit.Timeout` and leaves the session
unusable. stdin is closed, so commands that prompt get end-of-file instead of
hanging; use non-interactive flags such as `sudo -n`.

Async callers: `r = await asyncio.to_thread(s.exec, "npm ci")` (the native call
releases the GIL).

Unix-only (local sessions need a POSIX shell). See the project README for the
full picture and the operator security model.

## License

Apache-2.0.
