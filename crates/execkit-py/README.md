# execkit (Python)

Stateful, structured, **safe** shell sessions for AI agents - over local shells,
SSH, and Docker. Native bindings to the [execkit](https://github.com/blinkingbit-oss/execkit)
Rust core.

```bash
pip install execkit
```

```python
import execkit
from execkit import Session, Policy

with Session.local(policy=Policy(deny=["rm"]), timeout=30.0) as s:
    r = s.exec("cd /app && npm ci")
    print(r.stdout, r.exit_code, r.cwd)
```

State (cwd, env) persists across `exec` calls. Every result is a structured
`ExecResult` (split stdout/stderr, exit code, cwd, duration), already
secret-redacted and output-bounded. Commands pass an advisory policy fence first.

Async callers: `r = await asyncio.to_thread(s.exec, "npm ci")` (the native call
releases the GIL).

Unix-only (local sessions need a POSIX shell). See the project README for the
full picture and the operator security model.

## License

Apache-2.0.
