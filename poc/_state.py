"""Capture / restore shell session state — basis for snapshot, fork, reconnect."""


def capture_state(session) -> dict:
    cwd = session.exec("pwd")["stdout"]
    env_out = session.exec("env")["stdout"]
    env = {}
    for line in env_out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if k.isidentifier():
                env[k] = v
    return {"cwd": cwd, "env": env}


def restore_state(session, state: dict, skip_keys=()):
    """Re-apply cwd + env into a fresh session (used by fork & reconnect)."""
    session.exec(f"cd {state['cwd']}")
    for k, v in state["env"].items():
        if k in skip_keys or v == "[REDACTED]":
            continue
        # only restore vars we explicitly care about in the PoC namespace
        if k.startswith("EXECKIT_"):
            session.exec(f"export {k}={v}")
