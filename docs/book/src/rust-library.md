# Rust library

The `execkit` crate is the core. The MCP server is a thin wrapper over it; you can
embed the same sessions directly in your own program.

```toml
[dependencies]
execkit = "0.9"                                          # local + SSH + Docker
# execkit = { version = "0.9", default-features = false } # local + Docker only (no SSH; drops russh/tokio)
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

State persists across `exec` calls on the same `Session`, exactly as it does over
MCP. Results are the same structured `ExecResult` (split stdout/stderr, exit code,
duration, cwd, `truncated`, `timed_out`), ANSI-stripped and secret-redacted.

## Timeouts

Each `exec` has a timeout: 30 seconds by default. Change it with
`with_timeout` when building the session, `set_timeout` on a live one, or pass one
for a single call with `exec_with_timeout`:

```rust
use std::time::Duration;

let mut s = Session::local()?.with_timeout(Duration::from_secs(60));
let r = s.exec_with_timeout("sleep 30", None, Duration::from_secs(1))?;
assert!(r.timed_out);            // interrupted with Ctrl-C
assert_eq!(r.exit_code, 124);
assert_eq!(s.exec("echo still here")?.stdout, "still here");
```

A timed-out command is interrupted with Ctrl-C and returned as `Ok` with
`timed_out: true`; the session keeps its cwd and env. If the command ignores
Ctrl-C, `exec` returns `Error::StillRunning` and the session is poisoned: later
calls return `Error::SessionPoisoned` and `is_poisoned()` is true. A command that
exits the shell (`exit`, or a failure under `set -e`) returns `Error::ShellExited`
and poisons it the same way. Open a new session in either case.

## SSH and Docker

SSH and Docker sessions are constructed with their configs:

```rust
use execkit::{Session, SshConfig, SshAuth, HostKeyVerification};

let cfg = SshConfig::new("web-01", "deploy",
    SshAuth::Password("...".into()),
    HostKeyVerification::KnownHosts("/home/me/.execkit/known_hosts".into()));
let mut s = Session::ssh(cfg)?;
```

The known_hosts file uses execkit's own `host SHA256:<fingerprint>` format (keyed
`[host]:port` on ports other than 22), not OpenSSH's; use a file of its own.
`SshConfig::connect_timeout` (default 15 seconds) bounds the TCP connect, key
exchange and authentication together.

The API surface stays small; the richness lives in the result, not the verbs:

```text
Session::local() / ::ssh(cfg) / ::docker(container)        -> Session
session.exec(command)                                      -> ExecResult
session.exec_budgeted(command, &budget)                    -> ExecResult
session.exec_with_timeout(command, Option<&budget>, dur)   -> ExecResult
session.checkpoint(label?) / restore(id) / restore_last()  -> CheckpointId / restore report
```

Runnable examples live in the repository:

```bash
cargo run --example local
EXECKIT_SSH="user:password@host:22" cargo run --example ssh
```

Full API docs are on [docs.rs/execkit](https://docs.rs/execkit).
