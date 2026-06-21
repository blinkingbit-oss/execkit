# Rust library

The `execkit` crate is the core. The MCP server is a thin wrapper over it; you can
embed the same sessions directly in your own program.

```toml
[dependencies]
execkit = "0.7"                                          # local + SSH + Docker
# execkit = { version = "0.7", default-features = false } # local + Docker only (no SSH; drops russh/tokio)
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
duration, cwd), ANSI-stripped and secret-redacted.

SSH and Docker sessions are constructed with their configs:

```rust
use execkit::{Session, SshConfig, SshAuth, HostKeyVerification};

let cfg = SshConfig::new("web-01".into(), "deploy".into(),
    SshAuth::Password("...".into()),
    HostKeyVerification::KnownHosts("/home/me/.ssh/known_hosts".into()));
let mut s = Session::ssh(cfg)?;
```

The API surface stays small; the richness lives in the result, not the verbs:

```text
Session::local() / ::ssh(cfg) / ::docker(container)        -> Session
session.exec(command)                                      -> ExecResult
session.exec_budgeted(command, &budget)                    -> ExecResult
session.checkpoint(label?) / restore(id) / restore_last()  -> CheckpointId / restore report
```

Runnable examples live in the repository:

```bash
cargo run --example local
EXECKIT_SSH="user:password@host:22" cargo run --example ssh
```

Full API docs are on [docs.rs/execkit](https://docs.rs/execkit).
