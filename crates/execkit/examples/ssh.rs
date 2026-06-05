// SPDX-License-Identifier: Apache-2.0
//! A persistent SSH session with host-key verification.
//!
//! Run: `EXECKIT_SSH="user:password@host:port" cargo run --example ssh`
//!
//! Host keys are verified (TOFU) against a known_hosts file; a changed key is
//! rejected as a likely MITM.

use execkit::{HostKeyVerification, Session, SshAuth, SshConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let spec =
        std::env::var("EXECKIT_SSH").map_err(|_| "set EXECKIT_SSH=\"user:password@host:port\"")?;
    let (creds, hostport) = spec.split_once('@').ok_or("expected user:pass@host:port")?;
    let (user, password) = creds.split_once(':').ok_or("expected user:password")?;
    let (host, port) = hostport.split_once(':').ok_or("expected host:port")?;

    let mut cfg = SshConfig::new(
        host,
        user,
        SshAuth::Password(password.to_string()),
        HostKeyVerification::KnownHosts("/tmp/execkit_known_hosts".into()),
    );
    cfg.port = port.parse()?;

    let mut session = Session::ssh(cfg)?;
    let r = session.exec("uname -a; whoami; pwd")?;
    println!("{}", r.stdout);

    // State persists over SSH, just like a local terminal left open.
    session.exec("cd /tmp")?;
    println!("cwd is now: {}", session.exec("pwd")?.cwd);

    Ok(())
}
