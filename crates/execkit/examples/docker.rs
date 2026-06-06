// SPDX-License-Identifier: Apache-2.0
//! A persistent shell session inside a running Docker container.
//!
//! Run:
//!   docker run -d --name ek alpine sleep 600
//!   EXECKIT_DOCKER=ek cargo run --example docker
//!
//! Needs the `docker` CLI on PATH. Same structured ExecResult, policy, redaction,
//! and bounding as the local and SSH transports.

use execkit::Session;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let container =
        std::env::var("EXECKIT_DOCKER").map_err(|_| "set EXECKIT_DOCKER=<container name or id>")?;

    let mut session = Session::docker(&container)?;
    let r = session.exec("uname -a; cat /etc/os-release | grep PRETTY")?;
    println!("{}", r.stdout);

    // State persists across commands, inside the container.
    session.exec("cd /tmp")?;
    println!("cwd is now: {}", session.exec("pwd")?.cwd);

    Ok(())
}
