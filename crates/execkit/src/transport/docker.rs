// SPDX-License-Identifier: Apache-2.0
//! Docker transport: a session inside a running container via `docker exec`.
//!
//! This is the local PTY transport driving the `docker` CLI, plus in-container
//! cleanup. Killing the `docker exec` *client* (what the PTY child kill does)
//! does NOT stop the shell it started inside the container, so on drop we
//! best-effort kill our marked process tree there - otherwise a dropped or
//! timed-out session would leave a shell (and any still-running command) alive.

use std::process::{Command, Stdio};
use std::time::Duration;

use super::local::LocalPty;
use super::Transport;
use crate::error::Result;

pub struct DockerExec {
    inner: LocalPty,
    container: String,
    marker: String,
}

impl DockerExec {
    /// `marker` is a per-session token; the container shell and every command it
    /// spawns inherit it as `EXECKIT_SID`, so drop-cleanup can find the tree.
    pub fn spawn(container: &str, marker: &str) -> Result<Self> {
        let env = format!("EXECKIT_SID={marker}");
        // -t so the container shell line-buffers (a pipe block-buffers and the
        // sentinel markers never flush); -- so a `-`-leading name can't be a flag.
        let inner = LocalPty::spawn(
            "docker",
            &["exec", "-it", "-e", &env, "--", container, "/bin/sh"],
        )?;
        Ok(Self {
            inner,
            container: container.to_string(),
            marker: marker.to_string(),
        })
    }
}

impl Transport for DockerExec {
    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.inner.write_all(bytes)
    }

    fn recv_timeout(&self, dur: Duration) -> Option<Vec<u8>> {
        self.inner.recv_timeout(dur)
    }
}

impl Drop for DockerExec {
    fn drop(&mut self) {
        // Best-effort: kill every process in the container whose environ carries
        // our marker (the shell and its children). Portable across busybox/dash
        // (uses /proc, tr, grep, kill). Runs before `inner` (LocalPty) drops and
        // kills the client. Best-effort only: an adversarial command that unsets
        // EXECKIT_SID before forking can evade it.
        let script = format!(
            "for p in /proc/[0-9]*; do \
               tr '\\0' '\\n' < \"$p/environ\" 2>/dev/null | grep -qx 'EXECKIT_SID={m}' && \
               kill -9 \"${{p#/proc/}}\" 2>/dev/null; \
             done",
            m = self.marker
        );
        let _ = Command::new("docker")
            .args(["exec", "--", &self.container, "/bin/sh", "-c", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
