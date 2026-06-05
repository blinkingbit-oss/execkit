// SPDX-License-Identifier: Apache-2.0
//! Transports — how a session reaches an environment.
//!
//! `Session` frames commands on top of a byte-level [`Transport`], so the
//! framing / policy / redaction / audit logic is identical across local PTY,
//! SSH, and (later) Docker/K8s.

use std::time::{Duration, Instant};

use crate::error::{Error, Result};

pub mod local;
pub mod ssh;

/// A byte-level duplex link to a live shell.
pub trait Transport: Send {
    /// Write raw bytes to the shell's stdin.
    fn write_all(&mut self, bytes: &[u8]) -> Result<()>;
    /// Next available output chunk, or `None` on timeout/disconnect.
    fn recv_timeout(&self, dur: Duration) -> Option<Vec<u8>>;
}

/// Disable echo + prompts, then block until the shell confirms readiness.
///
/// Transport-agnostic and race-free: the readiness tag is printed via
/// `EXECKITrdy''<n>` so the *output* is the contiguous tag while the *echoed
/// command line* contains the `''` — we match only real output, never the
/// pre-`stty -echo` echo.
pub(crate) fn shell_init(t: &mut dyn Transport) -> Result<()> {
    const TAG: &[u8] = b"EXECKITrdy9f3a7c";
    t.write_all(
        b"stty -echo 2>/dev/null; PS1=''; PS2=''; PROMPT_COMMAND=''; \
          printf '%s\\n' EXECKITrdy''9f3a7c\n",
    )?;
    let mut acc = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Transport("shell init timed out".into()));
        }
        match t.recv_timeout(remaining) {
            Some(c) => {
                acc.extend_from_slice(&c);
                if contains(&acc, TAG) {
                    return Ok(());
                }
            }
            None => return Err(Error::Transport("shell init: disconnected".into())),
        }
    }
}

pub(crate) fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && hay.len() >= needle.len()
        && hay.windows(needle.len()).any(|w| w == needle)
}
