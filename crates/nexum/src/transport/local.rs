// SPDX-License-Identifier: Apache-2.0
//! Local PTY transport — a persistent shell in a pseudo-terminal.
//!
//! Ported from the proven PoC (`poc/rust/`): a reader thread pumps PTY bytes to
//! a channel so the session loop can frame commands and detect timeouts.

use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

/// Bounded reader→session queue. A flooding command (`yes`) fills this, the
/// reader thread then blocks on `send`, the PTY buffer fills, and the child
/// blocks on write — real backpressure that bounds memory (≤ CAP * read chunk).
const CHANNEL_CAP: usize = 64;

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};

use crate::error::{Error, Result};

/// A live shell process attached to a PTY.
pub struct LocalPty {
    writer: Box<dyn Write + Send>,
    rx: Receiver<Vec<u8>>,
    _master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
}

impl LocalPty {
    /// Spawn `shell` with `args` in a fresh PTY and quiet its echo/prompt.
    pub fn spawn(shell: &str, args: &[&str]) -> Result<Self> {
        let pair = native_pty_system()
            .openpty(PtySize { rows: 24, cols: 120, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| Error::Transport(e.to_string()))?;

        let mut cmd = CommandBuilder::new(shell);
        cmd.args(args);
        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| Error::Transport(e.to_string()))?;
        drop(pair.slave); // let EOF propagate when the shell exits

        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| Error::Transport(e.to_string()))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| Error::Transport(e.to_string()))?;

        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_CAP);
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let mut pty = LocalPty { writer, rx, _master: pair.master, child };
        pty.init()?;
        Ok(pty)
    }

    /// Disable echo + prompts, then block until the shell confirms readiness.
    ///
    /// The readiness tag is printed via `NEXUMrdy''<n>` so the *output* is the
    /// contiguous tag while the *echoed command line* contains the `''` — we
    /// therefore match only the real output, never the pre-`stty -echo` echo,
    /// closing the init race.
    fn init(&mut self) -> Result<()> {
        const TAG: &[u8] = b"NEXUMrdy9f3a7c";
        self.write_all(
            b"stty -echo 2>/dev/null; PS1=''; PS2=''; PROMPT_COMMAND=''; \
              printf '%s\\n' NEXUMrdy''9f3a7c\n",
        )?;
        let mut acc = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::Transport("shell init timed out".into()));
            }
            match self.recv_timeout(deadline - now) {
                Some(c) => {
                    acc.extend_from_slice(&c);
                    if contains(&acc, TAG) {
                        return Ok(());
                    }
                }
                None => return Err(Error::Transport("shell init: shell disconnected".into())),
            }
        }
    }

    pub fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.write_all(bytes)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Receive the next chunk, or `None` on timeout/disconnect.
    pub fn recv_timeout(&self, dur: Duration) -> Option<Vec<u8>> {
        self.rx.recv_timeout(dur).ok()
    }
}

impl Drop for LocalPty {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && hay.len() >= needle.len()
        && hay.windows(needle.len()).any(|w| w == needle)
}
