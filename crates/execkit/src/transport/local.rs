// SPDX-License-Identifier: Apache-2.0
//! Local PTY transport - a persistent shell in a pseudo-terminal.

use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};

use super::Transport;
use crate::error::{Error, Result};

/// Bounded reader->session queue. A flooding command (`yes`) fills this, the
/// reader thread then blocks on `send`, the PTY buffer fills, and the child
/// blocks on write - real backpressure that bounds memory (≤ CAP * read chunk).
const CHANNEL_CAP: usize = 64;

/// A live shell process attached to a PTY.
pub struct LocalPty {
    writer: Box<dyn Write + Send>,
    rx: Receiver<Vec<u8>>,
    _master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
}

impl LocalPty {
    /// Spawn `shell` with `args` in a fresh PTY. Readiness/echo-off is applied
    /// by the session via `super::shell_init`.
    pub fn spawn(shell: &str, args: &[&str]) -> Result<Self> {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            })
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

        Ok(LocalPty {
            writer,
            rx,
            _master: pair.master,
            child,
        })
    }
}

impl Transport for LocalPty {
    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.write_all(bytes)?;
        self.writer.flush()?;
        Ok(())
    }

    fn recv_timeout(&self, dur: Duration) -> Option<Vec<u8>> {
        self.rx.recv_timeout(dur).ok()
    }
}

impl Drop for LocalPty {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}
