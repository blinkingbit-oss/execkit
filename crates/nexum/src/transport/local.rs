// SPDX-License-Identifier: Apache-2.0
//! Local PTY transport — a persistent shell in a pseudo-terminal.
//!
//! Ported from the proven PoC (`poc/rust/`): a reader thread pumps PTY bytes to
//! a channel so the session loop can frame commands and detect timeouts.

use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

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

        let (tx, rx) = mpsc::channel::<Vec<u8>>();
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
        pty.init();
        Ok(pty)
    }

    fn init(&mut self) {
        // Echo off + no prompt so captured output is exactly the command output.
        let _ = self.write_all(b"stty -echo 2>/dev/null; PS1=''; PS2=''; PROMPT_COMMAND=''\n");
        let deadline = Instant::now() + Duration::from_millis(300);
        while let Some(rem) = deadline.checked_duration_since(Instant::now()) {
            if self.rx.recv_timeout(rem).is_err() {
                break;
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
