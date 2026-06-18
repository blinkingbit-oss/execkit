// SPDX-License-Identifier: Apache-2.0
//! A poll source for the viewer: a single audit file, or a directory of
//! per-session files. Both yield AuditEvents through the same poll() contract,
//! so the TUI and the plain `--follow` stream share one source.
use std::path::PathBuf;

use crate::audit::AuditEvent;
use crate::watch::dirtail::DirTailer;
use crate::watch::tail::Tailer;

pub enum Source {
    File(Tailer),
    Dir(DirTailer),
}

impl Source {
    /// A directory path tails per-session files; anything else tails one file.
    pub fn new(path: PathBuf) -> Self {
        if path.is_dir() {
            Source::Dir(DirTailer::new(path))
        } else {
            Source::File(Tailer::new(path))
        }
    }

    pub fn poll(&mut self) -> Vec<AuditEvent> {
        match self {
            Source::File(t) => t.poll(),
            Source::Dir(d) => d.poll(),
        }
    }
}
