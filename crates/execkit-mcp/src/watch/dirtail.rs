// SPDX-License-Identifier: Apache-2.0
//! Tails a directory of per-session audit files: one `Tailer` per `*.jsonl`,
//! picking up files that appear after startup. Each file is one session; events
//! carry their own session id, so the viewer's state model demuxes them as in
//! single-file mode.
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::audit::AuditEvent;
use crate::watch::tail::Tailer;

pub struct DirTailer {
    dir: PathBuf,
    tailers: BTreeMap<PathBuf, Tailer>,
}

impl DirTailer {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            tailers: BTreeMap::new(),
        }
    }

    pub fn poll(&mut self) -> Vec<AuditEvent> {
        // Discover new *.jsonl files (BTreeMap keeps a stable poll order).
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("jsonl")
                    && !self.tailers.contains_key(&path)
                {
                    self.tailers.insert(path.clone(), Tailer::new(path));
                }
            }
        }
        let mut events = Vec::new();
        for tailer in self.tailers.values_mut() {
            events.extend(tailer.poll());
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);
    fn tmpdir() -> PathBuf {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("ek_dirtail_{}_{}", std::process::id(), n));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn write_line(dir: &std::path::Path, name: &str, line: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(name))
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    #[test]
    fn merges_sessions_and_picks_up_new_files() {
        let d = tmpdir();
        write_line(
            &d,
            "sess_0-1.jsonl",
            r#"{"event":"open","ts":1,"session":"sess_0","transport":"local"}"#,
        );
        write_line(
            &d,
            "sess_1-2.jsonl",
            r#"{"event":"open","ts":2,"session":"sess_1","transport":"ssh:h"}"#,
        );
        let mut t = DirTailer::new(d.clone());
        let evs = t.poll();
        assert_eq!(evs.len(), 2); // both session files read
                                  // a file that appears later is picked up on the next poll
        write_line(
            &d,
            "sess_2-3.jsonl",
            r#"{"event":"open","ts":3,"session":"sess_2","transport":"docker:c"}"#,
        );
        let evs = t.poll();
        assert_eq!(evs.len(), 1); // only the new file's new line
        let _ = std::fs::remove_dir_all(&d);
    }
}
