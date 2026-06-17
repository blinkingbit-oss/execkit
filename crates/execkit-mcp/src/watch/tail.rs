// SPDX-License-Identifier: Apache-2.0
//! Reads new complete lines from the audit file as it grows; parses each into
//! an AuditEvent (skipping malformed lines). Polling-based, no file-watch dep.
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use crate::audit::AuditEvent;

pub struct Tailer {
    path: PathBuf,
    offset: u64,
    buf: String,
    mtime_nanos: u128,
}

impl Tailer {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            buf: String::new(),
            mtime_nanos: 0,
        }
    }

    pub fn poll(&mut self) -> Vec<AuditEvent> {
        let mut file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Vec::new(), // not created yet
        };
        let metadata = match file.metadata() {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        let len = metadata.len();
        let current_mtime_nanos = match metadata.modified() {
            Ok(t) => t
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            Err(_) => 0,
        };

        if self.mtime_nanos > 0 && current_mtime_nanos > self.mtime_nanos {
            // File was modified after we last read it: possible rotation
            if len < self.offset {
                // Definitely truncated
                self.offset = 0;
                self.buf.clear();
            } else if len == self.offset && self.offset > 0 {
                // Size hasn't changed but mtime has; likely rotation/rewrite
                self.offset = 0;
                self.buf.clear();
            }
        } else if len < self.offset {
            // Truncated: start over
            self.offset = 0;
            self.buf.clear();
        }

        self.mtime_nanos = current_mtime_nanos;

        if len == self.offset {
            return Vec::new();
        }
        if file.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }
        let mut chunk = String::new();
        if file.read_to_string(&mut chunk).is_err() {
            return Vec::new();
        }
        self.offset = len;
        self.buf.push_str(&chunk);

        let mut events = Vec::new();
        // Drain complete lines; keep any trailing partial line in `buf`.
        while let Some(nl) = self.buf.find('\n') {
            let line: String = self.buf.drain(..=nl).collect();
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            if let Ok(ev) = serde_json::from_str::<AuditEvent>(line) {
                events.push(ev);
            }
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ek_tail_{}_{}.jsonl",
            std::process::id(),
            crate::audit::now_ms()
        ))
    }
    fn append(path: &std::path::Path, s: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        f.write_all(s.as_bytes()).unwrap();
    }

    #[test]
    fn missing_file_yields_nothing_then_picks_up_new_lines() {
        let p = tmp();
        let _ = std::fs::remove_file(&p);
        let mut t = Tailer::new(p.clone());
        assert!(t.poll().is_empty()); // file absent

        append(
            &p,
            "{\"event\":\"open\",\"ts\":1,\"session\":\"s\",\"transport\":\"local\"}\n",
        );
        let evs = t.poll();
        assert_eq!(evs.len(), 1);
        assert!(matches!(evs[0], crate::audit::AuditEvent::Open { .. }));

        // partial line is buffered until its newline arrives
        append(&p, "{\"event\":\"close\",\"ts\":2,\"sessi");
        assert!(t.poll().is_empty());
        append(&p, "on\":\"s\",\"reason\":\"destroyed\"}\nGARBAGE\n");
        let evs = t.poll();
        assert_eq!(evs.len(), 1); // close parsed, GARBAGE skipped
        assert!(matches!(evs[0], crate::audit::AuditEvent::Close { .. }));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rotation_resets_and_rereads() {
        let p = tmp();
        append(
            &p,
            "{\"event\":\"open\",\"ts\":1,\"session\":\"a\",\"transport\":\"local\"}\n",
        );
        let mut t = Tailer::new(p.clone());
        assert_eq!(t.poll().len(), 1);
        // truncate (rotate) and write a fresh line: offset must reset
        std::fs::write(
            &p,
            "{\"event\":\"open\",\"ts\":2,\"session\":\"b\",\"transport\":\"local\"}\n",
        )
        .unwrap();
        let evs = t.poll();
        assert_eq!(evs.len(), 1);
        let _ = std::fs::remove_file(&p);
    }
}
