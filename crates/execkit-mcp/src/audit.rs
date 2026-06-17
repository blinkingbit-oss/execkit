// SPDX-License-Identifier: Apache-2.0
//! Session-aware audit log (v2): one JSON event per line, written by the MCP
//! server which owns the session id, transport, and lifecycle. Append-only and
//! tail-safe; the `watch` viewer renders these events as a shell transcript.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "lowercase")]
pub enum AuditEvent {
    Open {
        ts: u64,
        session: String,
        transport: String,
    },
    Exec {
        ts: u64,
        session: String,
        transport: String,
        command: String,
        stdout: String,
        stderr: String,
        exit_code: i32,
        duration_ms: u64,
        cwd: String,
        truncated: bool,
    },
    Close {
        ts: u64,
        session: String,
        reason: String,
    },
}

/// Unix epoch milliseconds. Monotonic enough for ordering/display; no time dep.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Appends audit events as JSONL. Writes are serialized so concurrent large
/// `exec` lines never interleave. Best-effort: IO errors go to stderr only.
pub struct AuditWriter {
    path: PathBuf,
    lock: Mutex<()>,
}

impl AuditWriter {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    fn append(&self, ev: &AuditEvent) {
        let line = match serde_json::to_string(ev) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("execkit-mcp: audit serialize error: {e}");
                return;
            }
        };
        // Hold the lock across open+write so a whole line lands atomically
        // relative to other audit writers, regardless of line size.
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{line}") {
                    eprintln!("execkit-mcp: audit write error: {e}");
                }
            }
            Err(e) => eprintln!("execkit-mcp: audit open error: {e}"),
        }
    }

    pub fn open(&self, session: &str, transport: &str) {
        self.append(&AuditEvent::Open {
            ts: now_ms(),
            session: session.to_string(),
            transport: transport.to_string(),
        });
    }

    pub fn exec(&self, session: &str, transport: &str, r: &execkit::ExecResult) {
        self.append(&AuditEvent::Exec {
            ts: now_ms(),
            session: session.to_string(),
            transport: transport.to_string(),
            command: r.command.clone(),
            stdout: r.stdout.clone(),
            stderr: r.stderr.clone(),
            exit_code: r.exit_code,
            duration_ms: r.duration_ms,
            cwd: r.cwd.clone(),
            truncated: r.truncated,
        });
    }

    pub fn close(&self, session: &str, reason: &str) {
        self.append(&AuditEvent::Close {
            ts: now_ms(),
            session: session.to_string(),
            reason: reason.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_exec_close_round_trip_as_jsonl() {
        let dir = std::env::temp_dir().join(format!("ek_audit_{}", now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let w = AuditWriter::new(path.clone());

        w.open("sess_1", "ssh:web-01");
        w.exec(
            "sess_1",
            "ssh:web-01",
            &execkit::ExecResult {
                command: "echo hi".into(),
                stdout: "hi".into(),
                stderr: String::new(),
                exit_code: 0,
                duration_ms: 5,
                cwd: "/root".into(),
                truncated: false,
                budget: None,
            },
        );
        w.close("sess_1", "destroyed");

        let body = std::fs::read_to_string(&path).unwrap();
        let events: Vec<AuditEvent> = body
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(events.len(), 3);
        assert!(
            matches!(&events[0], AuditEvent::Open { session, transport, .. }
            if session == "sess_1" && transport == "ssh:web-01")
        );
        assert!(
            matches!(&events[1], AuditEvent::Exec { command, stdout, exit_code, .. }
            if command == "echo hi" && stdout == "hi" && *exit_code == 0)
        );
        assert!(matches!(&events[2], AuditEvent::Close { reason, .. } if reason == "destroyed"));
        // The raw line must carry the discriminator and ts.
        let first = body.lines().next().unwrap();
        assert!(first.contains("\"event\":\"open\""));
        assert!(first.contains("\"ts\":"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
