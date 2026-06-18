// SPDX-License-Identifier: Apache-2.0
//! Drives the built server over stdio with EXECKIT_MCP_AUDIT_DIR set and
//! asserts that exactly one per-session JSONL file is written per session,
//! named `<session_id>-<open_ms>.jsonl`, with ordered open/exec/close events.
//! Mirrors the mcp_e2e / audit_v2 harness pattern.
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

struct Mcp {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<Value>,
}
impl Mcp {
    fn start(env: &[(&str, &str)]) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_execkit-mcp"));
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn execkit-mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel::<Value>();
        thread::spawn(move || {
            let mut r = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match r.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if let Ok(v) = serde_json::from_str::<Value>(line.trim()) {
                            if tx.send(v).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
        let mut m = Mcp { child, stdin, rx };
        m.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-06-18","capabilities":{},
                      "clientInfo":{"name":"test","version":"0"}}}));
        m.recv();
        m.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        m
    }
    fn send(&mut self, v: Value) {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
    }
    fn recv(&mut self) -> Value {
        loop {
            match self.rx.recv_timeout(Duration::from_secs(15)) {
                Ok(v) if v.get("id").is_some() => return v,
                Ok(_) => continue,
                Err(RecvTimeoutError::Timeout) => panic!("no reply within 15s"),
                Err(RecvTimeoutError::Disconnected) => panic!("server closed stdout"),
            }
        }
    }
    fn call(&mut self, id: i64, name: &str, args: Value) -> Value {
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
            "params":{"name":name,"arguments":args}}));
        loop {
            let v = self.recv();
            if v["id"] == json!(id) {
                return v;
            }
        }
    }
}
impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn result_text(v: &Value) -> String {
    v["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn audit_dir_one_file_per_session() {
    let dir = std::env::temp_dir().join(format!("ek_adir_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let mut m = Mcp::start(&[("EXECKIT_MCP_AUDIT_DIR", dir.to_str().unwrap())]);

    // Create a local session, exec a command, destroy it.
    let created = m.call(2, "session_create", json!({"transport":"local"}));
    let sid: String = serde_json::from_str::<Value>(&result_text(&created)).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    m.call(
        3,
        "session_exec",
        json!({"session_id": sid, "command": "echo hello"}),
    );
    m.call(4, "session_destroy", json!({"session_id": sid}));
    drop(m); // ensure all writes flushed before reading

    // Exactly one *.jsonl file in the dir.
    let entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one .jsonl file, found {:?}",
        entries
    );

    let file_path = entries[0].path();
    let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();

    // Filename matches `^sess_\d+-\d+\.jsonl$`.
    // e.g. "sess_1-1718123456789.jsonl"
    assert!(
        file_name.starts_with("sess_")
            && file_name.ends_with(".jsonl")
            && file_name
                .trim_start_matches("sess_")
                .trim_end_matches(".jsonl")
                .split('-')
                .count()
                == 2
            && file_name
                .trim_start_matches("sess_")
                .trim_end_matches(".jsonl")
                .split('-')
                .all(|p| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty()),
        "filename {file_name:?} does not match expected pattern sess_<digits>-<digits>.jsonl"
    );

    // Lines are ordered open/exec/close with correct session id and transport.
    let body = std::fs::read_to_string(&file_path).unwrap();
    let events: Vec<Value> = body
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let kinds: Vec<&str> = events
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        vec!["open", "exec", "close"],
        "expected open/exec/close ordering, got {kinds:?}"
    );
    assert_eq!(events[0]["session"], json!(sid));
    assert_eq!(events[0]["transport"], json!("local"));
    assert!(events[0]["ts"].as_u64().unwrap() > 0);
    assert_eq!(events[1]["command"], json!("echo hello"));
    assert_eq!(events[1]["exit_code"], json!(0));
    assert_eq!(events[2]["reason"], json!("destroyed"));

    let _ = std::fs::remove_dir_all(&dir);
}
