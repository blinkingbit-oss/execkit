// SPDX-License-Identifier: Apache-2.0
//! Drives the built server over stdio with EXECKIT_MCP_AUDIT set and asserts the
//! enriched open/exec/close audit lines. Mirrors the mcp_e2e harness.
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
fn audit_log_records_open_exec_close() {
    let dir = std::env::temp_dir().join(format!("ek_av2_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit.jsonl");
    let mut m = Mcp::start(&[("EXECKIT_MCP_AUDIT", path.to_str().unwrap())]);

    let created = m.call(2, "session_create", json!({"transport":"local"}));
    let sid: String = serde_json::from_str::<Value>(&result_text(&created)).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    m.call(
        3,
        "session_exec",
        json!({"session_id":sid,"command":"echo hi"}),
    );
    m.call(4, "session_destroy", json!({"session_id":sid}));
    drop(m); // ensure all writes flushed before reading

    let body = std::fs::read_to_string(&path).unwrap();
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
        "ordered lifecycle, got {kinds:?}"
    );
    assert_eq!(events[0]["session"], json!(sid));
    assert_eq!(events[0]["transport"], json!("local"));
    assert!(events[0]["ts"].as_u64().unwrap() > 0);
    assert_eq!(events[1]["command"], json!("echo hi"));
    assert_eq!(events[1]["stdout"], json!("hi"));
    assert_eq!(events[1]["exit_code"], json!(0));
    assert_eq!(events[2]["reason"], json!("destroyed"));
    let _ = std::fs::remove_dir_all(&dir);
}
