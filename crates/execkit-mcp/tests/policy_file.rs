// SPDX-License-Identifier: Apache-2.0
//! Drives the built server over stdio with EXECKIT_MCP_POLICY_FILE and
//! EXECKIT_MCP_AUDIT set, then asserts that blocked commands are rejected, emit
//! a warning notification, and land in the audit log as "blocked" events.
//! Mirrors the mcp_e2e / audit_dir / live_notify harness pattern.
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
    /// The server's `initialize` response (so tests can inspect capabilities).
    init: Value,
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
        let mut m = Mcp {
            child,
            stdin,
            rx,
            init: Value::Null,
        };
        m.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-06-18","capabilities":{},
                      "clientInfo":{"name":"test","version":"0"}}}));
        m.init = m.recv_id();
        m.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        m
    }
    fn send(&mut self, v: Value) {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
    }
    /// Next message carrying an `id` (a response), skipping notifications.
    fn recv_id(&mut self) -> Value {
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
            let v = self.recv_id();
            if v["id"] == json!(id) {
                return v;
            }
        }
    }
    /// Send a tool call with a progressToken in `params._meta`, then collect every
    /// notification that arrives until the response to `id`. Returns those
    /// notifications (the live activity is streamed before the result).
    fn call_collecting(
        &mut self,
        id: i64,
        name: &str,
        args: Value,
        token: Option<&str>,
    ) -> Vec<Value> {
        let mut params = json!({"name":name,"arguments":args});
        if let Some(t) = token {
            params["_meta"] = json!({"progressToken": t});
        }
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params}));
        let mut notes = Vec::new();
        loop {
            match self.rx.recv_timeout(Duration::from_secs(15)) {
                Ok(v) if v["id"] == json!(id) => return notes,
                Ok(v) if v.get("id").is_none() => notes.push(v),
                Ok(_) => continue, // a response to some other id
                Err(RecvTimeoutError::Timeout) => panic!("no reply to id {id} within 15s"),
                Err(RecvTimeoutError::Disconnected) => panic!("server closed stdout"),
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
fn operator_policy_blocks_audits_and_notifies() {
    let dir = std::env::temp_dir().join(format!("ek_polint_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pf = dir.join("policy.json");
    std::fs::write(
        &pf,
        r#"{"allow":[],"deny":["shutdown"],"deny_patterns":["\\brm\\b","\\btouch\\b"]}"#,
    )
    .unwrap();
    let audit = dir.join("audit.jsonl");

    let mut m = Mcp::start(&[
        ("EXECKIT_MCP_POLICY_FILE", pf.to_str().unwrap()),
        ("EXECKIT_MCP_AUDIT", audit.to_str().unwrap()),
    ]);

    let created = m.call(2, "session_create", json!({"transport":"local"}));
    let sid: String = serde_json::from_str::<Value>(&result_text(&created)).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    // allowed command runs (empty allow == all allowed; not a denied name/pattern)
    let ok = m.call(
        3,
        "session_exec",
        json!({"session_id": sid, "command": "echo hi"}),
    );
    assert!(
        result_text(&ok).contains("\"exit_code\": 0"),
        "allowed runs"
    );

    // denied by pattern -> blocked, and a warning notification fires
    let notes = m.call_collecting(
        4,
        "session_exec",
        json!({"session_id": sid, "command": "rm -rf /tmp/x"}),
        Some("tok"),
    );
    // this call only checks the live notification; the tool-error text on the
    // deny path is asserted separately below.
    let warn = notes
        .iter()
        .find(|v| v["method"] == json!("notifications/message"))
        .expect("a logging notification");
    assert_eq!(warn["params"]["level"], json!("warning"));
    assert!(warn["params"]["data"]["reason"]
        .as_str()
        .unwrap()
        .contains("deny pattern"));
    assert_eq!(warn["params"]["data"]["blocked"], json!("rm -rf /tmp/x"));

    // denied by name
    let blk = m.call(
        5,
        "session_exec",
        json!({"session_id": sid, "command": "shutdown now"}),
    );
    assert!(
        result_text(&blk).contains("blocked by operator policy"),
        "name deny blocks"
    );

    // denied by pattern -> tool response is also a tool_error
    let pat = m.call(
        7,
        "session_exec",
        json!({"session_id": sid, "command": "rm /tmp/zzz"}),
    );
    assert!(
        result_text(&pat).contains("blocked by operator policy"),
        "deny_pattern returns a tool error"
    );

    // blocked command must not produce a side effect
    let sentinel = dir.join("sentinel");
    let touched = m.call(
        9,
        "session_exec",
        json!({"session_id": sid, "command": format!("touch {}", sentinel.display())}),
    );
    assert!(
        result_text(&touched).contains("blocked by operator policy"),
        "touch blocked"
    );
    assert!(
        !sentinel.exists(),
        "a blocked command must not run (no side effect)"
    );

    m.call(10, "session_destroy", json!({"session_id": sid}));
    drop(m);

    // the audit log recorded the blocks
    let body = std::fs::read_to_string(&audit).unwrap();
    let blocked: Vec<_> = body
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["event"] == json!("blocked"))
        .collect();
    assert!(blocked
        .iter()
        .any(|v| v["command"] == json!("rm -rf /tmp/x")));
    assert!(blocked
        .iter()
        .any(|v| v["command"] == json!("shutdown now")));

    let _ = std::fs::remove_dir_all(&dir);
}
