// SPDX-License-Identifier: Apache-2.0
//! Drives the built server over stdio and asserts that `session_exec` streams
//! live activity to the client: a `notifications/message` (logging) carrying the
//! shell transcript, and a `notifications/progress` when the call supplied a
//! progressToken. Mirrors the mcp_e2e / audit_dir harness pattern.
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
fn exec_streams_logging_and_progress_notifications() {
    let mut m = Mcp::start(&[]);

    // The server must advertise the logging capability for clients to opt into
    // these notifications.
    assert!(
        m.init["result"]["capabilities"]["logging"].is_object(),
        "server should advertise logging capability, got {:?}",
        m.init["result"]["capabilities"]
    );

    let created = m.call(2, "session_create", json!({"transport":"local"}));
    let sid: String = serde_json::from_str::<Value>(&result_text(&created)).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Exec with a progressToken so both notification kinds fire. The activity is
    // streamed before the tool response, so collect notifications during the call.
    let notes = m.call_collecting(
        3,
        "session_exec",
        json!({"session_id": sid, "command": "echo hello"}),
        Some("tok-1"),
    );
    let find = |method: &str| -> Value {
        notes
            .iter()
            .find(|v| v["method"] == json!(method))
            .unwrap_or_else(|| panic!("no {method} among notifications: {notes:?}"))
            .clone()
    };

    // A logging message carries the transcript for this session.
    let logmsg = find("notifications/message");
    let p = &logmsg["params"];
    assert_eq!(p["level"], json!("info"), "exit 0 -> info level");
    assert_eq!(p["data"]["session"], json!(sid));
    assert_eq!(p["data"]["transport"], json!("local"));
    let transcript = p["data"]["transcript"]
        .as_array()
        .expect("transcript array");
    let joined: String = transcript
        .iter()
        .map(|l| l.as_str().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("$ echo hello"),
        "transcript should show the command, got {joined:?}"
    );
    assert!(
        joined.contains("hello"),
        "transcript should show stdout, got {joined:?}"
    );

    // A progress notification echoes the token the client supplied.
    let prog = find("notifications/progress");
    assert_eq!(prog["params"]["progressToken"], json!("tok-1"));
    assert!(prog["params"]["message"]
        .as_str()
        .unwrap()
        .contains("echo hello"));

    m.call(4, "session_destroy", json!({"session_id": sid}));
}

#[test]
fn nonzero_exit_warns_and_no_token_suppresses_progress() {
    let mut m = Mcp::start(&[]);
    let created = m.call(2, "session_create", json!({"transport":"local"}));
    let sid: String = serde_json::from_str::<Value>(&result_text(&created)).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    // A failing command (nonzero exit, but `false` does not kill the persistent
    // shell the way `exit` would), and NO progressToken supplied.
    let notes = m.call_collecting(
        3,
        "session_exec",
        json!({"session_id": sid, "command": "false"}),
        None,
    );

    // The logging message is present and escalated to warning on nonzero exit.
    let logmsg = notes
        .iter()
        .find(|v| v["method"] == json!("notifications/message"))
        .unwrap_or_else(|| panic!("no logging notification among {notes:?}"));
    assert_eq!(
        logmsg["params"]["level"],
        json!("warning"),
        "nonzero exit -> warning level"
    );

    // With no progressToken, the server has nowhere to attach progress: none sent.
    assert!(
        !notes
            .iter()
            .any(|v| v["method"] == json!("notifications/progress")),
        "progress must be suppressed without a token, got {notes:?}"
    );

    m.call(4, "session_destroy", json!({"session_id": sid}));
}
