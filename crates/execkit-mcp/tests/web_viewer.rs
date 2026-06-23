// SPDX-License-Identifier: Apache-2.0
//! End-to-end: with EXECKIT_MCP_WATCH_WEB + EXECKIT_MCP_AUDIT set, the server
//! starts the web viewer, emits its URL via a log notification, and streams a
//! command's transcript over SSE. Drives the built server over stdio.
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

struct Server {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<Value>,
}

impl Server {
    fn start(audit: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_execkit-mcp"))
            .env("EXECKIT_MCP_WATCH_WEB", "1")
            .env("EXECKIT_MCP_AUDIT", audit)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn server");
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
        Self { child, stdin, rx }
    }

    fn send(&mut self, v: Value) {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn recv_timeout(&mut self, dur: Duration) -> Option<Value> {
        match self.rx.recv_timeout(dur) {
            Ok(v) => Some(v),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => panic!("server closed stdout"),
        }
    }

    /// Wait for a response carrying the given id (skipping notifications).
    fn recv_id(&mut self, id: i64) -> Value {
        loop {
            match self.rx.recv_timeout(Duration::from_secs(15)) {
                Ok(v) if v["id"] == json!(id) => return v,
                Ok(_) => continue,
                Err(RecvTimeoutError::Timeout) => panic!("no reply to id {id} within 15s"),
                Err(RecvTimeoutError::Disconnected) => panic!("server closed stdout"),
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn web_viewer_emits_url_and_streams_sse() {
    let audit = std::env::temp_dir().join(format!("ek_webe2e_{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&audit);
    let mut m = Server::start(&audit);

    m.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-06-18","capabilities":{},
        "clientInfo":{"name":"t","version":"0"}}}));
    m.recv_id(1); // consume init response
    m.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));

    // Collect messages until we see the web URL notification.
    let mut url = String::new();
    for _ in 0..50 {
        if let Some(v) = m.recv_timeout(Duration::from_secs(5)) {
            if v["method"] == json!("notifications/message") {
                if let Some(u) = v["params"]["data"]["url"].as_str() {
                    url = u.to_string();
                    break;
                }
            }
        }
    }
    assert!(
        url.starts_with("http://127.0.0.1:"),
        "expected loopback url, got {url:?}"
    );
    assert!(url.contains("/?t="), "url should carry a token: {url}");

    // Create a session and run a command; it lands in the audit file the viewer tails.
    m.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"session_create","arguments":{"transport":"local"}}}));
    m.recv_id(3); // consume session_create response

    m.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
        "params":{"name":"session_exec","arguments":{"session_id":"1_local","command":"echo sse-demo"}}}));
    m.recv_id(4); // consume session_exec response

    // Connect to /events and confirm the exec arrives over SSE.
    let base = url.replace("/?t=", "/events?t=");
    let (host_port, token) = base
        .split_once("/events?t=")
        .map(|(h, t)| (h.trim_start_matches("http://"), t))
        .unwrap();
    let mut found = false;
    for _ in 0..40 {
        if let Ok(body) = sse_read(host_port, token, Duration::from_millis(500)) {
            if body.contains("echo sse-demo") {
                found = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(found, "expected the exec to stream over SSE");

    let _ = std::fs::remove_file(&audit);
}

// Minimal blocking SSE read: GET /events?t=, read for `dur`, return what arrived.
fn sse_read(host_port: &str, token: &str, dur: Duration) -> std::io::Result<String> {
    use std::io::Read;
    use std::net::TcpStream;
    let mut s = TcpStream::connect(host_port)?;
    s.set_read_timeout(Some(dur))?;
    write!(
        s,
        "GET /events?t={token} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )?;
    let mut buf = [0u8; 8192];
    let mut acc = String::new();
    let start = std::time::Instant::now();
    while start.elapsed() < dur {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => acc.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(_) => break,
        }
    }
    Ok(acc)
}
