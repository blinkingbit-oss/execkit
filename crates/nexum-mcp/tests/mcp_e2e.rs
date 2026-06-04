// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests that drive the built MCP server binary over stdio with real
//! JSON-RPC. No network needed (local transport + key-path rejection).

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

struct Mcp {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Mcp {
    fn start(env: &[(&str, &str)]) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nexum-mcp"));
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn nexum-mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut m = Mcp {
            child,
            stdin,
            stdout,
        };
        m.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-06-18","capabilities":{},
                      "clientInfo":{"name":"test","version":"0"}}}));
        m.recv(); // initialize result
        m.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        m
    }

    fn send(&mut self, v: Value) {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn recv(&mut self) -> Value {
        loop {
            let mut line = String::new();
            let n = self.stdout.read_line(&mut line).expect("read");
            assert!(n > 0, "server closed stdout unexpectedly");
            let v: Value = serde_json::from_str(line.trim()).expect("valid json-rpc line");
            if v.get("id").is_some() {
                return v;
            }
        }
    }

    fn call(&mut self, id: i64, name: &str, args: Value) -> Value {
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
            "params":{"name":name,"arguments":args}}));
        self.recv()
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn is_error(result: &Value) -> bool {
    result["result"]["isError"] == Value::Bool(true)
}

fn result_json(result: &Value) -> Value {
    let text = result["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap()
}

fn result_text(result: &Value) -> String {
    result["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn lists_tools_and_runs_a_command() {
    let mut m = Mcp::start(&[]);

    m.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}));
    let tools = m.recv();
    let mut names: Vec<String> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(names, ["session_create", "session_destroy", "session_exec"]);

    let created = m.call(3, "session_create", json!({"transport":"local"}));
    let sid = result_json(&created)["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Split streams + exit code + persisted cwd in one structured result.
    let e = m.call(
        4,
        "session_exec",
        json!({"session_id":sid,"command":"echo OUT; echo ERR 1>&2; cd /tmp; false"}),
    );
    let r = result_json(&e);
    assert_eq!(r["stdout"], "OUT");
    assert_eq!(r["stderr"], "ERR");
    assert_eq!(r["exit_code"], 1);
    assert_eq!(r["cwd"], "/tmp");

    // Secret redaction flows through MCP.
    let e2 = m.call(
        5,
        "session_exec",
        json!({"session_id":sid,"command":"echo k=AKIAIOSFODNN7EXAMPLE"}),
    );
    let out = result_json(&e2)["stdout"].as_str().unwrap().to_string();
    assert!(out.contains("[REDACTED]") && !out.contains("AKIA"), "{out}");

    let d = m.call(6, "session_destroy", json!({"session_id":sid}));
    assert!(result_text(&d).contains("\"destroyed\":true"));
}

#[test]
fn enforces_session_cap() {
    let mut m = Mcp::start(&[("NEXUM_MCP_MAX_SESSIONS", "2")]);
    let r1 = m.call(3, "session_create", json!({"transport":"local"}));
    let r2 = m.call(4, "session_create", json!({"transport":"local"}));
    let r3 = m.call(5, "session_create", json!({"transport":"local"}));
    assert!(!is_error(&r1) && !is_error(&r2));
    assert!(is_error(&r3) && result_text(&r3).contains("limit reached"));
}

#[test]
fn rejects_key_path_traversal_generically() {
    let mut m = Mcp::start(&[]);
    let r = m.call(
        3,
        "session_create",
        json!({"transport":"ssh","host":"127.0.0.1","user":"x","key_path":"/etc/passwd"}),
    );
    assert!(is_error(&r));
    let t = result_text(&r);
    assert!(t.contains("not permitted"), "{t}");
    assert!(!t.contains("passwd"), "must not leak the path: {t}");
}
