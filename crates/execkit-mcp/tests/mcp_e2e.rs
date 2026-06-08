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
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_execkit-mcp"));
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn execkit-mcp");
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
        let init = m.recv();
        // Lock in the identity fix: must advertise execkit-mcp, not rmcp's default.
        assert_eq!(init["result"]["serverInfo"]["name"], "execkit-mcp");
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
        // Correlate by id rather than assuming the next id-bearing message is ours.
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
    assert_eq!(
        names,
        [
            "session_checkpoint",
            "session_checkpoints",
            "session_create",
            "session_destroy",
            "session_exec",
            "session_restore",
        ]
    );

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
    let mut m = Mcp::start(&[("EXECKIT_MCP_MAX_SESSIONS", "2")]);
    let r1 = m.call(3, "session_create", json!({"transport":"local"}));
    let r2 = m.call(4, "session_create", json!({"transport":"local"}));
    let r3 = m.call(5, "session_create", json!({"transport":"local"}));
    assert!(!is_error(&r1) && !is_error(&r2));
    assert!(is_error(&r3) && result_text(&r3).contains("limit reached"));
}

#[test]
fn session_cap_atomic_under_concurrency() {
    // Regression for the TOCTOU in session_create: the cap was checked, the map
    // lock dropped, and the (blocking) build awaited before re-inserting WITHOUT
    // a re-check. Pipelined creates all observed len() < max and all proceeded,
    // spawning far more live PTY children than the operator cap allowed.
    //
    // The server processes pipelined tools/call requests concurrently (each build
    // runs on spawn_blocking), so firing many creates without reading replies in
    // between reproduces the race.
    const N: i64 = 30;
    let mut m = Mcp::start(&[("EXECKIT_MCP_MAX_SESSIONS", "2")]);

    // Fire N creates back-to-back, before reading any reply.
    for id in 0..N {
        m.send(json!({"jsonrpc":"2.0","id":100+id,"method":"tools/call",
            "params":{"name":"session_create","arguments":{"transport":"local"}}}));
    }

    // Drain N id-bearing replies and count successes (those carrying a session_id).
    let mut successes = 0;
    let mut received = 0;
    while received < N {
        let v = m.recv();
        let id = v["id"].as_i64();
        if !matches!(id, Some(i) if (100..100 + N).contains(&i)) {
            continue; // not one of ours (e.g. a stray notification id)
        }
        received += 1;
        if !is_error(&v) {
            let txt = result_text(&v);
            if txt.contains("session_id") {
                successes += 1;
            }
        }
    }

    assert!(
        successes <= 2,
        "session cap bypassed under concurrency: {successes} creates succeeded, cap was 2"
    );
}

#[test]
fn destroy_releases_a_cap_slot() {
    // After hitting the cap, destroying a session must free a slot so a new
    // create succeeds (the atomic admission counter is decremented on destroy).
    let mut m = Mcp::start(&[("EXECKIT_MCP_MAX_SESSIONS", "2")]);
    let r1 = m.call(3, "session_create", json!({"transport":"local"}));
    let r2 = m.call(4, "session_create", json!({"transport":"local"}));
    assert!(!is_error(&r1) && !is_error(&r2));
    let sid1 = result_json(&r1)["session_id"].as_str().unwrap().to_string();

    // At the cap: third create is rejected.
    let r3 = m.call(5, "session_create", json!({"transport":"local"}));
    assert!(is_error(&r3) && result_text(&r3).contains("limit reached"));

    // Free a slot, then a new create must succeed.
    let d = m.call(6, "session_destroy", json!({"session_id": sid1}));
    assert!(result_text(&d).contains("\"destroyed\":true"));
    let r4 = m.call(7, "session_create", json!({"transport":"local"}));
    assert!(!is_error(&r4), "slot not released after destroy: {r4}");

    // Still at the cap again: another create is rejected.
    let r5 = m.call(8, "session_create", json!({"transport":"local"}));
    assert!(is_error(&r5) && result_text(&r5).contains("limit reached"));
}

#[test]
fn rejects_key_path_traversal_generically() {
    // Use a real, existing key_dir so the rejection exercises the bounds check
    // specifically (not the "key_dir missing" branch, which shares the message).
    let key_dir = std::env::temp_dir().join(format!("execkit_kd_{}", std::process::id()));
    std::fs::create_dir_all(&key_dir).unwrap();
    let mut m = Mcp::start(&[("EXECKIT_MCP_KEY_DIR", key_dir.to_str().unwrap())]);
    let r = m.call(
        3,
        "session_create",
        json!({"transport":"ssh","host":"127.0.0.1","user":"x","key_path":"/etc/passwd"}),
    );
    assert!(is_error(&r));
    let t = result_text(&r);
    assert!(t.contains("not permitted"), "{t}");
    assert!(!t.contains("passwd"), "must not leak the path: {t}");
    let _ = std::fs::remove_dir_all(&key_dir);
}

#[test]
fn output_budget_shapes_and_reports() {
    let mut m = Mcp::start(&[]);
    let created = m.call(3, "session_create", json!({"transport":"local"}));
    let sid = result_json(&created)["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 200 lines, keep last 5
    let e = m.call(
        4,
        "session_exec",
        json!({"session_id": sid,
               "command": "for i in $(seq 1 200); do echo line$i; done",
               "budget": {"keep": {"mode": "tail", "n": 5}}}),
    );
    let r = result_json(&e);
    assert!(r["stdout"].as_str().unwrap().ends_with("line200"));
    assert_eq!(r["budget"]["stdout"]["lines_total"], 200);
    assert_eq!(r["budget"]["stdout"]["lines_kept"], 5);
    assert_eq!(r["budget"]["stdout"]["mode"], "tail");

    // invalid regex -> tool error, no crash
    let bad = m.call(
        5,
        "session_exec",
        json!({"session_id": sid, "command": "echo hi", "budget": {"grep": {"pattern": "("}}}),
    );
    assert!(is_error(&bad));
    assert!(result_text(&bad).contains("invalid grep pattern"));

    let _ = m.call(6, "session_destroy", json!({"session_id": sid}));
}
