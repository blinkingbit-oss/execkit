// SPDX-License-Identifier: Apache-2.0
//! Drives the built binary's operator subcommands (--version, --help, setup,
//! doctor) and asserts their output and exit codes. These are commands a human
//! at a terminal would type; the no-arg server path is covered by mcp_e2e.
use std::io::Read;
use std::process::Command;
use std::time::Duration;

fn run(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_execkit-mcp"))
        .args(args)
        .output()
        .expect("spawn execkit-mcp");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn version_prints_name_and_semver() {
    let (stdout, _, code) = run(&["--version"]);
    assert_eq!(code, 0);
    assert!(stdout.starts_with("execkit-mcp "), "got {stdout:?}");
    // a dotted version follows the name
    let v = stdout.trim().strip_prefix("execkit-mcp ").unwrap();
    assert!(
        v.split('.').count() >= 3 && v.chars().next().unwrap().is_ascii_digit(),
        "expected semver, got {v:?}"
    );
    // -V is the same
    let (s2, _, c2) = run(&["-V"]);
    assert_eq!(c2, 0);
    assert_eq!(s2, stdout);
}

#[test]
fn help_lists_the_subcommands() {
    let (stdout, _, code) = run(&["--help"]);
    assert_eq!(code, 0);
    for needle in [
        "USAGE:",
        "setup <client>",
        "doctor",
        "watch",
        "EXECKIT_MCP_AUDIT",
    ] {
        assert!(stdout.contains(needle), "help missing {needle:?}");
    }
}

#[test]
fn setup_claude_prints_command_and_config() {
    let (stdout, _, code) = run(&["setup", "claude"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("claude mcp add execkit"), "got {stdout:?}");
    assert!(stdout.contains("\"mcpServers\""));
    assert!(stdout.contains("\"execkit\""));
}

#[test]
fn setup_cursor_and_gemini_name_their_files() {
    let (cursor, _, c1) = run(&["setup", "cursor"]);
    assert_eq!(c1, 0);
    assert!(cursor.contains(".cursor/mcp.json"), "got {cursor:?}");

    let (gemini, _, c2) = run(&["setup", "gemini"]);
    assert_eq!(c2, 0);
    assert!(gemini.contains(".gemini/settings.json"), "got {gemini:?}");
}

#[test]
fn setup_codex_prints_toml_snippet() {
    let (stdout, _, code) = run(&["setup", "codex"]);
    assert_eq!(code, 0);
    assert!(stdout.contains(".codex/config.toml"), "got {stdout:?}");
    assert!(stdout.contains("[mcp_servers.execkit]"), "got {stdout:?}");
    assert!(stdout.contains("command ="), "got {stdout:?}");
}

#[test]
fn setup_vscode_prints_mcp_json_snippet() {
    let (stdout, _, code) = run(&["setup", "vscode"]);
    assert_eq!(code, 0);
    assert!(stdout.contains(".vscode/mcp.json"), "got {stdout:?}");
    assert!(stdout.contains("\"servers\""), "got {stdout:?}");
    assert!(stdout.contains("\"type\": \"stdio\""), "got {stdout:?}");
}

#[test]
fn setup_windsurf_prints_mcp_config_snippet() {
    let (stdout, _, code) = run(&["setup", "windsurf"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains(".codeium/windsurf/mcp_config.json"),
        "got {stdout:?}"
    );
    assert!(stdout.contains("\"mcpServers\""), "got {stdout:?}");
}

#[test]
fn version_word_works_like_dash_capital_v() {
    let (stdout, _, code) = run(&["version"]);
    assert_eq!(code, 0);
    let (expected, _, _) = run(&["--version"]);
    assert_eq!(stdout, expected);
}

#[test]
fn help_lists_watch_flags_and_new_env_vars() {
    let (stdout, _, code) = run(&["--help"]);
    assert_eq!(code, 0);
    for needle in [
        "--serve",
        "--open",
        "EXECKIT_MCP_EXEC_TIMEOUT",
        "EXECKIT_MCP_WATCH_WEB",
        "EXECKIT_MCP_WATCH_PORT",
        "EXECKIT_MCP_WATCH_OPEN",
        "EXECKIT_MCP_KNOWN_HOSTS",
    ] {
        assert!(stdout.contains(needle), "help missing {needle:?}");
    }
}

#[test]
fn watch_help_prints_watch_section() {
    let (stdout, _, code) = run(&["watch", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--serve"), "got {stdout:?}");
    assert!(stdout.contains("EXECKIT_MCP_WATCH_PORT"), "got {stdout:?}");
    // a focused section, not the full top-level usage
    assert!(!stdout.contains("setup <client>"), "got {stdout:?}");
}

#[test]
fn watch_on_missing_parent_dir_warns() {
    let dir = std::env::temp_dir().join(format!("ek_watch_missing_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("audit.jsonl"); // dir itself does not exist

    let mut child = Command::new(env!("CARGO_BIN_EXE_execkit-mcp"))
        .args(["watch", "--follow", path.to_str().unwrap()])
        .env_remove("EXECKIT_MCP_AUDIT")
        .env_remove("EXECKIT_MCP_AUDIT_DIR")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn watch --follow");

    // Read stderr on a background thread, sending the accumulated text so far
    // on every chunk; the main thread polls with a deadline (the child never
    // exits on its own - `--follow` loops until killed).
    let mut stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut acc = String::new();
        loop {
            match stderr.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if tx.send(acc.clone()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let expected = format!(
        "warning: {} does not exist yet; waiting for it to appear",
        dir.display()
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut found = false;
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(acc) if acc.contains(&expected) => {
                found = true;
                break;
            }
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(found, "expected stderr to contain {expected:?}");
}

#[test]
fn setup_without_client_or_unknown_client_exits_2() {
    let (_, err, code) = run(&["setup"]);
    assert_eq!(code, 2);
    assert!(err.contains("name a client"), "got {err:?}");

    let (_, err2, code2) = run(&["setup", "nano"]);
    assert_eq!(code2, 2);
    assert!(err2.contains("unknown client"), "got {err2:?}");
}

#[test]
fn doctor_reports_version_and_audit_state() {
    // With no audit env set, audit is reported off.
    let out = Command::new(env!("CARGO_BIN_EXE_execkit-mcp"))
        .arg("doctor")
        .env_remove("EXECKIT_MCP_AUDIT")
        .env_remove("EXECKIT_MCP_AUDIT_DIR")
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout.contains("execkit-mcp "));
    assert!(stdout.contains("audit"));

    // With a writable audit dir, doctor marks it ok.
    let dir = std::env::temp_dir().join(format!("ek_doctor_{}", std::process::id()));
    let out2 = Command::new(env!("CARGO_BIN_EXE_execkit-mcp"))
        .arg("doctor")
        .env("EXECKIT_MCP_AUDIT_DIR", &dir)
        .output()
        .expect("spawn");
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert!(
        stdout2.contains("[ ok ] audit dir") && stdout2.contains("writable"),
        "got {stdout2:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unknown_command_exits_2_with_hint() {
    let (_, err, code) = run(&["frobnicate"]);
    assert_eq!(code, 2);
    assert!(err.contains("unknown command"), "got {err:?}");
    assert!(err.contains("--help"));
}

#[test]
fn doctor_reports_policy_state() {
    // off when unset
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_execkit-mcp"))
        .arg("doctor")
        .env_remove("EXECKIT_MCP_POLICY_FILE")
        .output()
        .expect("spawn");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("policy") && s.contains("off"), "got {s:?}");

    // counts when a valid file is set
    let dir = std::env::temp_dir().join(format!("ek_doc_pol_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pf = dir.join("p.json");
    std::fs::write(
        &pf,
        r#"{"allow":["git","ls"],"deny":["rm"],"deny_patterns":["\\brm\\b"]}"#,
    )
    .unwrap();
    let out2 = std::process::Command::new(env!("CARGO_BIN_EXE_execkit-mcp"))
        .arg("doctor")
        .env("EXECKIT_MCP_POLICY_FILE", &pf)
        .output()
        .expect("spawn");
    let s2 = String::from_utf8_lossy(&out2.stdout);
    assert!(
        s2.contains("[ ok ] policy") && s2.contains("2 allow, 1 deny, 1 patterns"),
        "got {s2:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn watch_serve_without_path_shows_usage() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_execkit-mcp"))
        .args(["watch", "--serve"])
        .env_remove("EXECKIT_MCP_AUDIT")
        .env_remove("EXECKIT_MCP_AUDIT_DIR")
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "missing path should exit non-zero");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--serve"),
        "usage should mention --serve, got {err:?}"
    );
}

/// `execkit-mcp setup claude | head -1`: once the reader is gone, a write to
/// stdout fails with a broken pipe. That is a clean exit, not a panic.
#[cfg(unix)]
#[test]
fn closed_stdout_is_a_clean_exit_not_a_panic() {
    for args in [
        &["setup", "claude"][..],
        &["--help"][..],
        &["watch", "--help"][..],
        &["--version"][..],
        &["doctor"][..],
    ] {
        let (reader, writer) = std::io::pipe().expect("pipe");
        // Close the read end first, so the very first write hits EPIPE.
        drop(reader);
        let out = Command::new(env!("CARGO_BIN_EXE_execkit-mcp"))
            .args(args)
            .stdout(writer)
            .output()
            .expect("spawn execkit-mcp");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("panicked"), "{args:?}: {stderr}");
        assert_eq!(out.status.code(), Some(0), "{args:?}: {stderr}");
    }
}

/// `watch --follow` stamps prompts and markers with local time (TZ=UTC here)
/// and prints a date line before the first event and when the date changes.
#[test]
fn follow_prints_times_and_a_date_line_across_midnight() {
    let dir = std::env::temp_dir().join(format!("ek_follow_midnight_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit.jsonl");
    // 2026-01-01 23:59:50 UTC: opened. A 5 s command recorded at 00:00:15
    // on 2026-01-02 (so it started at 00:00:10), then closed at 00:00:20.
    let t0: u64 = 1_767_311_990_000;
    let lines = [
        format!(r#"{{"event":"open","ts":{t0},"session":"local_1","transport":"local"}}"#),
        format!(
            r#"{{"event":"exec","ts":{},"session":"local_1","transport":"local","command":"echo hi","stdout":"hi\n","stderr":"","exit_code":0,"duration_ms":5000,"cwd":"/tmp","truncated":false}}"#,
            t0 + 25_000
        ),
        format!(
            r#"{{"event":"close","ts":{},"session":"local_1","reason":"destroyed"}}"#,
            t0 + 30_000
        ),
    ];
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_execkit-mcp"))
        .args(["watch", "--follow", path.to_str().unwrap()])
        .env("TZ", "UTC")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn watch --follow");
    let mut stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut acc = String::new();
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 {
                break;
            }
            acc.push_str(&String::from_utf8_lossy(&buf[..n]));
            if tx.send(acc.clone()).is_err() {
                break;
            }
        }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut got = String::new();
    while std::time::Instant::now() < deadline && !got.contains("closed") {
        if let Ok(acc) = rx.recv_timeout(Duration::from_millis(200)) {
            got = acc;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        got,
        "-- 2026-01-01 --\n\
         [local_1] [23:59:50] -- opened: local --\n\
         -- 2026-01-02 --\n\
         [local_1] [00:00:10] /tmp $ echo hi\n\
         [local_1] hi\n\
         [local_1] ok exit 0  (5000ms)\n\
         [local_1] [00:00:20] -- closed (destroyed) --\n"
    );
}
