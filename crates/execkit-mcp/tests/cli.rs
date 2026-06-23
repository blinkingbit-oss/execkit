// SPDX-License-Identifier: Apache-2.0
//! Drives the built binary's operator subcommands (--version, --help, setup,
//! doctor) and asserts their output and exit codes. These are commands a human
//! at a terminal would type; the no-arg server path is covered by mcp_e2e.
use std::process::Command;

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
