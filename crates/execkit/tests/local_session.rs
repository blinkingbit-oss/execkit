// SPDX-License-Identifier: Apache-2.0
//! Integration tests against a real local PTY session.

use std::time::Duration;

use execkit::{Policy, Session};

#[test]
fn echo_roundtrip() {
    let mut s = Session::local().expect("spawn");
    let r = s.exec("echo hello").expect("exec");
    assert_eq!(r.stdout, "hello");
    assert_eq!(r.exit_code, 0);
}

#[test]
fn stderr_split_and_exit_code() {
    let mut s = Session::local().unwrap();
    let r = s.exec("echo OUT; echo ERR 1>&2; false").unwrap();
    assert_eq!(r.stdout, "OUT");
    assert_eq!(r.stderr, "ERR");
    assert_eq!(r.exit_code, 1);
}

#[test]
fn state_persists_across_commands() {
    let mut s = Session::local().unwrap();
    s.exec("cd /tmp").unwrap();
    let r = s.exec("pwd").unwrap();
    assert_eq!(r.cwd, "/tmp");
    assert_eq!(r.stdout, "/tmp");
}

#[test]
fn secrets_are_redacted_in_output() {
    let mut s = Session::local().unwrap();
    let r = s.exec("echo key=AKIAIOSFODNN7EXAMPLE").unwrap();
    assert!(r.stdout.contains("[REDACTED]"));
    assert!(!r.stdout.contains("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn policy_blocks_before_execution() {
    let mut s = Session::local().unwrap().with_policy(Policy {
        allow: vec![],
        deny: vec!["rm".into()],
    });
    let err = s.exec("rm -rf /tmp/should_not_run").unwrap_err();
    assert!(matches!(err, execkit::Error::PolicyDenied(_)));
}

#[test]
fn timeout_is_interrupted_not_poisoned() {
    let mut s = Session::local()
        .unwrap()
        .with_timeout(Duration::from_millis(400));
    // A command that outlives the timeout is interrupted and reported...
    let r = s.exec("sleep 3").unwrap();
    assert!(r.timed_out);
    assert_eq!(r.exit_code, 124);
    // ...and the session keeps working.
    assert!(!s.is_poisoned());
    assert_eq!(s.exec("echo hi").unwrap().stdout, "hi");
}

#[test]
fn session_learned_token_is_redacted_from_output_and_command() {
    let mut s = Session::local().unwrap();
    let token = format!("ghp_{}", "A".repeat(36));
    let r = s
        .exec(&format!("export GH_TOKEN={token} && echo $GH_TOKEN"))
        .unwrap();
    assert!(
        !r.stdout.contains(&token),
        "stdout must not contain the learned token; got: {}",
        r.stdout
    );
    assert!(
        !r.command.contains(&token),
        "command must not contain the learned token; got: {}",
        r.command
    );
}

#[test]
fn output_is_bounded_for_flood() {
    let mut s = Session::local().unwrap().with_max_output(1000);
    // ~50k lines (~280 KB) from one fast process - must come back bounded near
    // max_output, proving acc is compacted rather than accumulated whole.
    let r = s.exec("seq 1 50000").unwrap();
    assert!(r.truncated, "flood output should be marked truncated");
    assert!(
        r.stdout.chars().count() <= 1100,
        "stdout should be bounded near max_output, got {}",
        r.stdout.chars().count()
    );
}
