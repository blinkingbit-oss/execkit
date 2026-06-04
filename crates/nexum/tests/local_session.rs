// SPDX-License-Identifier: Apache-2.0
//! Integration tests against a real local PTY session.

use nexum::{Policy, Session};

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
    let mut s = Session::local()
        .unwrap()
        .with_policy(Policy { allow: vec![], deny: vec!["rm".into()] });
    let err = s.exec("rm -rf /tmp/should_not_run").unwrap_err();
    assert!(matches!(err, nexum::Error::PolicyDenied(_)));
}
