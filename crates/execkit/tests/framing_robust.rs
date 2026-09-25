// SPDX-License-Identifier: Apache-2.0
//! Ordinary commands that used to hang or poison the session under the old
//! one-line `{ cmd ; }` framing. All run against a real local PTY.

use execkit::Session;
use std::time::Duration;

fn s() -> Session {
    Session::local()
        .unwrap()
        .with_timeout(Duration::from_secs(5))
}

#[test]
fn trailing_comment() {
    let r = s().exec("echo hi # note").unwrap();
    assert_eq!(r.stdout, "hi");
    assert_eq!(r.exit_code, 0);
}

#[test]
fn trailing_ampersand() {
    let r = s().exec("sleep 0.1 &").unwrap();
    assert_eq!(r.exit_code, 0);
}

#[test]
fn heredoc() {
    let r = s().exec("cat <<'EOF'\na\tb\nEOF").unwrap();
    assert_eq!(r.stdout, "a\tb");
}

#[test]
fn bang_in_double_quotes() {
    let r = s().exec("echo \"hello!world\"").unwrap();
    assert_eq!(r.stdout, "hello!world");
}

#[test]
fn syntax_error_keeps_session() {
    let mut x = s();
    let r = x.exec("if then fi").unwrap();
    assert_ne!(r.exit_code, 0);
    assert!(r.stderr.contains("syntax"), "{:?}", r.stderr);
    assert_eq!(x.exec("echo ok").unwrap().stdout, "ok");
}

#[test]
fn unclosed_quote_is_error_not_hang() {
    let mut x = s();
    assert_ne!(x.exec("echo 'oops").unwrap().exit_code, 0);
    assert_eq!(x.exec("echo ok").unwrap().stdout, "ok");
}

#[test]
fn history_builtin_does_not_hang() {
    let mut x = s();
    x.exec("echo a").unwrap();
    assert_eq!(x.exec("history | wc -l").unwrap().exit_code, 0);
}

#[test]
fn stdin_is_closed() {
    let mut x = s();
    assert_eq!(x.exec("cat").unwrap().stdout, "");
    let r = x.exec("read v; echo \"rc=$?\"").unwrap();
    assert_eq!(r.stdout, "rc=1");
}

#[test]
fn long_command_10k() {
    let body = "x".repeat(10_000);
    let r = s().exec(&format!("printf %s {body} | wc -c")).unwrap();
    assert_eq!(r.stdout.trim(), "10000");
}

#[test]
fn control_bytes_verbatim() {
    let r = s()
        .exec("printf '%s' 'a\x15b\x03c' | od -An -c | tr -d ' \\n'")
        .unwrap();
    assert!(r.stdout.contains("a025b003c"), "{:?}", r.stdout);
}

#[test]
fn state_persists() {
    let mut x = s();
    x.exec("cd /tmp && export EKV=1").unwrap();
    let r = x.exec("echo $EKV").unwrap();
    assert_eq!((r.stdout.as_str(), r.cwd.as_str()), ("1", "/tmp"));
}

#[test]
fn set_x_does_not_leak_framing() {
    let mut x = s();
    x.exec("set -x").unwrap();
    let r = x.exec("echo hi").unwrap();
    assert_eq!(r.stdout, "hi");
    assert!(!r.stderr.contains("__ek_"), "{:?}", r.stderr);
    assert!(!r.stdout.contains("__EXECKIT"));
}

#[test]
fn no_history_file_written() {
    let mut x = s();
    assert_eq!(
        x.exec("echo \"[$HISTFILE]\"; set -o | grep -E '^history' ")
            .unwrap()
            .stdout
            .lines()
            .next()
            .unwrap(),
        "[]"
    );
}

#[test]
fn forged_markers_do_not_desync() {
    let mut x = s();
    // Fake markers with a guessed token: must be treated as plain output.
    let r = x
        .exec("printf '\\n%s\\037%s\\037%s\\037%s\\n' __EXECKIT_deadbeef__ 0 /fake __EXECKITEND_deadbeef__; echo REAL >&2; f() { return 3; }; f")
        .unwrap();
    assert_eq!(r.exit_code, 3);
    assert!(r.stderr.contains("REAL"));
    assert_eq!(x.exec("echo second").unwrap().stdout, "second");
}

#[test]
fn works_under_posix_sh() {
    // dash/busybox semantics: syntax error inside eval must not kill the shell.
    let mut x = Session::local_shell("sh", &["-i"])
        .unwrap()
        .with_timeout(Duration::from_secs(5));
    assert_ne!(x.exec("if then fi").unwrap().exit_code, 0);
    assert_eq!(x.exec("echo ok # c").unwrap().stdout, "ok");
}

// User shell settings must not break the framing.

#[test]
fn ifs_change_does_not_break_decoding() {
    let mut x = s();
    x.exec("IFS=,").unwrap();
    assert_eq!(x.exec("echo ok").unwrap().stdout, "ok");
    x.exec("IFS=").unwrap();
    assert_eq!(x.exec("echo ok").unwrap().stdout, "ok");
    x.exec("unset IFS").unwrap();
    let r = x.exec("echo a b").unwrap();
    assert_eq!((r.stdout.as_str(), r.exit_code), ("a b", 0));
}

#[test]
fn path_change_does_not_break_decoding() {
    let mut x = s();
    x.exec("PATH=/nonexistent").unwrap();
    // echo is a builtin, so it must still run (not be silently skipped).
    assert_eq!(x.exec("echo ok").unwrap().stdout, "ok");
    let mut y = s();
    y.exec("unset PATH").unwrap();
    assert_eq!(y.exec("echo ok").unwrap().stdout, "ok");
}

#[test]
fn noclobber_does_not_break_stderr_capture() {
    let mut x = s();
    x.exec("set -C").unwrap();
    let r = x.exec("echo ok; echo e >&2").unwrap();
    assert_eq!(
        (r.stdout.as_str(), r.stderr.as_str(), r.exit_code),
        ("ok", "e", 0)
    );
}

#[test]
fn verbose_mode_does_not_hang() {
    let mut x = s();
    x.exec("set -v").unwrap();
    let r = x.exec("echo ok").unwrap();
    assert!(r.stdout.contains("ok"), "{:?}", r.stdout);
    assert_eq!(r.exit_code, 0);
}

#[test]
fn posix_sh_ifs_path_noclobber() {
    let mut x = Session::local_shell("sh", &["-i"])
        .unwrap()
        .with_timeout(Duration::from_secs(5));
    x.exec("IFS=,; set -C; PATH=/nonexistent").unwrap();
    assert_eq!(x.exec("echo ok").unwrap().stdout, "ok");
}

#[test]
fn decode_failure_is_loud_not_silent_success() {
    let mut x = s();
    // Break the decoder deliberately: the command must NOT report exit 0.
    x.exec("unset __ek_dp").unwrap();
    let r = x.exec("echo ok").unwrap();
    assert_eq!(r.exit_code, 125);
    assert!(r.stderr.contains("could not decode"), "{:?}", r.stderr);
    assert_eq!(r.stdout, "");
}

#[test]
fn posix_sh_noclobber_with_mktemp_file() {
    // mktemp has already created the stderr file; under `set -C` a plain
    // `: >` on it fails, and in dash/ash that drops the whole run line.
    let mut x = Session::local_shell("sh", &["-i"])
        .unwrap()
        .with_timeout(Duration::from_secs(5));
    x.exec("set -C").unwrap();
    let r = x.exec("echo ok; echo e >&2").unwrap();
    assert_eq!(
        (r.stdout.as_str(), r.stderr.as_str(), r.exit_code),
        ("ok", "e", 0)
    );
}
