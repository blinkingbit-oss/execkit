// SPDX-License-Identifier: Apache-2.0
//! A command that outlives the timeout is interrupted (Ctrl-C) and the shell
//! resynced, so the session - cwd, env - survives.

use execkit::{Error, Session};
use std::time::Duration;

#[test]
fn timeout_interrupts_and_keeps_state() {
    let mut s = Session::local()
        .unwrap()
        .with_timeout(Duration::from_secs(1));
    s.exec("cd /tmp && export KEEP=yes").unwrap();
    let r = s.exec("echo started; sleep 30").unwrap();
    assert!(r.timed_out);
    assert_eq!(r.exit_code, 124);
    assert!(r.stdout.contains("started"));
    let r2 = s.exec("echo $KEEP; pwd").unwrap();
    assert_eq!(r2.stdout, "yes\n/tmp");
}

#[test]
fn per_call_timeout_overrides_default() {
    let mut s = Session::local()
        .unwrap()
        .with_timeout(Duration::from_secs(1));
    let r = s
        .exec_with_timeout("sleep 2; echo done", None, Duration::from_secs(5))
        .unwrap();
    assert_eq!((r.stdout.as_str(), r.timed_out), ("done", false));
}

#[test]
fn uninterruptible_command_poisons() {
    let mut s = Session::local()
        .unwrap()
        .with_timeout(Duration::from_secs(1));
    let e = s.exec("sh -c 'trap \"\" INT; sleep 20'").unwrap_err();
    assert!(matches!(e, Error::StillRunning), "{e}");
    assert!(matches!(
        s.exec("echo x").unwrap_err(),
        Error::SessionPoisoned
    ));
}

/// Ctrl-C must interrupt under `set +m` in dash and busybox ash too, not just
/// bash (the run line is abandoned and the resync brings the shell back).
#[test]
fn timeout_interrupts_in_dash_and_busybox_ash() {
    for (shell, args) in [("sh", &["-i"][..]), ("busybox", &["sh", "-i"][..])] {
        if shell == "busybox" && std::process::Command::new("busybox").output().is_err() {
            continue;
        }
        let mut s = Session::local_shell(shell, args)
            .unwrap()
            .with_timeout(Duration::from_secs(1));
        s.exec("cd /tmp; KEEP=yes").unwrap();
        let r = s.exec("P=$__ek_f; echo started; sleep 30").unwrap();
        assert!(r.timed_out, "{shell}: {r:?}");
        assert!(r.stdout.contains("started"), "{shell}: {r:?}");
        let r2 = s
            .exec("echo $KEEP; pwd; test -n \"$P\" && test ! -e \"$P\" && echo gone")
            .unwrap();
        assert_eq!(r2.stdout, "yes\n/tmp\ngone", "{shell}");
    }
}

#[test]
fn set_timeout_changes_live_session_and_result_serializes_flag() {
    let mut s = Session::local().unwrap();
    s.set_timeout(Duration::from_millis(500));
    let r = s.exec("sleep 5").unwrap();
    assert!(r.timed_out);
    assert!(r.stderr.contains("timed out after 0.5s"), "{}", r.stderr);
    assert_eq!(r.cwd, s.exec("pwd").unwrap().stdout);
    let j = serde_json::to_value(&r).unwrap();
    assert_eq!(j["timed_out"], true);
    // Older JSON without the field still deserializes.
    let mut j = serde_json::to_value(s.exec("true").unwrap()).unwrap();
    j.as_object_mut().unwrap().remove("timed_out");
    let back: execkit::ExecResult = serde_json::from_value(j).unwrap();
    assert!(!back.timed_out);
}

#[test]
fn timeout_removes_the_interrupted_commands_stderr_temp_file() {
    let mut s = Session::local()
        .unwrap()
        .with_timeout(Duration::from_secs(1));
    // The run line's stderr temp file path is in $__ek_f while the command runs.
    let r = s.exec("__ek_probe=$__ek_f; sleep 30").unwrap();
    assert!(r.timed_out);
    let r = s
        .exec("test -n \"$__ek_probe\" && test ! -e \"$__ek_probe\" && echo gone")
        .unwrap();
    assert_eq!(r.stdout, "gone");
}

/// A timed-out command keeps the stderr it wrote before the Ctrl-C (it sat in
/// the run line's temp file), followed by the timeout guidance - in bash,
/// dash and busybox ash. Neither the interrupted run line's temp file nor
/// the resync's own is left behind.
#[test]
fn timeout_keeps_the_interrupted_commands_stderr() {
    for (shell, args) in [
        ("bash", &["--norc", "--noprofile", "-i"][..]),
        ("sh", &["-i"][..]),
        ("busybox", &["sh", "-i"][..]),
    ] {
        if std::process::Command::new(shell)
            .arg("--help")
            .output()
            .is_err()
        {
            continue;
        }
        let mut s = Session::local_shell(shell, args)
            .unwrap()
            .with_timeout(Duration::from_secs(1));
        s.exec("export TMPDIR=$(mktemp -d)").unwrap();
        let r = s.exec("echo boom >&2; sleep 30").unwrap();
        assert!(r.timed_out, "{shell}: {r:?}");
        assert!(r.stderr.starts_with("boom\n"), "{shell}: {r:?}");
        assert!(
            r.stderr.contains("execkit: timed out after 1s"),
            "{shell}: {r:?}"
        );
        assert_eq!(s.exec("echo ok").unwrap().stdout, "ok", "{shell}");
        // Only the listing command's own stderr file exists.
        let r = s
            .exec("ls -A \"$TMPDIR\" | wc -l; rm -rf \"$TMPDIR\"")
            .unwrap();
        assert_eq!(r.stdout.trim(), "1", "{shell}: temp files leaked");
    }
}

/// Huge stderr before a timeout: only its tail comes back, the resync still
/// finds its markers, and the session stays usable.
#[test]
fn timeout_with_huge_stderr_keeps_the_tail() {
    let mut s = Session::local()
        .unwrap()
        .with_timeout(Duration::from_secs(1));
    let r = s
        .exec("i=0; while [ $i -lt 20000 ]; do echo \"line $i\" >&2; i=$((i+1)); done; echo LAST >&2; sleep 30")
        .unwrap();
    assert!(r.timed_out, "{r:?}");
    assert!(
        r.stderr.contains("LAST\n"),
        "{}",
        &r.stderr[r.stderr.len().saturating_sub(300)..]
    );
    assert!(!r.stderr.contains("line 0\n"));
    assert!(r.stderr.contains("execkit: timed out"));
    assert_eq!(s.exec("echo ok").unwrap().stdout, "ok");
}
