// SPDX-License-Identifier: Apache-2.0
//! Regression tests for output-framing integrity (SEC-5).
//!
//! All run against a real local PTY session (no network). They prove the three
//! framing vulnerabilities are closed without regressing cwd/state tracking:
//!   1. cwd spoof / stderr pollution via a `\x1f` (US) byte in `$PWD`.
//!   2. stderr field forgeable via the leaked `$__E` shell variable.
//!   3. residual control bytes (NUL, US) surviving into final fields.

use execkit::Session;

/// #1: a directory whose name contains US (0x1f) must not be able to inject an
/// extra separator into the cwd field, truncating cwd and leaking the remainder
/// into the stderr field.
#[test]
fn cwd_spoof_via_us_in_pwd_is_blocked() {
    let mut s = Session::local().unwrap();
    let r = s
        .exec("d=$(printf '/tmp/evil\\037pwn'); mkdir -p \"$d\"; cd \"$d\"; printf out")
        .unwrap();
    // stdout still delivered.
    assert!(r.stdout.contains("out"), "stdout was {:?}", r.stdout);
    // cwd must not carry a raw US byte and must not be split/spoofed.
    assert!(
        !r.cwd.contains('\u{1f}'),
        "cwd leaked a US byte: {:?}",
        r.cwd
    );
    assert_eq!(r.cwd, "/tmp/evilpwn", "cwd was {:?}", r.cwd);
    // the "pwn" tail must NOT have leaked into stderr.
    assert!(
        !r.stderr.contains("pwn"),
        "stderr was polluted by cwd tail: {:?}",
        r.stderr
    );
}

/// #2: there is no `$__E` shell variable any more, so the command cannot forge
/// the stderr field by writing to it.
#[test]
fn stderr_forge_via_leaked_var_is_blocked() {
    let mut s = Session::local().unwrap();
    let r = s.exec("printf 'FORGED' > \"$__E\"; true").unwrap();
    assert_ne!(r.stderr, "FORGED", "attacker forged the stderr field");
    assert!(
        !r.stderr.contains("FORGED"),
        "stderr contains forged text: {:?}",
        r.stderr
    );
}

/// #2 positive: real fd-2 output still surfaces as stderr.
#[test]
fn real_stderr_still_captured() {
    let mut s = Session::local().unwrap();
    let r = s.exec("echo real 1>&2").unwrap();
    assert_eq!(r.stderr, "real");
}

/// #3: a NUL byte in stdout must be stripped from the final result.
#[test]
fn nul_is_stripped_from_stdout() {
    let mut s = Session::local().unwrap();
    let r = s.exec("printf 'a\\0b'").unwrap();
    assert!(
        !r.stdout.contains('\0'),
        "stdout retained a NUL byte: {:?}",
        r.stdout
    );
    assert_eq!(r.stdout, "ab", "stdout was {:?}", r.stdout);
}

// ---- regression guards: the fix must not break the core feature ----

#[test]
fn cd_state_persists_across_execs() {
    let mut s = Session::local().unwrap();
    s.exec("cd /tmp").unwrap();
    let r = s.exec("pwd").unwrap();
    assert_eq!(r.cwd, "/tmp");
    assert_eq!(r.stdout, "/tmp");
}

#[test]
fn exit_codes_are_correct() {
    let mut s = Session::local().unwrap();
    assert_eq!(s.exec("false").unwrap().exit_code, 1);
    assert_eq!(s.exec("true").unwrap().exit_code, 0);
}

#[test]
fn normal_echo_roundtrip_with_real_cwd() {
    let mut s = Session::local().unwrap();
    s.exec("cd /").unwrap();
    let r = s.exec("echo hi").unwrap();
    assert_eq!(r.stdout, "hi");
    assert_eq!(r.cwd, "/");
    assert_eq!(r.exit_code, 0);
}
