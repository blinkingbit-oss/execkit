// SPDX-License-Identifier: Apache-2.0
//! Real end-to-end Docker smoke test. Self-skips unless a running container is
//! provided via:
//!   EXECKIT_TEST_DOCKER="<container name or id>"
//! e.g.
//!   docker run -d --name ek alpine sleep 600
//!   EXECKIT_TEST_DOCKER=ek cargo test --test docker_smoke
//!
//! Needs the `docker` CLI on PATH. Without the env var this test passes trivially.

use execkit::Session;

#[test]
fn docker_exec_roundtrip() {
    let Ok(container) = std::env::var("EXECKIT_TEST_DOCKER") else {
        eprintln!("skip: set EXECKIT_TEST_DOCKER=<container> to run");
        return;
    };

    let mut s = Session::docker(&container).expect("docker session");

    let r = s.exec("echo hello").expect("exec");
    assert_eq!(r.stdout, "hello");
    assert_eq!(r.exit_code, 0);

    // Split streams + exit code, inside the container.
    let r = s.exec("echo OUT; echo ERR 1>&2; false").expect("exec");
    assert_eq!(r.stdout, "OUT");
    assert_eq!(r.stderr, "ERR");
    assert_eq!(r.exit_code, 1);

    // State persists across execs.
    s.exec("cd /tmp").unwrap();
    assert_eq!(s.exec("pwd").unwrap().cwd, "/tmp");

    // Secret redaction applies on the Docker transport too.
    let r = s.exec("echo k=AKIAIOSFODNN7EXAMPLE").expect("exec");
    assert!(r.stdout.contains("[REDACTED]"), "stdout was {:?}", r.stdout);
}

/// A timeout in busybox sh inside the container sends Ctrl-C and resyncs;
/// the session keeps working.
#[test]
fn docker_timeout_interrupts_and_keeps_session() {
    let Ok(container) = std::env::var("EXECKIT_TEST_DOCKER") else {
        eprintln!("skip: set EXECKIT_TEST_DOCKER=<container> to run");
        return;
    };
    let mut s = Session::docker(&container)
        .expect("docker session")
        .with_timeout(std::time::Duration::from_secs(1));
    s.exec("cd /tmp").unwrap();
    let r = s.exec("sleep 30").expect("timeout is not an error");
    assert!(r.timed_out, "{r:?}");
    assert_eq!(r.exit_code, 124);
    let r = s.exec("echo ok").expect("session survives");
    assert_eq!((r.stdout.as_str(), r.cwd.as_str()), ("ok", "/tmp"));
}

/// Dropping a docker session (here after an uninterruptible timeout) must reap the in-container
/// shell + the still-running command - killing only the local `docker exec`
/// client would leave them alive in the container.
#[test]
fn docker_drop_reaps_in_container_processes() {
    let Ok(container) = std::env::var("EXECKIT_TEST_DOCKER") else {
        eprintln!("skip: set EXECKIT_TEST_DOCKER=<container> to run");
        return;
    };
    {
        let mut s = Session::docker(&container)
            .expect("docker session")
            .with_timeout(std::time::Duration::from_millis(400));
        // Foreground command that outlives the timeout and ignores Ctrl-C: the
        // session poisons with this still running in the container.
        assert!(
            s.exec("sh -c 'trap \"\" INT; sleep 31459'").is_err(),
            "expected an uninterruptible timeout"
        );
    } // drop -> best-effort cleanup kills the in-container tree
    std::thread::sleep(std::time::Duration::from_millis(900));
    // Count survivors via /proc (busybox-safe); `[3]1459` avoids matching the probe.
    let out = std::process::Command::new("docker")
        .args([
            "exec",
            &container,
            "sh",
            "-c",
            "c=0; for p in /proc/[0-9]*/cmdline; do \
             tr '\\0' ' ' < \"$p\" 2>/dev/null | grep -q '[3]1459' && c=$((c+1)); done; echo $c",
        ])
        .output()
        .expect("docker exec probe");
    let count = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(count, "0", "in-container 'sleep 31459' survived drop");
}
