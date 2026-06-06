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
