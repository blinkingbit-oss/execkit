// SPDX-License-Identifier: Apache-2.0
//! A command whose stdout AND stderr are both large used to run into its
//! timeout (exit 124): compaction dropped the start marker, which sits
//! between the two streams, so the trailer could never be parsed.

use execkit::{Budget, Session};
use std::time::{Duration, Instant};

fn s() -> Session {
    Session::local()
        .unwrap()
        .with_timeout(Duration::from_secs(15))
}

fn check(r: &execkit::ExecResult, n: usize, dt: Duration) {
    assert!(!r.timed_out, "timed out after {dt:?}");
    assert_eq!(r.exit_code, 0);
    assert!(r.truncated);
    let last = n.to_string();
    assert!(
        r.stdout.ends_with(&last),
        "stdout tail: {:?}",
        tail(&r.stdout)
    );
    assert!(
        r.stderr.ends_with(&last),
        "stderr tail: {:?}",
        tail(&r.stderr)
    );
    assert!(!r.stdout.contains("__EXECKIT") && !r.stderr.contains("__EXECKIT"));
    assert!(dt < Duration::from_secs(10), "took {dt:?}");
}

fn tail(s: &str) -> &str {
    &s[s.len().saturating_sub(80)..]
}

fn run(cmd: &str, budget: Option<&Budget>) -> (execkit::ExecResult, Duration) {
    let mut x = s();
    let t = Instant::now();
    let r = match budget {
        Some(b) => x.exec_budgeted(cmd, b),
        None => x.exec(cmd),
    }
    .unwrap();
    let dt = t.elapsed();
    eprintln!("{cmd}: {dt:?}");
    // The session stays usable and in sync.
    assert_eq!(x.exec("echo ok").unwrap().stdout, "ok");
    (r, dt)
}

#[test]
fn large_stdout_and_stderr_60k() {
    let (r, dt) = run("seq 1 60000; seq 1 60000 >&2", None);
    check(&r, 60000, dt);
    assert!(r.stdout.contains(" elided") && r.stderr.contains(" elided"));
}

#[test]
fn large_stdout_and_stderr_100k() {
    let (r, dt) = run("seq 1 100000; seq 1 100000 >&2", None);
    check(&r, 100000, dt);
    assert!(r.stdout.contains(" elided") && r.stderr.contains(" elided"));
}

// ~15 MB per stream: both exceed the 8 MiB budget window.
#[test]
fn large_stdout_and_stderr_2m_budgeted() {
    let (r, dt) = run("seq 1 2000000; seq 1 2000000 >&2", Some(&Budget::tail(1)));
    check(&r, 2000000, dt);
    let b = r.budget.expect("budget report");
    assert_eq!((b.stdout.lines_kept, b.stderr.lines_kept), (1, 1));
}
