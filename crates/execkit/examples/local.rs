// SPDX-License-Identifier: Apache-2.0
//! A local session: structured results, persistent state, and the policy fence.
//!
//! Run: `cargo run --example local`

use execkit::{Policy, Session};

fn main() -> Result<(), execkit::Error> {
    let mut session = Session::local()?.with_policy(Policy {
        allow: vec![],
        deny: vec!["rm".into(), "dd".into()],
    });

    // Structured result: stdout/stderr are split, with exit code and cwd.
    let r = session.exec("echo hello; echo oops 1>&2; cd /tmp; false")?;
    println!("stdout : {:?}", r.stdout);
    println!("stderr : {:?}", r.stderr);
    println!("exit   : {}", r.exit_code);
    println!("cwd    : {}", r.cwd);
    println!("took   : {} ms", r.duration_ms);

    // State persists across calls (we're still in /tmp).
    println!("\npwd now: {}", session.exec("pwd")?.stdout);

    // Secrets are redacted before they reach you.
    let s = session.exec("echo token=AKIAIOSFODNN7EXAMPLE")?;
    println!("redacted: {}", s.stdout);

    // The advisory fence blocks dangerous commands before they run.
    match session.exec("rm -rf /tmp/whatever") {
        Err(execkit::Error::PolicyDenied(why)) => println!("\nblocked by policy: {why}"),
        other => println!("\nunexpected: {other:?}"),
    }

    Ok(())
}
