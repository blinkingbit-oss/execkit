// SPDX-License-Identifier: Apache-2.0
//! Real end-to-end SSH smoke test. Self-skips unless a server is provided via
//!   EXECKIT_TEST_SSH="user:password@host:port"
//! e.g. EXECKIT_TEST_SSH="root:pw@127.0.0.1:2222" cargo test --test ssh_smoke
//!
//! Uses AcceptAny host-key policy (test only). There is no sshd in CI by
//! default, so without the env var this test passes trivially.
#![cfg(feature = "ssh")]

use std::time::{Duration, Instant};

use execkit::{HostKeyVerification, Session, SshAuth, SshConfig};

fn parse(spec: &str) -> Option<(String, String, String, u16)> {
    // user:password@host:port
    let (creds, hostport) = spec.split_once('@')?;
    let (user, pass) = creds.split_once(':')?;
    let (host, port) = hostport.split_once(':')?;
    Some((user.into(), pass.into(), host.into(), port.parse().ok()?))
}

#[test]
fn ssh_echo_roundtrip() {
    let Ok(spec) = std::env::var("EXECKIT_TEST_SSH") else {
        eprintln!("skip: set EXECKIT_TEST_SSH=\"user:pass@host:port\" to run");
        return;
    };
    let (user, pass, host, port) = parse(&spec).expect("EXECKIT_TEST_SSH=user:pass@host:port");

    let mut cfg = SshConfig::new(
        host,
        user,
        SshAuth::Password(pass),
        HostKeyVerification::AcceptAny,
    );
    cfg.port = port;

    let mut s = Session::ssh(cfg).expect("ssh connect");
    let r = s.exec("echo hello").expect("exec");
    assert_eq!(r.stdout, "hello");
    assert_eq!(r.exit_code, 0);

    // State persists over SSH too.
    s.exec("cd /tmp").unwrap();
    assert_eq!(s.exec("pwd").unwrap().cwd, "/tmp");
}

/// Regression for the RSA rsa-sha2 fix: authenticate with an RSA *key* against a
/// server that rejects legacy `ssh-rsa` (SHA-1). If we ever sign with `ssh-rsa`
/// again (e.g. by passing `None` for the hash), the server denies auth and this
/// fails. Gated on:
///   EXECKIT_TEST_SSH_KEYSPEC="user@host:port"  EXECKIT_TEST_SSH_KEY="/path/to/key"
#[test]
fn ssh_rsa_key_uses_rsa_sha2() {
    let (Ok(spec), Ok(key)) = (
        std::env::var("EXECKIT_TEST_SSH_KEYSPEC"),
        std::env::var("EXECKIT_TEST_SSH_KEY"),
    ) else {
        eprintln!("skip: set EXECKIT_TEST_SSH_KEYSPEC + EXECKIT_TEST_SSH_KEY to run");
        return;
    };
    let (user, hostport) = spec.split_once('@').expect("EXECKIT_TEST_SSH_KEYSPEC=user@host:port");
    let (host, port) = hostport.split_once(':').expect("host:port");

    let mut cfg = SshConfig::new(
        host,
        user,
        SshAuth::Key {
            path: key.into(),
            passphrase: None,
        },
        HostKeyVerification::AcceptAny,
    );
    cfg.port = port.parse().expect("port");

    // Connecting at all proves rsa-sha2 was negotiated (the server rejects ssh-rsa).
    let mut s = Session::ssh(cfg).expect("RSA-key auth via rsa-sha2");
    assert_eq!(s.exec("echo rsa-ok").expect("exec").stdout, "rsa-ok");
}

/// Regression: dropping a session after a flood/timeout must not hang (the
/// runtime thread is parked in a full blocking read send, not in select!).
#[test]
fn ssh_drop_after_timeout_does_not_hang() {
    let Ok(spec) = std::env::var("EXECKIT_TEST_SSH") else {
        eprintln!("skip: set EXECKIT_TEST_SSH to run");
        return;
    };
    let (user, pass, host, port) = parse(&spec).expect("EXECKIT_TEST_SSH=user:pass@host:port");
    let mut cfg = SshConfig::new(
        host,
        user,
        SshAuth::Password(pass),
        HostKeyVerification::AcceptAny,
    );
    cfg.port = port;

    let mut s = Session::ssh(cfg)
        .expect("ssh connect")
        .with_timeout(Duration::from_millis(500));
    // Floods forever -> StillRunning; the runtime thread blocks in read_tx.send.
    assert!(s.exec("yes").is_err());
    let t = Instant::now();
    drop(s); // must return promptly, not deadlock in join()
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "drop hung for {:?}",
        t.elapsed()
    );
}
