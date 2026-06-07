// SPDX-License-Identifier: Apache-2.0
//! Real checkpoint test against a Docker container (the remote stand-in).
//! Self-skips unless EXECKIT_TEST_DOCKER=<container> is set. The container needs
//! git installed (the CI job runs `apk add git`).
//!
//!   docker run -d --name ek alpine sleep 600
//!   docker exec ek apk add --no-cache git
//!   EXECKIT_TEST_DOCKER=ek cargo test --test checkpoint_smoke

use execkit::Session;

fn session(container: &str, workspace: &str) -> Session {
    Session::docker(container)
        .expect("docker session")
        .with_workspace(workspace)
}

#[test]
fn checkpoint_restore_roundtrip() {
    let Ok(c) = std::env::var("EXECKIT_TEST_DOCKER") else {
        eprintln!("skip: set EXECKIT_TEST_DOCKER=<container> (needs git) to run");
        return;
    };
    let ws = "/root/ck_roundtrip";
    let mut s = session(&c, ws);
    // clean slate - these write commands will auto-snapshot, but we discard them
    // and take an explicit checkpoint after writing the file we care about
    s.exec(&format!("rm -rf {ws} && mkdir -p {ws}")).unwrap();
    s.exec(&format!("printf 'v1' > {ws}/keep.txt")).unwrap();

    let id = s.checkpoint(Some("baseline")).expect("checkpoint");

    // mutate: modify, then delete and create another file
    s.exec(&format!("printf 'v2' > {ws}/keep.txt")).unwrap();
    s.exec(&format!(
        "rm -f {ws}/keep.txt && printf 'new' > {ws}/created.txt"
    ))
    .unwrap();

    s.restore(&id).expect("restore");

    // keep.txt is back at v1; created.txt is gone
    assert_eq!(s.exec(&format!("cat {ws}/keep.txt")).unwrap().stdout, "v1");
    assert_eq!(
        s.exec(&format!("test -f {ws}/created.txt; echo $?"))
            .unwrap()
            .stdout,
        "1"
    );
}

#[test]
fn auto_snapshot_skips_reads_and_local_is_unsupported() {
    let Ok(c) = std::env::var("EXECKIT_TEST_DOCKER") else {
        return;
    };
    let ws = "/root/ck_auto";
    // Use a session with auto-snapshot off to set up the workspace cleanly;
    // this avoids the setup commands (rm/mkdir) appearing as writing commands
    // and polluting the checkpoint list in the test session.
    let mut setup = Session::docker(&c)
        .expect("docker session")
        .with_workspace(ws)
        .with_auto_snapshot(false);
    setup
        .exec(&format!("rm -rf {ws} && mkdir -p {ws}"))
        .unwrap();

    // Now create the actual test session with auto-snapshot enabled (default).
    let mut s = session(&c, ws);
    // a read-only command must not create a checkpoint
    s.exec(&format!("ls {ws}")).unwrap();
    assert!(
        s.checkpoints().unwrap().is_empty(),
        "read-only must not snapshot"
    );
    // a writing command auto-snapshots
    s.exec(&format!("printf x > {ws}/a.txt")).unwrap();
    assert!(!s.checkpoints().unwrap().is_empty(), "write must snapshot");

    // local session: unsupported
    let mut local = Session::local().unwrap();
    assert!(local.checkpoint(None).is_err());
}

#[test]
fn multi_path_only_reverts_listed_dirs() {
    let Ok(c) = std::env::var("EXECKIT_TEST_DOCKER") else {
        return;
    };
    let ws = "/root/ck_multi";
    let mut s = Session::docker(&c)
        .unwrap()
        .with_workspace(ws)
        .with_checkpoint_paths(["src"])
        .with_auto_snapshot(false);
    s.exec(&format!("rm -rf {ws} && mkdir -p {ws}/src {ws}/docs"))
        .unwrap();
    s.exec(&format!("printf s1 > {ws}/src/a; printf d1 > {ws}/docs/b"))
        .unwrap();
    let id = s.checkpoint(Some("base")).unwrap();
    s.exec(&format!("printf s2 > {ws}/src/a; printf d2 > {ws}/docs/b"))
        .unwrap();
    s.restore(&id).unwrap();
    assert_eq!(s.exec(&format!("cat {ws}/src/a")).unwrap().stdout, "s1"); // reverted
    assert_eq!(s.exec(&format!("cat {ws}/docs/b")).unwrap().stdout, "d2"); // untouched
}
