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

#[test]
fn no_workspace_disables_checkpoints() {
    let Ok(c) = std::env::var("EXECKIT_TEST_DOCKER") else {
        eprintln!("skip: set EXECKIT_TEST_DOCKER=<container> (needs git) to run");
        return;
    };
    // auto_snapshot defaults ON, but NO workspace is set.
    let mut s = Session::docker(&c).expect("docker session");
    // A changing command still runs fine; the auto-snapshot path is skipped
    // because there is no workspace (so it never defaults to the cwd / home dir).
    // (We assert the deterministic, isolation-safe behavior below rather than the
    // shared ~/.execkit dir, which other parallel tests legitimately create.)
    s.exec("mkdir -p /root/nw && printf v > /root/nw/f")
        .unwrap();
    // Writing a checkpoint fails loudly with a clear, workspace-mentioning error.
    let e1 = s.checkpoint(None).unwrap_err();
    assert!(
        matches!(&e1, execkit::Error::Unsupported(m) if m.contains("workspace")),
        "checkpoint: got {e1:?}"
    );
    // Listing degrades gracefully to an empty list (read-only, no error).
    assert!(
        s.checkpoints().unwrap().is_empty(),
        "checkpoints() should be empty without a workspace"
    );
}

#[test]
fn custom_ignores_are_not_snapshotted_or_restored() {
    let Ok(c) = std::env::var("EXECKIT_TEST_DOCKER") else {
        eprintln!("skip: set EXECKIT_TEST_DOCKER=<container> (needs git) to run");
        return;
    };
    let ws = "/root/ck_ignores";
    let mut s = session(&c, ws).with_checkpoint_ignores(["*.log"]);
    s.exec(&format!(
        "rm -rf {ws} && mkdir -p {ws} && printf v1 > {ws}/keep.txt && printf L1 > {ws}/app.log"
    ))
    .unwrap();
    let id = s.checkpoint(Some("base")).unwrap();
    s.exec(&format!(
        "printf v2 > {ws}/keep.txt; printf L2 > {ws}/app.log"
    ))
    .unwrap();
    s.restore(&id).unwrap();
    assert_eq!(s.exec(&format!("cat {ws}/keep.txt")).unwrap().stdout, "v1"); // reverted
    assert_eq!(s.exec(&format!("cat {ws}/app.log")).unwrap().stdout, "L2"); // ignored -> untouched
}

#[test]
fn restore_rejects_option_injecting_id_and_no_file_clobber() {
    // SEC-1: a checkpoint id is always a git SHA. A `-`-leading id is otherwise
    // parsed by git as an OPTION, e.g. `--output=/path` makes `git diff` write an
    // arbitrary file OUTSIDE the workspace (the `-- {paths}` only constrains
    // pathspecs). restore() must reject any non-hex id BEFORE running git.
    let Ok(c) = std::env::var("EXECKIT_TEST_DOCKER") else {
        eprintln!("skip: set EXECKIT_TEST_DOCKER=<container> (needs git) to run");
        return;
    };
    let ws = "/root/ck_sec1";
    let mut s = session(&c, ws);
    s.exec(&format!("rm -rf {ws} && mkdir -p {ws}")).unwrap();
    s.exec(&format!("printf 'v1' > {ws}/keep.txt")).unwrap();
    // a real checkpoint so the shadow repo is initialized (restore gets past the
    // "no checkpoints yet" guard and reaches the vulnerable builders).
    s.checkpoint(Some("baseline")).expect("checkpoint");

    // victim file OUTSIDE the workspace.
    s.exec("mkdir -p /tmp/pwn && printf ORIGINAL > /tmp/pwn/victim")
        .unwrap();

    // the exploit: a `-`-leading id that git would treat as `--output=<file>`.
    let evil = execkit::CheckpointId("--output=/tmp/pwn/victim".into());
    let err = s.restore(&evil).unwrap_err();
    assert!(
        matches!(&err, execkit::Error::Unsupported(m)
            if m.contains("checkpoint id") || m.contains("invalid")),
        "expected Unsupported(invalid checkpoint id), got {err:?}"
    );

    // the victim file must be untouched (NOT clobbered by a `git diff --output`).
    assert_eq!(
        s.exec("cat /tmp/pwn/victim").unwrap().stdout,
        "ORIGINAL",
        "victim file outside the workspace was clobbered"
    );
}

#[test]
fn secret_excludes_resist_user_negation() {
    // SEC-4: even when the caller supplies `!.ssh` (a negation), the SECRET_IGNORES
    // `.ssh` rule written after it in the exclude file overrides the negation.
    // Proof: after checkpoint + restore, `.ssh/id_rsa` retains the "TAMPERED" value
    // because git never tracked it (it was excluded).  `keep.txt` IS reverted,
    // proving the restore ran and the selective non-revert of id_rsa is intentional.
    let Ok(c) = std::env::var("EXECKIT_TEST_DOCKER") else {
        eprintln!("skip: set EXECKIT_TEST_DOCKER=<container> (needs git) to run");
        return;
    };
    let ws = "/root/ck_sec4";
    let mut s = Session::docker(&c)
        .expect("docker session")
        .with_workspace(ws)
        .with_checkpoint_ignores(["!.ssh"])
        .with_auto_snapshot(false);

    // Set up: fake secret + regular file.
    s.exec(&format!(
        "rm -rf {ws} && mkdir -p {ws}/.ssh && \
         printf 'SECRET' > {ws}/.ssh/id_rsa && \
         printf 'v1' > {ws}/keep.txt"
    ))
    .unwrap();

    let id = s.checkpoint(Some("sec4-base")).expect("checkpoint");

    // Mutate keep.txt so we can verify restore ran.
    s.exec(&format!("printf 'v2' > {ws}/keep.txt")).unwrap();
    // Also mutate the fake secret to a sentinel value.
    s.exec(&format!("printf 'TAMPERED' > {ws}/.ssh/id_rsa"))
        .unwrap();

    s.restore(&id).expect("restore");

    // keep.txt must be reverted (proves the restore ran).
    assert_eq!(
        s.exec(&format!("cat {ws}/keep.txt")).unwrap().stdout,
        "v1",
        "keep.txt must be restored to v1"
    );

    // .ssh/id_rsa must NOT be reverted -- it was never snapshotted.
    // If the negation `!.ssh` had won, git would have captured the original
    // "SECRET" value and restore would have written it back, replacing "TAMPERED".
    assert_eq!(
        s.exec(&format!("cat {ws}/.ssh/id_rsa")).unwrap().stdout,
        "TAMPERED",
        ".ssh/id_rsa must remain TAMPERED (secret was not snapshotted)"
    );
}

#[test]
fn restore_before_any_checkpoint_errors_cleanly() {
    let Ok(c) = std::env::var("EXECKIT_TEST_DOCKER") else {
        eprintln!("skip: set EXECKIT_TEST_DOCKER=<container> (needs git) to run");
        return;
    };
    // Workspace set, but no snapshot ever taken: restore must error clearly and
    // never run git against a default cwd.
    let mut s = session(&c, "/root/ck_noinit").with_auto_snapshot(false);
    let err = s
        .restore(&execkit::CheckpointId("deadbeef".into()))
        .unwrap_err();
    assert!(
        matches!(&err, execkit::Error::Unsupported(m) if m.contains("no checkpoint")),
        "got {err:?}"
    );
}
