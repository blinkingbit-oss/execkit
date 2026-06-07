// SPDX-License-Identifier: Apache-2.0
//! Remote workspace checkpoints: git-backed "undo" for an agent's file changes.
//!
//! Pure logic only - command strings, output parsing, and read-only command
//! classification. `Session` runs the commands over its transport (see
//! `session.rs`); keeping the logic transport-free makes it unit-testable.

use serde::Serialize;

/// A checkpoint identifier: a commit SHA in the shadow git repo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckpointId(pub String);

/// One checkpoint in the linear history.
#[derive(Debug, Clone, Serialize)]
pub struct Checkpoint {
    pub id: String,
    pub label: String,
    pub created: String,
}

/// What a restore changed.
#[derive(Debug, Clone, Serialize)]
pub struct RestoreReport {
    pub restored_to: String,
    pub files_changed: usize,
}

/// Programs that never write the filesystem in normal use. Conservative:
/// anything not here, any redirection, or command substitution => snapshot.
pub(crate) const READ_ONLY: &[&str] = &[
    "ls", "cat", "head", "tail", "grep", "egrep", "fgrep", "find", "pwd", "echo",
    "printf", "env", "printenv", "which", "whoami", "id", "hostname", "uname",
    "date", "stat", "file", "wc", "cut", "uniq", "ps", "df", "du", "free", "uptime",
];

/// True if `command` is unambiguously read-only (auto-snapshot can be skipped).
pub(crate) fn is_read_only(command: &str) -> bool {
    // Redirections and command substitution can write or hide writes.
    if command.contains('>') || command.contains("$(") || command.contains('`') {
        return false;
    }
    // Every segment of a pipeline / chain must start with an allowlisted program.
    for seg in command.split(|c| matches!(c, '|' | ';' | '&')) {
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        let prog = seg.split_whitespace().next().unwrap_or("");
        let base = prog.rsplit('/').next().unwrap_or(prog);
        if !READ_ONLY.contains(&base) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod read_only_tests {
    use super::is_read_only;

    #[test]
    fn classifies_commands() {
        // read-only -> true
        assert!(is_read_only("ls -la"));
        assert!(is_read_only("cat f | grep x"));
        assert!(is_read_only("ls; cat f"));
        assert!(is_read_only("/bin/ls /tmp"));
        assert!(is_read_only("ps aux | grep nginx"));
        // writing / ambiguous -> false
        assert!(!is_read_only("rm -rf build"));
        assert!(!is_read_only("echo hi > f"));      // redirection
        assert!(!is_read_only("sed -i s/a/b/ f"));  // sed not allowlisted
        assert!(!is_read_only("ls && rm x"));       // a segment writes
        assert!(!is_read_only("cat $(whoami)"));    // command substitution
        assert!(!is_read_only("tee f"));            // tee can write
        assert!(!is_read_only("npm install"));      // unknown program
    }
}
