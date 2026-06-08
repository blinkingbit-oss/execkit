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
    /// Commit SHA (the checkpoint id).
    pub id: String,
    pub label: String,
    /// Unix timestamp (seconds since the epoch) as a decimal string (git `%ct`).
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
// Note: `find` (-delete/-exec), `env`/`printenv` (run an arbitrary command),
// `uniq` (writes via its OUTPUT positional arg), and `sort`/`sed`/`awk`/`tee` are
// deliberately EXCLUDED - they can write or execute, so they always snapshot.
// Membership here assumes default (filesystem-read) usage of the program.
pub(crate) const READ_ONLY: &[&str] = &[
    "ls", "cat", "head", "tail", "grep", "egrep", "fgrep", "pwd", "echo", "printf", "which",
    "whoami", "id", "hostname", "uname", "date", "stat", "file", "wc", "cut", "ps", "df", "du",
    "free", "uptime",
];

/// True if `command` is unambiguously read-only (auto-snapshot can be skipped).
pub(crate) fn is_read_only(command: &str) -> bool {
    // Redirections, command substitution `$(...)`/backtick, and process
    // substitution `<(...)` can write or hide writes/execution. (`>(...)` is
    // covered by the `>` check.)
    if command.contains('>')
        || command.contains("$(")
        || command.contains('`')
        || command.contains("<(")
    {
        return false;
    }
    // Every segment of a pipeline / chain / multi-line script must start with an
    // allowlisted program. Newlines count: run_framed wraps the whole command in
    // `{ ...; }`, so every line runs.
    #[allow(clippy::manual_pattern_char_comparison)]
    for seg in command.split(|c| matches!(c, '|' | ';' | '&' | '\n' | '\r')) {
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

/// Regenerable build/cache output: written BEFORE user patterns so users may
/// legitimately override them (e.g. a project that tracks its `dist/` folder).
const BUILD_IGNORES: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".venv",
    "__pycache__",
    ".mypy_cache",
    "dist",
    "build",
];

/// Secret/credential paths: written AFTER user patterns so they are always the
/// LAST matching rules. gitignore semantics are "last match wins," so placing
/// these after any user-supplied negations (e.g. `!.ssh`) ensures a negation
/// cannot re-include them. Never capture or restore these paths.
///
/// `.execkit` is included here to prevent self-capture: if workspace == $HOME,
/// `git add` would walk into the live shadow git-dir and corrupt the index.
/// A user `!.execkit` negation CANNOT re-enable self-capture because SECRET_IGNORES
/// trails all user patterns.
const SECRET_IGNORES: &[&str] = &[".cache", ".ssh", ".gnupg", ".aws", ".netrc", ".execkit"];

/// Single-quote a value for safe use in a `/bin/sh` command.
pub(crate) fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Config + lazy state for a session's checkpoints. Builds command strings; the
/// Session runs them and feeds outputs back to the parsers.
pub(crate) struct Checkpointer {
    token: String,
    pub auto: bool,
    pub workspace: Option<String>, // explicit root; REQUIRED (no cwd fallback)
    paths: Vec<String>,            // sub-paths under root; default ["."]
    ignores: Vec<String>,          // extra exclude patterns (additive to defaults)
    pub root: Option<String>,      // resolved root (set on first snapshot)
    pub initialized: bool,
    pub git_unavailable: bool,
    pub last: Option<String>, // last checkpoint id
}

impl Checkpointer {
    pub fn new(token: &str, auto: bool, workspace: Option<String>, paths: Vec<String>) -> Self {
        // token is interpolated into a double-quoted shell string in git_dir(); it
        // MUST be all hex so no shell-special characters can sneak in. The caller
        // (unique_token) always produces hex, so this fires only in tests/dev.
        debug_assert!(
            token.bytes().all(|b| b.is_ascii_hexdigit()),
            "checkpoint token must be hex"
        );
        let paths = if paths.is_empty() {
            vec![".".into()]
        } else {
            paths
        };
        Self {
            token: token.to_string(),
            auto,
            workspace,
            paths,
            ignores: Vec::new(),
            root: None,
            initialized: false,
            git_unavailable: false,
            last: None,
        }
    }

    fn git_dir(&self) -> String {
        // $HOME expands on the remote; token is hex-safe so the rest is literal.
        format!("\"$HOME/.execkit/ckpt-{}.git\"", self.token)
    }

    fn pathspec(&self) -> String {
        self.paths
            .iter()
            .map(|p| shq(p))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn git(&self, root: &str) -> String {
        // -C <root> so git runs WITH cwd = the work-tree: the session's cwd is not
        // necessarily the workspace root, and pathspecs (`.`, `src`, ...) resolve
        // relative to cwd. Without this, `add -- .` captures nothing.
        format!(
            "git -C {root} --git-dir={gd} --work-tree={root}",
            root = shq(root),
            gd = self.git_dir()
        )
    }

    /// One-time: detect git, ensure the shadow repo exists with excludes set.
    pub fn init_cmd(&self, root: &str) -> String {
        // Order matters: gitignore uses "last match wins."
        // BUILD_IGNORES first (users may override), then user patterns, then
        // SECRET_IGNORES last (non-negotiable: any user negation in the middle
        // is overridden by the trailing secret rules).
        let mut all: Vec<&str> = BUILD_IGNORES.to_vec();
        all.extend(self.ignores.iter().map(String::as_str));
        all.extend_from_slice(SECRET_IGNORES);
        let excludes = all.join("\n");
        let g = self.git(root);
        format!(
            "mkdir -p \"$HOME/.execkit\" && {g} init -q && \
             printf '%s\\n' {ex} > {gd}/info/exclude",
            g = g,
            ex = shq(&excludes),
            gd = self.git_dir(),
        )
    }

    // Always commits with --allow-empty: auto-snapshot runs BEFORE each changing
    // command (to capture the pre-change baseline), so even an empty/unchanged
    // workspace must produce a restorable point (e.g. to undo the first file
    // creation in an empty workspace). The cost is one tiny empty commit per
    // unchanged write-ish command; pruning that growth without losing the baseline
    // is a future improvement.
    pub fn snapshot_cmd(&self, root: &str, label: &str) -> String {
        let g = self.git(root);
        format!(
            "{g} add -- {paths}; \
             {g} -c user.email=execkit@local -c user.name=execkit \
             commit -q --allow-empty -m {label} && {g} rev-parse HEAD",
            paths = self.pathspec(),
            label = shq(label),
        )
    }

    pub fn restore_cmd(&self, root: &str, id: &str) -> String {
        // id is agent-controlled (untrusted): single-quote it so a malicious value
        // becomes a harmless literal ref (git just fails to find it).
        let g = self.git(root);
        format!(
            "{g} checkout {id} -- {paths} && {g} clean -fdq -- {paths}",
            id = shq(id),
            paths = self.pathspec(),
        )
    }

    pub fn list_cmd(&self, root: &str) -> String {
        // "<sha> <unixtime> <subject>" per line, newest first. Space-delimited
        // (NOT a control char): SHA and unixtime are space-free, so splitn(3, ' ')
        // is unambiguous, and it survives the PTY + framing unmangled.
        format!("{} log --format='%H %ct %s'", self.git(root))
    }

    pub fn set_ignores(&mut self, ignores: Vec<String>) {
        self.ignores = ignores;
    }

    pub fn set_paths(&mut self, paths: Vec<String>) {
        self.paths = paths;
    }

    /// Count files differing from `id` within the checkpoint paths.
    pub fn diff_count_cmd(&self, root: &str, id: &str) -> String {
        format!(
            "{} diff --name-only {} -- {} | wc -l",
            self.git(root),
            shq(id),
            self.pathspec()
        )
    }
}

/// First whitespace-delimited token of git output (a commit SHA), or None.
pub(crate) fn parse_sha(out: &str) -> Option<String> {
    out.split_whitespace().next().map(|s| s.to_string())
}

/// Parse `list_cmd` output into checkpoints (newest first).
pub(crate) fn parse_log(out: &str) -> Vec<Checkpoint> {
    out.lines()
        .filter_map(|line| {
            let mut it = line.splitn(3, ' ');
            let id = it.next()?.trim();
            // SHA is 40 hex chars; ignore any non-commit noise lines.
            if id.len() != 40 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            let created = it.next().unwrap_or("").to_string();
            let label = it.next().unwrap_or("").to_string();
            Some(Checkpoint {
                id: id.to_string(),
                label,
                created,
            })
        })
        .collect()
}

#[cfg(test)]
mod builder_tests {
    use super::{shq, Checkpointer};

    fn cp() -> Checkpointer {
        Checkpointer::new("abc123", true, None, vec![".".into()])
    }

    #[test]
    fn shell_quote_is_safe() {
        assert_eq!(shq("/srv/app"), "'/srv/app'");
        assert_eq!(shq("a b"), "'a b'");
        assert_eq!(shq("it's"), "'it'\\''s'");
    }

    #[test]
    fn snapshot_and_restore_commands_are_scoped() {
        let c = cp();
        let root = "/srv/app";
        let snap = c.snapshot_cmd(root, "before");
        assert!(snap.contains("--git-dir=\"$HOME/.execkit/ckpt-abc123.git\""));
        assert!(snap.contains("--work-tree='/srv/app'"));
        assert!(snap.contains("add -- '.'"));
        assert!(snap.contains("commit -q --allow-empty"));

        let restore = c.restore_cmd(root, "deadbeef");
        assert!(restore.contains("checkout 'deadbeef' -- '.'"));
        assert!(restore.contains("clean -fdq -- '.'"));
    }

    #[test]
    fn multi_path_scopes_each_path() {
        let c = Checkpointer::new(
            "deadbeef",
            true,
            Some("/srv/app".into()),
            vec!["src".into(), "migrations".into()],
        );
        let snap = c.snapshot_cmd("/srv/app", "x");
        assert!(snap.contains("add -- 'src' 'migrations'"));
    }

    #[test]
    fn parse_commit_sha_takes_first_token() {
        assert_eq!(super::parse_sha("a1b2c3d4\n"), Some("a1b2c3d4".to_string()));
        assert_eq!(super::parse_sha("  \n"), None);
    }

    #[test]
    fn parse_log_reads_records() {
        // "<40-hex sha> <unixtime> <subject>" per line.
        let a = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let b = "cafebabecafebabecafebabecafebabecafebabe";
        let out = format!("{a} 1700000000 before refactor\n{b} 1699999999 init\n");
        let list = super::parse_log(&out);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, a);
        assert_eq!(list[0].created, "1700000000");
        assert_eq!(list[0].label, "before refactor");
        assert_eq!(list[1].id, b);
        // non-commit noise lines are ignored (only 40-hex-sha lines count).
        let noisy = format!("{a} 1700000000 x\n~~~ junk ~~~\n");
        assert_eq!(super::parse_log(&noisy).len(), 1);
    }

    #[test]
    fn init_cmd_excludes_defaults_plus_user_ignores() {
        let mut cp = Checkpointer::new("abc123", true, Some("/srv/app".into()), vec![".".into()]);
        cp.set_ignores(vec!["*.log".into(), "secrets".into()]);
        let cmd = cp.init_cmd("/srv/app");
        // a build default, a secret default, and both user patterns must appear.
        assert!(cmd.contains("node_modules"));
        assert!(cmd.contains(".ssh"));
        assert!(cmd.contains("*.log"));
        assert!(cmd.contains("secrets"));
        assert!(cmd.contains("info/exclude"));
        // SEC-6: .execkit must be excluded so workspace==$HOME does not self-capture.
        assert!(
            cmd.contains(".execkit"),
            ".execkit must appear in the excludes to prevent shadow git-dir self-capture"
        );
    }

    #[test]
    fn execkit_dir_excluded_as_non_negotiable_secret_ignore() {
        // Even if a user passes "!.execkit" as an ignore (trying to re-enable
        // self-capture), the trailing SECRET_IGNORES entry ".execkit" must win.
        let mut cp = Checkpointer::new("abc123", true, Some("/home/user".into()), vec![".".into()]);
        cp.set_ignores(vec!["!.execkit".into()]);
        let cmd = cp.init_cmd("/home/user");

        // Both the negation and the secret rule must be present.
        assert!(cmd.contains("!.execkit"), "user negation must appear");
        assert!(cmd.contains(".execkit"), "secret exclude must appear");

        // The LAST occurrence of ".execkit" in the exclude blob must NOT be
        // a negation -- i.e. SECRET_IGNORES ".execkit" wins over "!.execkit".
        let last_pos = cmd
            .rfind(".execkit")
            .expect(".execkit not found in command");
        let byte_before = if last_pos > 0 {
            cmd.as_bytes().get(last_pos - 1).copied()
        } else {
            None
        };
        assert_ne!(
            byte_before,
            Some(b'!'),
            "last occurrence of .execkit must not be a negation; SECRET_IGNORES must trail user patterns"
        );
    }

    #[test]
    fn init_cmd_secret_excludes_appear_after_user_negation() {
        // SEC-4: a user-supplied negation like `!.ssh` must be overridden by the
        // trailing SECRET_IGNORES entry.  gitignore last-match-wins means the rule
        // written LAST controls; we verify the position invariant here.
        let mut cp = Checkpointer::new("abc123", true, Some("/srv/app".into()), vec![".".into()]);
        cp.set_ignores(vec!["!.ssh".into()]);
        let cmd = cp.init_cmd("/srv/app");

        // Both the negation and the secret rule must be present.
        assert!(
            cmd.contains("!.ssh"),
            "user negation must appear in command"
        );
        assert!(
            cmd.contains(".ssh"),
            "secret exclude must appear in command"
        );

        // The LAST occurrence of `.ssh` in the exclude blob must not be preceded
        // by `!` -- i.e. the SECRET_IGNORES `.ssh` wins over the user `!.ssh`.
        let last_ssh_pos = cmd.rfind(".ssh").expect("`.ssh` not found in command");
        // Check the byte immediately before the match (if any).
        let byte_before = if last_ssh_pos > 0 {
            cmd.as_bytes().get(last_ssh_pos - 1).copied()
        } else {
            None
        };
        assert_ne!(
            byte_before,
            Some(b'!'),
            "last occurrence of `.ssh` must not be a negation (`!.ssh`); \
             SECRET_IGNORES must trail user patterns"
        );
    }
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
        assert!(!is_read_only("echo hi > f")); // redirection
        assert!(!is_read_only("sed -i s/a/b/ f")); // sed not allowlisted
        assert!(!is_read_only("ls && rm x")); // a segment writes
        assert!(!is_read_only("cat $(whoami)")); // command substitution
        assert!(!is_read_only("tee f")); // tee can write
        assert!(!is_read_only("npm install")); // unknown program
                                               // regression (final review): command/file gateways + newline-separated writes
        assert!(!is_read_only("find . -delete")); // find can delete / -exec
        assert!(!is_read_only("env X=1 rm -rf y")); // env runs a command
        assert!(!is_read_only("uptime\nrm -rf /tmp/x")); // newline -> second line writes
        assert!(!is_read_only("cat <(rm x)")); // process substitution executes rm
        assert!(!is_read_only("uniq in out")); // uniq OUTPUT positional writes a file
    }
}
