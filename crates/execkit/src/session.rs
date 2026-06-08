// SPDX-License-Identifier: Apache-2.0
//! A persistent session: frame each command with unguessable start/end sentinels
//! that carry exit code + cwd, and dump the command's stderr back *through the
//! channel* between them - so the framing is identical for local and remote
//! transports (no local-filesystem dependency). Then apply policy, redaction,
//! bounding, and audit.

use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::audit::AuditLog;
use crate::budget::{self, Budget};
use crate::checkpoint::{self, Checkpoint, Checkpointer, RestoreReport};
use crate::error::{Error, Result};
use crate::exec::ExecResult;
use crate::output::clean;
use crate::policy::Policy;
use crate::redact::redact;
use crate::transport::{self, local::LocalPty, Transport};

const US: u8 = 0x1f; // unit separator

/// A live, stateful shell session.
pub struct Session {
    io: Box<dyn Transport>,
    token: String,
    policy: Option<Policy>,
    audit: Option<AuditLog>,
    timeout: Duration,
    max_output: usize,
    /// Default budget applied to every `exec` that does not pass its own.
    output_budget: Option<Budget>,
    /// Set after a timeout: the prior command is still running and would desync
    /// framing, so the session refuses further commands.
    poisoned: bool,
    /// Some only for remote (ssh/docker) sessions; None for local.
    checkpointer: Option<Checkpointer>,
}

impl Session {
    /// Open a session backed by a local `bash` PTY.
    pub fn local() -> Result<Self> {
        let pty = LocalPty::spawn("bash", &["--norc", "--noprofile"])?;
        Self::from_transport(Box::new(pty), false)
    }

    /// Open a session over SSH.
    #[cfg(feature = "ssh")]
    pub fn ssh(config: crate::transport::ssh::SshConfig) -> Result<Self> {
        let t = crate::transport::ssh::SshTransport::connect(config)?;
        Self::from_transport(Box::new(t), true)
    }

    /// Open a session inside a running Docker container via `docker exec`.
    ///
    /// `container` is a name or ID. Requires the `docker` CLI on PATH and a
    /// running container with a POSIX `/bin/sh`. No extra dependencies - this is
    /// the local PTY transport driving `docker exec`, so the same framing,
    /// policy, redaction, and bounding apply.
    ///
    /// On drop (including after a timeout) it makes a best-effort attempt to kill
    /// the in-container shell and any command it spawned - killing the local
    /// `docker exec` client alone would leave them running in the container.
    pub fn docker(container: &str) -> Result<Self> {
        // `container` is caller/agent-controlled (untrusted via MCP). Validate it
        // against Docker's name/id charset so it can't carry shell/flag tricks
        // (the transport also passes it after `--`).
        if !is_valid_container_ref(container) {
            return Err(Error::Transport("invalid docker container name/id".into()));
        }
        let t = crate::transport::docker::DockerExec::spawn(container, &unique_token())?;
        Self::from_transport(Box::new(t), true)
    }

    /// Build a session over any transport: run the readiness handshake and set
    /// up the per-session sentinel token.
    fn from_transport(mut io: Box<dyn Transport>, remote: bool) -> Result<Self> {
        transport::shell_init(io.as_mut())?;
        let token = unique_token();
        let checkpointer = remote.then(|| Checkpointer::new(&token, true, None, vec![".".into()]));
        Ok(Self {
            io,
            token,
            policy: None,
            audit: None,
            timeout: Duration::from_secs(30),
            max_output: 100_000,
            output_budget: None,
            poisoned: false,
            checkpointer,
        })
    }

    /// Attach an advisory policy (checked before each command runs).
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Attach an audit log (every result is appended).
    pub fn with_audit(mut self, audit: AuditLog) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Set the per-command completion timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Cap the (char) size of returned stdout/stderr; also bounds in-memory
    /// accumulation so a flooding command can't exhaust RAM.
    pub fn with_max_output(mut self, max: usize) -> Self {
        self.max_output = max;
        self
    }

    /// Default output budget applied to every `exec` that does not pass its own.
    pub fn with_output_budget(mut self, budget: Budget) -> Self {
        self.output_budget = Some(budget);
        self
    }

    /// True if a prior timeout left the session unusable.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Run a command and return a structured [`ExecResult`].
    ///
    /// On a completion timeout this returns [`Error::StillRunning`] and poisons
    /// the session (subsequent calls return [`Error::SessionPoisoned`]).
    pub fn exec(&mut self, command: &str) -> Result<ExecResult> {
        let budget = self.output_budget.clone().unwrap_or_default();
        self.exec_inner(command, &budget)
    }

    /// Like [`Session::exec`], but shape this command's output with `budget`
    /// (overrides any session-default budget).
    pub fn exec_budgeted(&mut self, command: &str, budget: &Budget) -> Result<ExecResult> {
        self.exec_inner(command, budget)
    }

    fn exec_inner(&mut self, command: &str, budget: &Budget) -> Result<ExecResult> {
        if self.poisoned {
            return Err(Error::SessionPoisoned);
        }
        // Fail fast on a bad/oversized grep regex BEFORE running the command.
        if let Some(g) = &budget.grep {
            budget::compile_grep(&g.pattern)?;
        }
        if let Some(p) = &self.policy {
            if let Err(reason) = p.check(command) {
                return Err(Error::PolicyDenied(reason));
            }
        }
        self.maybe_auto_snapshot(command);
        // A slow auto-snapshot can time out and poison the session; running the
        // real command now would desync framing on the still-busy channel.
        if self.poisoned {
            return Err(Error::SessionPoisoned);
        }
        let started = Instant::now();
        let f = self.run_framed(command)?;
        let (stdout, rep_out, cap_out) =
            budget::apply(&redact(&f.stdout), budget, self.max_output)?;
        let (stderr, rep_err, cap_err) =
            budget::apply(&redact(&f.stderr), budget, self.max_output)?;
        let report = if *budget != Budget::default() {
            Some(crate::budget::BudgetReport {
                stdout: rep_out.clone(),
                stderr: rep_err.clone(),
            })
        } else {
            None
        };
        let result = ExecResult {
            command: command.to_string(),
            stdout,
            stderr,
            exit_code: f.exit_code,
            duration_ms: started.elapsed().as_millis() as u64,
            cwd: f.cwd,
            truncated: cap_out
                || cap_err
                || rep_out.lines_kept < rep_out.lines_total
                || rep_err.lines_kept < rep_err.lines_total
                || f.overflowed,
            budget: report,
        };
        if let Some(a) = &self.audit {
            if let Err(e) = a.record(&result) {
                eprintln!("execkit: audit write failed: {e}");
            }
        }
        Ok(result)
    }

    /// Before a changing remote command, take a snapshot (best-effort). Skipped
    /// for local sessions, when auto is off, for read-only commands, and silently
    /// if git is missing on the remote (so the user's command still runs).
    fn maybe_auto_snapshot(&mut self, command: &str) {
        // Auto-snapshot only when a workspace is explicitly set: without one we
        // will NOT silently snapshot the cwd (often $HOME - slow + leaks secrets).
        let should = matches!(&self.checkpointer,
            Some(cp) if cp.auto && !cp.git_unavailable && cp.workspace.is_some())
            && !checkpoint::is_read_only(command);
        if !should {
            return;
        }
        match self.ensure_init() {
            Ok(()) => {}
            Err(_) => return, // git missing / init failed: degrade, run the command
        }
        let root = self.cp_root();
        let cmd = self
            .checkpointer
            .as_ref()
            .unwrap()
            .snapshot_cmd(&root, "auto");
        if let Ok(f) = self.run_framed(&cmd) {
            if let Some(sha) = checkpoint::parse_sha(&f.stdout) {
                self.checkpointer.as_mut().unwrap().last = Some(sha);
            }
        }
    }

    /// Enable/disable auto-snapshot before changing remote commands (default on
    /// for remote sessions; no-op on local).
    pub fn with_auto_snapshot(mut self, on: bool) -> Self {
        if let Some(cp) = &mut self.checkpointer {
            cp.auto = on;
        }
        self
    }

    /// Set the remote workspace root checkpoints anchor at. REQUIRED to enable
    /// checkpoints - there is no default and it never falls back to the cwd/home
    /// dir. No-op on local.
    pub fn with_workspace(mut self, root: impl Into<String>) -> Self {
        if let Some(cp) = &mut self.checkpointer {
            cp.workspace = Some(root.into());
        }
        self
    }

    /// Set the sub-paths under the root to checkpoint (default ["."]). No-op on local.
    pub fn with_checkpoint_paths<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if let Some(cp) = &mut self.checkpointer {
            let v: Vec<String> = paths.into_iter().map(Into::into).collect();
            if !v.is_empty() {
                cp.set_paths(v);
            }
        }
        self
    }

    /// Add exclude patterns (gitignore syntax) to snapshots, on top of the
    /// built-in defaults. Written to the shadow repo's info/exclude. No-op on local.
    pub fn with_checkpoint_ignores<I, S>(mut self, ignores: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if let Some(cp) = &mut self.checkpointer {
            cp.set_ignores(ignores.into_iter().map(Into::into).collect());
        }
        self
    }

    /// Take a checkpoint now. Remote-only.
    pub fn checkpoint(&mut self, label: Option<&str>) -> Result<crate::CheckpointId> {
        self.require_workspace()?;
        self.ensure_init()?;
        let label = label.unwrap_or("checkpoint").to_string();
        let root = self.cp_root();
        let cmd = self
            .checkpointer
            .as_ref()
            .unwrap()
            .snapshot_cmd(&root, &label);
        let f = self.run_framed(&cmd)?;
        let sha = checkpoint::parse_sha(&f.stdout)
            .ok_or_else(|| Error::Transport(format!("checkpoint failed: {}", f.stderr.trim())))?;
        self.checkpointer.as_mut().unwrap().last = Some(sha.clone());
        Ok(crate::CheckpointId(sha))
    }

    /// List checkpoints, newest first. Remote-only.
    pub fn checkpoints(&mut self) -> Result<Vec<Checkpoint>> {
        self.require_workspace()?;
        if !self.checkpointer.as_ref().unwrap().initialized {
            return Ok(vec![]);
        }
        let root = self.cp_root();
        let cmd = self.checkpointer.as_ref().unwrap().list_cmd(&root);
        let f = self.run_framed(&cmd)?;
        Ok(checkpoint::parse_log(&f.stdout))
    }

    /// Restore the workspace files to a checkpoint. Remote-only.
    pub fn restore(&mut self, id: &crate::CheckpointId) -> Result<RestoreReport> {
        self.require_workspace()?;
        // No shadow repo yet => nothing to restore. Guard before cp_root() so we
        // never point git at a default cwd.
        if !self.checkpointer.as_ref().unwrap().initialized {
            return Err(Error::Unsupported(
                "no checkpoints yet in this session".into(),
            ));
        }
        // A checkpoint id is ALWAYS a git commit SHA (from parse_sha/parse_log).
        // It is shq-quoted before use (no shell injection), but a non-hex value
        // like "--output=/path" would be parsed by git as an OPTION, letting it
        // write/overwrite files OUTSIDE the workspace. Reject anything that is not
        // hex BEFORE running diff_count_cmd or restore_cmd (the only two builders
        // that take the id - confirmed restore() is their sole caller).
        if !is_valid_checkpoint_id(&id.0) {
            return Err(Error::Unsupported("invalid checkpoint id".into()));
        }
        let root = self.cp_root();
        // Count differing files BEFORE reverting (best-effort; informational).
        let diff_cmd = self
            .checkpointer
            .as_ref()
            .unwrap()
            .diff_count_cmd(&root, &id.0);
        let changed = self
            .run_framed(&diff_cmd)
            .ok()
            .and_then(|f| f.stdout.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let cmd = self
            .checkpointer
            .as_ref()
            .unwrap()
            .restore_cmd(&root, &id.0);
        let f = self.run_framed(&cmd)?;
        if f.exit_code != 0 {
            return Err(Error::Transport(format!(
                "restore failed: {}",
                f.stderr.trim()
            )));
        }
        Ok(RestoreReport {
            restored_to: id.0.clone(),
            files_changed: changed,
        })
    }

    /// Restore the most recent checkpoint. Remote-only.
    pub fn restore_last(&mut self) -> Result<RestoreReport> {
        self.require_workspace()?;
        let last = self
            .checkpointer
            .as_ref()
            .unwrap()
            .last
            .clone()
            .ok_or_else(|| Error::Unsupported("no checkpoint to restore".into()))?;
        self.restore(&crate::CheckpointId(last))
    }

    fn require_remote(&self) -> Result<()> {
        match &self.checkpointer {
            Some(_) => Ok(()),
            None => Err(Error::Unsupported(
                "checkpoints are available only for remote sessions".into(),
            )),
        }
    }

    /// Remote AND an explicit workspace set (checkpoints never default to cwd).
    fn require_workspace(&self) -> Result<()> {
        self.require_remote()?;
        match &self.checkpointer {
            Some(cp) if cp.workspace.is_some() => Ok(()),
            _ => Err(Error::Unsupported(
                "checkpoints require an explicit workspace; set it with with_workspace() \
                 (library) or the 'workspace' param (MCP)"
                    .into(),
            )),
        }
    }

    fn cp_root(&self) -> String {
        self.checkpointer
            .as_ref()
            .unwrap()
            .root
            .clone()
            .unwrap_or_else(|| ".".into())
    }

    /// Lazily detect git and init the shadow repo. Sets `git_unavailable` if git
    /// is missing (caller decides whether to error or skip).
    fn ensure_init(&mut self) -> Result<()> {
        let cp = self.checkpointer.as_ref().unwrap();
        if cp.initialized {
            return Ok(());
        }
        if cp.git_unavailable {
            return Err(Error::Unsupported(
                "checkpoints need git on the remote host - install it (e.g. apt/apk/yum install git)"
                    .into(),
            ));
        }
        // git present?
        let probe = self.run_framed("command -v git >/dev/null 2>&1 && echo OK || echo NO")?;
        if probe.stdout.trim() != "OK" {
            self.checkpointer.as_mut().unwrap().git_unavailable = true;
            return Err(Error::Unsupported(
                "checkpoints need git on the remote host - install it (e.g. apt/apk/yum install git)"
                    .into(),
            ));
        }
        // An explicit workspace is REQUIRED - never fall back to cwd ($HOME).
        let root = self
            .checkpointer
            .as_ref()
            .unwrap()
            .workspace
            .clone()
            .ok_or_else(|| {
                Error::Unsupported(
                    "checkpoints require an explicit workspace; set it with \
                     with_workspace() (library) or the 'workspace' param (MCP)"
                        .into(),
                )
            })?;
        let init = self.checkpointer.as_ref().unwrap().init_cmd(&root);
        let f = self.run_framed(&init)?;
        if f.exit_code != 0 {
            return Err(Error::Transport(format!(
                "checkpoint init failed: {}",
                f.stderr.trim()
            )));
        }
        let cp = self.checkpointer.as_mut().unwrap();
        cp.root = Some(root);
        cp.initialized = true;
        Ok(())
    }

    /// Run one command through the sentinel framing; return raw cleaned output.
    /// No policy, redaction, bounding, audit, or auto-snapshot - callers add what
    /// they need. Poisons the session on timeout.
    fn run_framed(&mut self, command: &str) -> Result<Framed> {
        let start_m = format!("__EXECKIT_{}__", self.token);
        let end_m = format!("__EXECKITEND_{}__", self.token);
        let payload = format!(
            "__E=$(umask 077; mktemp 2>/dev/null||{{ f=/tmp/execkitE_{tok}; : >\"$f\"; echo \"$f\"; }}); \
{{ {cmd} ; }} 2>\"$__E\"; \
printf '\\n{start}\\037%d\\037%s\\037' \"$?\" \"$PWD\"; cat \"$__E\" 2>/dev/null; \
printf '{end}\\n'; rm -f \"$__E\"\n",
            tok = self.token, cmd = command, start = start_m, end = end_m,
        );
        self.io.write_all(payload.as_bytes())?;

        let start_b = start_m.as_bytes();
        let end_b = end_m.as_bytes();
        let max_acc = self.max_output.saturating_mul(2).max(65_536);
        let mut acc: Vec<u8> = Vec::new();
        let mut overflowed = false;
        let deadline = Instant::now() + self.timeout;

        loop {
            let now = Instant::now();
            if now >= deadline {
                self.poisoned = true;
                return Err(Error::StillRunning);
            }
            let chunk = match self.io.recv_timeout(deadline - now) {
                Some(c) => c,
                None => {
                    self.poisoned = true;
                    return Err(Error::StillRunning);
                }
            };
            acc.extend_from_slice(&chunk);
            if acc.len() > max_acc {
                let keep = max_acc / 2;
                let tail_start = acc.len() - keep;
                let mut compacted = Vec::with_capacity(keep * 2);
                compacted.extend_from_slice(&acc[..keep]);
                compacted.extend_from_slice(&acc[tail_start..]);
                acc = compacted;
                overflowed = true;
            }
            let Some(end_pos) = find(&acc, end_b) else {
                continue;
            };
            let Some(start_pos) = find(&acc[..end_pos], start_b) else {
                continue;
            };
            let between = &acc[start_pos + start_b.len()..end_pos];
            let seps: Vec<usize> = between
                .iter()
                .enumerate()
                .filter(|(_, b)| **b == US)
                .map(|(i, _)| i)
                .collect();
            if seps.len() < 3 {
                continue;
            }
            let exit_code: i32 = String::from_utf8_lossy(&between[seps[0] + 1..seps[1]])
                .trim()
                .parse()
                .unwrap_or(-1);
            let cwd = String::from_utf8_lossy(&between[seps[1] + 1..seps[2]]).into_owned();
            let stderr = clean(&String::from_utf8_lossy(&between[seps[2] + 1..]));
            let stdout = clean(&String::from_utf8_lossy(&acc[..start_pos]));
            return Ok(Framed {
                stdout,
                stderr,
                exit_code,
                cwd,
                overflowed,
            });
        }
    }
}

/// Raw result of one framed command (pre-redaction/bounding).
struct Framed {
    stdout: String,
    stderr: String,
    exit_code: i32,
    cwd: String,
    overflowed: bool,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Docker container names/ids: first char alphanumeric, then `[A-Za-z0-9_.-]`.
/// Covers 64-hex ids too. Rejects empty, a leading `-`, and any shell/flag
/// metacharacters - so the value can't smuggle `docker exec` flags or shell tricks.
fn is_valid_container_ref(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// A checkpoint id is a git commit SHA: 4-40 ASCII hex chars (git accepts
/// unambiguous short prefixes). Rejecting anything else stops a `-`-leading id
/// from being parsed by git as an option (e.g. `--output=<file>`).
fn is_valid_checkpoint_id(s: &str) -> bool {
    let n = s.len();
    (4..=40).contains(&n) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn unique_token() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    // Unpredictable suffix so command output can't forge the sentinels and the
    // remote temp-file fallback path can't be guessed.
    let mut rnd = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut rnd);
    }
    let rhex: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    format!("{nanos:x}{n:x}{rhex}")
}

#[cfg(test)]
mod checkpoint_api_tests {
    use crate::error::Error;
    use crate::Session;

    #[test]
    fn checkpoints_unsupported_on_local() {
        let mut s = Session::local().unwrap();
        assert!(matches!(s.checkpoint(None), Err(Error::Unsupported(_))));
        assert!(matches!(s.restore_last(), Err(Error::Unsupported(_))));
        assert!(matches!(s.checkpoints(), Err(Error::Unsupported(_))));
    }
}

#[cfg(test)]
mod tests {
    use super::{is_valid_checkpoint_id, is_valid_container_ref};

    #[test]
    fn checkpoint_id_validation() {
        // Valid: full and short SHAs.
        assert!(is_valid_checkpoint_id("deadbeef"));
        assert!(is_valid_checkpoint_id("0a1b"));
        assert!(is_valid_checkpoint_id(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        ));
        // Invalid: option injection, empty/short, over-length, non-hex.
        assert!(!is_valid_checkpoint_id("--output=/tmp/pwn/victim"));
        assert!(!is_valid_checkpoint_id("-d"));
        assert!(!is_valid_checkpoint_id(""));
        assert!(!is_valid_checkpoint_id("abc")); // too short (<4)
        assert!(!is_valid_checkpoint_id(&"a".repeat(41))); // too long (>40)
        assert!(!is_valid_checkpoint_id("dead beef")); // space
        assert!(!is_valid_checkpoint_id("HEAD~1")); // non-hex ref expression
        assert!(!is_valid_checkpoint_id("zzzz")); // non-hex letters
    }

    #[test]
    fn container_ref_validation() {
        // Valid: names and 64-hex ids.
        assert!(is_valid_container_ref("my_app"));
        assert!(is_valid_container_ref("web-1.test"));
        assert!(is_valid_container_ref("0a1b2c3d4e5f"));
        // Invalid: flag smuggling, empty, shell metacharacters.
        assert!(!is_valid_container_ref(""));
        assert!(!is_valid_container_ref("-it"));
        assert!(!is_valid_container_ref("--privileged"));
        assert!(!is_valid_container_ref("a b"));
        assert!(!is_valid_container_ref("a;rm -rf /"));
        assert!(!is_valid_container_ref("a$(whoami)"));
        assert!(!is_valid_container_ref("a\nrm")); // embedded newline
        assert!(!is_valid_container_ref("..")); // leading dot
        assert!(!is_valid_container_ref("ａlpine")); // unicode fullwidth lookalike
    }
}
