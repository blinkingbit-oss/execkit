// SPDX-License-Identifier: Apache-2.0
//! A persistent session: frame each command (see [`crate::framing`]) with
//! fresh, unguessable start/end sentinels that carry exit code + cwd, and dump
//! the command's stderr back *through the channel* between them - so the
//! framing is identical for local and remote transports (no local-filesystem
//! dependency). Then apply policy, redaction, bounding, and audit.

use std::time::{Duration, Instant};

use crate::audit::AuditLog;
use crate::budget::{self, Budget};
use crate::checkpoint::{self, Checkpoint, Checkpointer, RestoreReport};
use crate::error::{Error, Result};
use crate::exec::ExecResult;
use crate::framing::{self, Markers};
use crate::policy::Policy;
use crate::redact::Redactor;
use crate::transport::{self, local::LocalPty, Transport};

/// A live, stateful shell session.
pub struct Session {
    io: Box<dyn Transport>,
    policy: Option<Policy>,
    audit: Option<AuditLog>,
    timeout: Duration,
    max_output: usize,
    /// Default budget applied to every `exec` that does not pass its own.
    output_budget: Option<Budget>,
    /// Set when a timed-out command could not be interrupted (or the shell
    /// exited): its later output would desync framing, so the session refuses
    /// further commands.
    poisoned: bool,
    /// Some only for remote (ssh/docker) sessions; None for local.
    checkpointer: Option<Checkpointer>,
    /// Learns secret-shaped literal values from commands this session runs
    /// (see `exec_inner`), so output/command echoing them is redacted even
    /// when the value doesn't match a fixed pattern.
    redactor: Redactor,
}

impl Session {
    /// Open a session backed by a local `bash` PTY.
    pub fn local() -> Result<Self> {
        Self::local_shell("bash", &["--norc", "--noprofile"])
    }

    /// Like [`Session::local`] but with a chosen shell (e.g. `sh -i` to exercise
    /// dash/busybox semantics). Test hook; not part of the supported API.
    #[doc(hidden)]
    pub fn local_shell(shell: &str, args: &[&str]) -> Result<Self> {
        // SEC: drop HISTFILE so the shell never writes agent commands (which
        // may carry secrets) to ~/.bash_history; shell_init also turns history
        // off in-session.
        let pty = LocalPty::spawn_with_env(shell, args, &[("HISTFILE", None)])?;
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

    /// Build a session over any transport: run the readiness handshake. The
    /// sentinel token is per command (see `run_framed`); the session token here
    /// only names the checkpoint shadow repo.
    fn from_transport(mut io: Box<dyn Transport>, remote: bool) -> Result<Self> {
        transport::shell_init(io.as_mut())?;
        let token = unique_token();
        let checkpointer = remote.then(|| Checkpointer::new(&token, true, None, vec![".".into()]));
        Ok(Self {
            io,
            policy: None,
            audit: None,
            timeout: Duration::from_secs(30),
            max_output: 100_000,
            output_budget: None,
            poisoned: false,
            checkpointer,
            redactor: Redactor::default(),
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

    /// Change the per-command completion timeout on a live session.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
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

    /// True if the session is unusable: a timed-out command could not be
    /// interrupted, or the shell exited.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// The shadow repo's basename (`ckpt-<token>.git`) for this session's
    /// checkpoints, if it has one (remote sessions only). Test hook; not part
    /// of the supported API.
    #[doc(hidden)]
    pub fn checkpoint_shadow_repo_name(&self) -> Option<String> {
        self.checkpointer
            .as_ref()
            .map(Checkpointer::shadow_repo_name)
    }

    /// Run a command and return a structured [`ExecResult`].
    ///
    /// If the command outlives the session timeout, execkit sends Ctrl-C,
    /// resyncs the shell and returns `Ok` with `timed_out: true` and exit code
    /// 124; the session (cwd, env) stays usable. Only if the command cannot be
    /// interrupted does this return [`Error::StillRunning`] and poison the
    /// session (subsequent calls return [`Error::SessionPoisoned`]). If the
    /// shell itself exits (e.g. the command ran `exit`), it returns
    /// [`Error::ShellExited`] and likewise poisons the session.
    pub fn exec(&mut self, command: &str) -> Result<ExecResult> {
        self.exec_with_timeout(command, None, self.timeout)
    }

    /// Like [`Session::exec`], but shape this command's output with `budget`
    /// (overrides any session-default budget).
    pub fn exec_budgeted(&mut self, command: &str, budget: &Budget) -> Result<ExecResult> {
        self.exec_with_timeout(command, Some(budget), self.timeout)
    }

    /// Like [`Session::exec`], with an explicit `timeout` for this call only
    /// and an optional `budget` (`None` uses the session-default budget).
    pub fn exec_with_timeout(
        &mut self,
        command: &str,
        budget: Option<&Budget>,
        timeout: Duration,
    ) -> Result<ExecResult> {
        let budget = match budget {
            Some(b) => b.clone(),
            None => self.output_budget.clone().unwrap_or_default(),
        };
        self.exec_inner(command, &budget, timeout)
    }

    fn exec_inner(
        &mut self,
        command: &str,
        budget: &Budget,
        timeout: Duration,
    ) -> Result<ExecResult> {
        if self.poisoned {
            return Err(Error::SessionPoisoned);
        }
        // Learn secret-shaped literal values from this command first, so
        // even a value with no recognizable shape (e.g. a freshly generated
        // password) is redacted from this same command's echoed output below.
        self.redactor.learn_from_command(command);
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
        // Budgets need to see the FULL output to report a true line total and
        // let grep find a match anywhere (not just in the last ~200 KB): give
        // the accumulator a much larger cap whenever a non-default budget is
        // shaping this call. Plain (unbudgeted) output keeps the smaller
        // cap - it's returned to the caller as-is, so bounding it early still
        // protects memory without changing behaviour.
        let acc_cap = if *budget != Budget::default() {
            BUDGET_ACC_CAP
        } else {
            self.default_acc_cap()
        };
        let f = self.run_framed_for(command, timeout, acc_cap)?;
        let (stdout, rep_out, cap_out) =
            budget::apply(&self.redactor.redact(&f.stdout), budget, self.max_output)?;
        let (stderr, rep_err, cap_err) =
            budget::apply(&self.redactor.redact(&f.stderr), budget, self.max_output)?;
        let report = if *budget != Budget::default() {
            Some(crate::budget::BudgetReport {
                stdout: rep_out.clone(),
                stderr: rep_err.clone(),
            })
        } else {
            None
        };
        let result = ExecResult {
            command: self.redactor.redact(command),
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
            timed_out: f.timed_out,
        };
        if let Some(a) = &self.audit {
            if let Err(e) = a.record(&result) {
                eprintln!("execkit: audit write failed: {e}");
            }
        }
        Ok(result)
    }

    /// Redact `cmd` as this session would redact its own `command` field:
    /// secret shapes, values learned from earlier commands, and values `cmd`
    /// itself assigns to secret-shaped names. Nothing is learned for later.
    /// For commands rejected before they reach [`Session::exec`] (e.g. by an
    /// outer policy) that still need to be logged.
    pub fn redact_command(&self, cmd: &str) -> String {
        self.redactor.redact_command(cmd)
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

    /// List checkpoints, newest first. Remote-only. Returns an empty list (not an
    /// error) when no workspace is set or nothing has been snapshotted yet.
    pub fn checkpoints(&mut self) -> Result<Vec<Checkpoint>> {
        self.require_remote()?;
        let cp = self.checkpointer.as_ref().unwrap();
        if cp.workspace.is_none() || !cp.initialized {
            return Ok(vec![]);
        }
        let root = self.cp_root();
        let cmd = self.checkpointer.as_ref().unwrap().list_cmd(&root);
        let f = self.run_framed(&cmd)?;
        Ok(checkpoint::parse_log(&f.stdout))
    }

    /// Restore the workspace files to a checkpoint. Remote-only.
    ///
    /// WARNING: this is destructive - it reverts tracked files AND deletes untracked
    /// files/dirs anywhere under the workspace (git clean), not only files created
    /// since the checkpoint.
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
    ///
    /// WARNING: this is destructive - it reverts tracked files AND deletes untracked
    /// files/dirs anywhere under the workspace (git clean), not only files created
    /// since the checkpoint.
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

    /// [`Session::run_framed_for`] with the session timeout, for execkit's own
    /// commands (checkpoints, probes). A timeout is an error here: partial
    /// output from an interrupted internal command must not be parsed as a
    /// result. The session itself stays usable.
    fn run_framed(&mut self, command: &str) -> Result<Framed> {
        let acc_cap = self.default_acc_cap();
        let f = self.run_framed_for(command, self.timeout, acc_cap)?;
        if f.timed_out {
            return Err(Error::Transport(format!(
                "internal command timed out after {}s and was interrupted",
                self.timeout.as_secs_f64()
            )));
        }
        Ok(f)
    }

    /// The default in-memory accumulation cap: for plain (unbudgeted) output,
    /// where whatever survives compaction is what the caller gets back.
    fn default_acc_cap(&self) -> usize {
        self.max_output.saturating_mul(2).max(65_536)
    }

    /// Run one command through the sentinel framing; return raw cleaned output.
    /// No policy, redaction, bounding, audit, or auto-snapshot - callers add what
    /// they need. On timeout it interrupts and resyncs (see [`Session::exec`]);
    /// it poisons the session only if that fails or the shell exits.
    ///
    /// `acc_cap` bounds how much of the command's output is kept in memory:
    /// once the buffer passes `2 * acc_cap` it is compacted back to about
    /// `acc_cap`: stdout's head and tail halves, and stderr (which arrives
    /// after stdout) separately to its own head and tail, at least a quarter
    /// each. A small cap is fine for plain exec (the caller only sees that
    /// much anyway), but a budget (grep/head/tail/max_chars)
    /// needs to see the FULL output to report true line totals and find matches
    /// anywhere - callers pass a much larger cap in that case (see `exec_inner`).
    fn run_framed_for(
        &mut self,
        command: &str,
        timeout: Duration,
        acc_cap: usize,
    ) -> Result<Framed> {
        // SEC: a fresh token per command, so a marker seen (or guessed) during
        // one command is useless for forging the next one's result.
        let token = framing::new_token();
        let markers = Markers::new(&token);
        self.io
            .write_all(framing::build_payload(command, &token).as_bytes())?;

        let mut acc = framing::Accumulator::new(acc_cap);
        let deadline = Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return self.interrupt(&acc, &markers, timeout);
            }
            let chunk = match self.io.recv_timeout(remaining) {
                Some(c) => c,
                // None at the deadline is a plain timeout.
                None if Instant::now() >= deadline => {
                    return self.interrupt(&acc, &markers, timeout);
                }
                None => {
                    // None with time still on the clock means the channel closed
                    // (the shell exited - e.g. the command ran `exit`), which is a
                    // distinct, immediately-clear failure from a timeout.
                    self.poisoned = true;
                    return Err(Error::ShellExited);
                }
            };
            if let Some(p) = acc.push(&chunk, &markers) {
                return Ok(Framed {
                    stdout: p.stdout,
                    stderr: p.stderr,
                    exit_code: p.exit_code,
                    cwd: p.cwd,
                    overflowed: acc.overflowed(),
                    timed_out: false,
                });
            }
        }
    }

    /// The deadline passed: send Ctrl-C, resync the shell, and report the
    /// output captured so far as a timed-out result. If the shell does not
    /// come back, poison the session and return [`Error::StillRunning`].
    ///
    /// `shell_init` turned job control off (`set +m`), so the command runs in
    /// the shell's process group: the `\x03` sends SIGINT to it, and the shell
    /// abandons the rest of the run line (the trailer never prints). The
    /// resync reads back (the tail of) the stderr temp file that trailer
    /// would have printed and removed; it is returned ahead of the guidance.
    fn interrupt(
        &mut self,
        acc: &framing::Accumulator,
        markers: &Markers,
        timeout: Duration,
    ) -> Result<Framed> {
        let (out, overflowed) = (acc.partial_stdout(markers), acc.overflowed());
        let Ok((cwd, late_stderr)) = self.resync() else {
            self.poisoned = true;
            return Err(Error::StillRunning);
        };
        Ok(Framed {
            stdout: crate::output::clean(&String::from_utf8_lossy(out)),
            stderr: format!(
                "{late_stderr}{sep}execkit: timed out after {}s; sent Ctrl-C. The shell \
                 session is intact (cwd/env kept). For long jobs run them in the \
                 background: nohup CMD > /tmp/job.log 2>&1 & then poll the log.",
                timeout.as_secs_f64(),
                sep = if late_stderr.is_empty() || late_stderr.ends_with('\n') {
                    ""
                } else {
                    "\n"
                },
            ),
            exit_code: 124,
            cwd,
            overflowed,
            timed_out: true,
        })
    }

    /// Write Ctrl-C, then run a cleanup command under a fresh token and wait
    /// up to 5 s for its end marker. Everything before it (the interrupted
    /// command's late output, a `^C` echo) is discarded. Returns the cwd and
    /// the interrupted command's stderr.
    ///
    /// The interrupted run line left its stderr temp file behind (its trailer
    /// never ran). Its path is still in `$__ek_f`, but the resync's own run
    /// line reassigns `__ek_f` before the cleanup command runs, so the path is
    /// saved to `__ek_x` on a line of its own first. The cleanup copies the
    /// file's last 16 KiB to its own stderr (so they come back framed as the
    /// resync's stderr), then removes it. 16 KiB is well under half of `CAP`,
    /// so the resync block always survives the drain below intact.
    /// It must not unset `__ek_f`: that now names the resync's OWN stderr
    /// file, which its trailer still has to print and remove.
    ///
    /// After the tail it prints `\n<file size>#`, so [`stderr_tail`] can tell
    /// whether the tail was cut (the size is the raw byte count; the framed
    /// text itself has been cleaned, so its length says nothing).
    fn resync(&mut self) -> Result<(String, String)> {
        const SAVE: &[u8] = b"{ __ek_x=$__ek_f; } 2>/dev/null\n";
        const RESYNC: &str = "__ek_n=$(wc -c 2>/dev/null <\"$__ek_x\"); \
                              tail -c 16384 \"$__ek_x\" >&2 2>/dev/null; \
                              printf '\\n%s#' \"$__ek_n\" >&2; \
                              rm -f \"$__ek_x\" 2>/dev/null; unset __ek_x __ek_n";
        const CAP: usize = 65_536;
        self.io.write_all(b"\x03")?;
        self.io.write_all(SAVE)?;
        let token = framing::new_token();
        let markers = Markers::new(&token);
        self.io
            .write_all(framing::build_payload(RESYNC, &token).as_bytes())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut acc: Vec<u8> = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error::StillRunning);
            }
            let chunk = self.io.recv_timeout(remaining).ok_or(Error::StillRunning)?;
            acc.extend_from_slice(&chunk);
            // A still-flooding command must not grow this without bound; the
            // resync block is small and always at the tail.
            if acc.len() > CAP {
                acc.drain(..acc.len() - CAP / 2);
            }
            if let Some(p) = framing::parse(&acc, &markers) {
                return Ok((p.cwd, stderr_tail(&p.stderr, 16_384)));
            }
        }
    }
}

/// Split the resync's stderr (`<tail>\n<size>#`) and, when the file was
/// larger than the `cap` bytes `tail` kept, drop everything up to and
/// including the first `\n`: the cut can land mid-line, mid-secret (which
/// redaction would then miss) or mid-UTF-8 character.
fn stderr_tail(framed: &str, cap: u64) -> String {
    let Some(body) = framed.strip_suffix('#') else {
        return framed.to_string();
    };
    let (tail, size) = body.rsplit_once('\n').unwrap_or(("", body));
    let cut = size.trim().parse::<u64>().is_ok_and(|n| n > cap);
    if !cut {
        return tail.to_string();
    }
    tail.split_once('\n')
        .map_or("", |(_, rest)| rest)
        .to_string()
}

/// Best-effort shadow-repo cleanup: for a remote session whose checkpointer
/// was initialized (i.e. a shadow repo actually exists at
/// `~/.execkit/ckpt-<token>.git`) and the session is not poisoned, remove it.
///
/// This is a `Drop` on `Session` itself (not on the transport) so it runs
/// BEFORE `io` is torn down: Rust calls a type's own `Drop::drop` before
/// dropping its fields, so the transport is still alive here and can carry
/// the cleanup command. A poisoned session's framing is desynced, so no
/// command is safe to send - skip it. Any failure (timeout, transport error)
/// is ignored: cleanup is best-effort and must never panic or block drop.
impl Drop for Session {
    fn drop(&mut self) {
        if self.poisoned {
            return;
        }
        let Some(cmd) = self
            .checkpointer
            .as_ref()
            .filter(|cp| cp.initialized)
            .map(Checkpointer::cleanup_cmd)
        else {
            return;
        };
        let acc_cap = self.default_acc_cap();
        let _ = self.run_framed_for(&cmd, Duration::from_secs(5), acc_cap);
    }
}

/// In-memory output window for a budgeted exec: budgets see all output up to
/// this size (and up to twice it between compactions); beyond that, the
/// first and last `BUDGET_ACC_CAP / 2` bytes of stdout and at least the first
/// and last `BUDGET_ACC_CAP / 4` bytes of stderr are kept (see
/// [`framing::Accumulator`]).
const BUDGET_ACC_CAP: usize = 8 * 1024 * 1024;

/// Raw result of one framed command (pre-redaction/bounding).
struct Framed {
    stdout: String,
    stderr: String,
    exit_code: i32,
    cwd: String,
    overflowed: bool,
    timed_out: bool,
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

/// Unguessable hex token for the checkpoint shadow repo and the docker
/// cleanup marker (the per-command sentinels use `framing::new_token` directly).
fn unique_token() -> String {
    framing::new_token()
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
    use super::{is_valid_checkpoint_id, is_valid_container_ref, stderr_tail};

    #[test]
    fn stderr_tail_drops_the_partial_first_line_only_when_cut() {
        assert_eq!(stderr_tail("boom\n\n5#", 16), "boom\n");
        assert_eq!(stderr_tail("0#", 16), "");
        assert_eq!(stderr_tail("ret=abc\nline 2\n\n  40#", 16), "line 2\n");
        assert_eq!(stderr_tail("no newline at all\n40#", 16), "");
        // Size unknown (wc failed): keep everything.
        assert_eq!(stderr_tail("ret=abc\nline 2\n\n#", 16), "ret=abc\nline 2\n");
        // No trailer at all: returned as is.
        assert_eq!(stderr_tail("odd", 16), "odd");
    }

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
