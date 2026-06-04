// SPDX-License-Identifier: Apache-2.0
//! A persistent session: frame each command with an unguessable sentinel that
//! carries exit code + cwd, split stderr to a side channel, then apply policy,
//! redaction, bounding, and audit.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::audit::AuditLog;
use crate::error::{Error, Result};
use crate::exec::ExecResult;
use crate::output::{bound, clean};
use crate::policy::Policy;
use crate::redact::redact;
use crate::transport::local::LocalPty;

const US: u8 = 0x1f; // unit separator

/// A live, stateful shell session.
pub struct Session {
    pty: LocalPty,
    token: String,
    errpath: String,
    policy: Option<Policy>,
    audit: Option<AuditLog>,
    timeout: Duration,
    max_output: usize,
    /// Set after a timeout: the prior command is still running and would desync
    /// framing, so the session refuses further commands.
    poisoned: bool,
}

impl Session {
    /// Open a session backed by a local `bash` PTY.
    pub fn local() -> Result<Self> {
        let pty = LocalPty::spawn("bash", &["--norc", "--noprofile"])?;
        let token = unique_token();
        let errpath = std::env::temp_dir()
            .join(format!("nexum_err_{token}"))
            .to_string_lossy()
            .into_owned();
        // O_EXCL + owner-only: defeats symlink pre-creation attacks and keeps
        // captured stderr (pre-redaction) unreadable by others in shared /tmp.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&errpath)?;
        Ok(Self {
            pty,
            token,
            errpath,
            policy: None,
            audit: None,
            timeout: Duration::from_secs(30),
            max_output: 100_000,
            poisoned: false,
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

    /// True if a prior timeout left the session unusable.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Run a command and return a structured [`ExecResult`].
    ///
    /// On a completion timeout this returns [`Error::StillRunning`] and poisons
    /// the session (subsequent calls return [`Error::SessionPoisoned`]), because
    /// the still-running command's later output would corrupt framing.
    pub fn exec(&mut self, command: &str) -> Result<ExecResult> {
        if self.poisoned {
            return Err(Error::SessionPoisoned);
        }
        if let Some(p) = &self.policy {
            if let Err(reason) = p.check(command) {
                return Err(Error::PolicyDenied(reason));
            }
        }

        // Truncate-reset our owned 0600 side channel.
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.errpath)?;

        let marker = format!("__NEXUM_{}__", self.token);
        // Sentinel printf is OUTSIDE the redirected group so it always reaches
        // the PTY even if the user's command redirects its own stdout.
        let payload = format!(
            "{{ {cmd} ; }} 2> {err} ; printf '\\n{m}\\037%d\\037%s\\037\\n' \"$?\" \"$PWD\"\n",
            cmd = command,
            err = self.errpath,
            m = marker,
        );

        let start = Instant::now();
        self.pty.write_all(payload.as_bytes())?;

        let mbytes = marker.as_bytes();
        // Bound in-memory accumulation. The sentinel arrives LAST, so keeping a
        // head + a large sliding tail always retains the full marker
        // (tail >> marker length). Prevents a `yes`/`cat /dev/urandom` from
        // exhausting RAM before the timeout fires.
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
            let chunk = match self.pty.recv_timeout(deadline - now) {
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

            if let Some(pos) = find(&acc, mbytes) {
                let tail = &acc[pos + mbytes.len()..];
                let seps: Vec<usize> = tail
                    .iter()
                    .enumerate()
                    .filter(|(_, b)| **b == US)
                    .map(|(i, _)| i)
                    .collect();
                if seps.len() >= 3 {
                    let exit_code: i32 = String::from_utf8_lossy(&tail[seps[0] + 1..seps[1]])
                        .trim()
                        .parse()
                        .unwrap_or(-1);
                    let cwd = String::from_utf8_lossy(&tail[seps[1] + 1..seps[2]]).into_owned();

                    let raw_out = clean(&String::from_utf8_lossy(&acc[..pos]));
                    let raw_err = clean(&std::fs::read_to_string(&self.errpath).unwrap_or_default());
                    let (stdout, t1) = bound(&redact(&raw_out), self.max_output);
                    let (stderr, t2) = bound(&redact(&raw_err), self.max_output);

                    let result = ExecResult {
                        command: command.to_string(),
                        stdout,
                        stderr,
                        exit_code,
                        duration_ms: start.elapsed().as_millis() as u64,
                        cwd,
                        truncated: t1 || t2 || overflowed,
                    };
                    if let Some(a) = &self.audit {
                        if let Err(e) = a.record(&result) {
                            eprintln!("nexum: audit write failed: {e}");
                        }
                    }
                    return Ok(result);
                }
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.errpath);
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn unique_token() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    // Unpredictable suffix so the /tmp side-channel path and the sentinel token
    // can't be guessed.
    let mut rnd = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut rnd);
    }
    let rhex: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    format!("{nanos:x}{n:x}{rhex}")
}
