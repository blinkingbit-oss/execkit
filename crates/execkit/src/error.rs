// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

/// Errors returned by execkit.
///
/// `#[non_exhaustive]`: new variants may be added in a minor release without it
/// being a breaking change, so downstream `match` on `Error` must include a
/// wildcard arm.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("pty/transport error: {0}")]
    Transport(String),

    /// A command outlived its timeout and could not be interrupted (Ctrl-C and
    /// a resync did not bring the shell back). The session is poisoned and
    /// closed to further commands. (An interruptible timeout is not an error:
    /// it returns `Ok` with `ExecResult::timed_out` set.)
    #[error("command timed out and could not be interrupted; the session was closed - create a new session")]
    StillRunning,

    /// The shell process exited and closed the session's channel (for example the
    /// command ran `exit`). Distinct from a timeout: it surfaces immediately. The
    /// session is unusable; create a new one.
    #[error("shell exited and closed the session; create a new session (a command ran 'exit', or 'set -e' hit a failing command)")]
    ShellExited,

    /// The session is unusable: a prior command could not be interrupted after
    /// a timeout, or the shell exited. Create a new session.
    #[error("session is no longer usable (a command could not be interrupted, or the shell exited); create a new session")]
    SessionPoisoned,

    /// Blocked by the advisory policy before reaching the shell.
    #[error("blocked by policy: {0}")]
    PolicyDenied(String),

    /// The operation is not supported for this session (e.g. checkpoints on a
    /// local session, or git missing on the remote).
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// An output budget was invalid (e.g. a malformed grep regex).
    #[error("invalid output budget: {0}")]
    Budget(String),
}

pub type Result<T> = std::result::Result<T, Error>;
