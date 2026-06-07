// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

/// Errors returned by execkit.
#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("pty/transport error: {0}")]
    Transport(String),

    /// Command did not finish before the session timeout (still running, or
    /// waiting for input). The session is poisoned afterward (see below) - the
    /// pending command would corrupt subsequent reads.
    #[error("command still running (timed out before completion)")]
    StillRunning,

    /// The session is unusable: a prior command timed out while still running,
    /// so its later output would desync framing. Create a new session.
    /// (v0.x will replace poisoning with interrupt + resync.)
    #[error("session poisoned by a prior timeout; create a new session")]
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
