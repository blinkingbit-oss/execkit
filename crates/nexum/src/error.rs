// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

/// Errors returned by nexum.
#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("pty/transport error: {0}")]
    Transport(String),

    /// Command did not finish before the session timeout (still running, or
    /// waiting for input). The session may need an interrupt + resync.
    #[error("command still running (timed out before completion)")]
    StillRunning,

    /// Blocked by the advisory policy before reaching the shell.
    #[error("blocked by policy: {0}")]
    PolicyDenied(String),
}

pub type Result<T> = std::result::Result<T, Error>;
