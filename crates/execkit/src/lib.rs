// SPDX-License-Identifier: Apache-2.0
//! # execkit
//!
//! Stateful, structured, **safe** shell sessions for AI agents on real
//! infrastructure. The agent driving execkit can be prompt-injected, so the
//! library's job is to contain its own caller: every command passes a policy
//! fence, output is redacted of secrets, and results are recorded.
//!
//! Sessions persist state (cwd, env) across commands and run over a **local PTY**,
//! **SSH**, or **Docker** ([`Session::local`] / [`Session::ssh`] / [`Session::docker`]),
//! returning a structured [`ExecResult`] checked by an advisory [`Policy`], with
//! secret redaction, bounded output, and an append-only audit log. Remote sessions
//! also support git-backed workspace checkpoints - a filesystem "undo" for an
//! agent's changes ([`Session::checkpoint`] / [`Session::restore`]). An MCP server
//! (`execkit-mcp`) exposes the same sessions to MCP agents.
//!
//! ```no_run
//! use execkit::Session;
//! let mut s = Session::local()?;
//! let r = s.exec("echo hello")?;
//! assert_eq!(r.stdout, "hello");
//! assert_eq!(r.exit_code, 0);
//! # Ok::<(), execkit::Error>(())
//! ```

mod audit;
pub mod budget;
pub mod checkpoint;
mod error;
mod exec;
mod output;
mod policy;
mod redact;
mod session;
pub mod transport;

pub use audit::AuditLog;
pub use checkpoint::{Checkpoint, CheckpointId, RestoreReport};
pub use error::{Error, Result};
pub use exec::{ExecResult, ShellState};
pub use output::strip_ansi;
pub use policy::Policy;
pub use session::Session;
pub use transport::ssh::{HostKeyVerification, SshAuth, SshConfig};
