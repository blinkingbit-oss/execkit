// SPDX-License-Identifier: Apache-2.0
//! # nexum
//!
//! Stateful, structured, **safe** shell sessions for AI agents on real
//! infrastructure. The agent driving nexum can be prompt-injected, so the
//! library's job is to contain its own caller: every command passes a policy
//! fence, output is redacted of secrets, and results are recorded.
//!
//! v0.1 scope: a persistent **local PTY** session with structured [`ExecResult`],
//! an advisory [`Policy`], secret redaction, and an append-only audit log.
//! SSH transport and MCP server mode follow (see `ROADMAP.md`).
//!
//! ```no_run
//! use nexum::Session;
//! let mut s = Session::local()?;
//! let r = s.exec("echo hello")?;
//! assert_eq!(r.stdout, "hello");
//! assert_eq!(r.exit_code, 0);
//! # Ok::<(), nexum::Error>(())
//! ```

mod audit;
mod error;
mod exec;
mod output;
mod policy;
mod redact;
mod session;
pub mod transport;

pub use audit::AuditLog;
pub use error::{Error, Result};
pub use exec::{ExecResult, ShellState};
pub use output::strip_ansi;
pub use policy::Policy;
pub use session::Session;
pub use transport::ssh::{HostKeyVerification, SshAuth, SshConfig};
