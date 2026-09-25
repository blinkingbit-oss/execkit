// SPDX-License-Identifier: Apache-2.0
use crate::budget::BudgetReport;
use serde::{Deserialize, Serialize};

/// The structured result of running one command - the agent-facing contract.
///
/// Note `stdout` and `stderr` are **split** (a raw PTY merges them), already
/// ANSI-stripped and secret-redacted, and bounded to the session's output cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecResult {
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub cwd: String,
    /// True if output was shortened: a char-cap hit, lines dropped by an output
    /// budget, or anti-flood overflow.
    pub truncated: bool,
    /// Present only when a non-default budget shaped this result.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub budget: Option<BudgetReport>,
    /// True if the command outlived its timeout and was interrupted with
    /// Ctrl-C (`exit_code` is then 124). The session is still usable.
    #[serde(default)]
    pub timed_out: bool,
}

/// A snapshot of shell state carried alongside results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellState {
    pub cwd: String,
    pub last_exit: i32,
}
