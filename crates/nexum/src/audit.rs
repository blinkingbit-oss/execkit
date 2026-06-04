// SPDX-License-Identifier: Apache-2.0
//! Append-only JSONL audit log (v0.1 simple form).
//!
//! v0.4 upgrades this to a hash-chained, tamper-evident log.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use crate::error::Result;
use crate::exec::ExecResult;

/// Records every command result as one JSON object per line.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Append one result. One line of JSON; safe to `tail -f`.
    pub fn record(&self, result: &ExecResult) -> Result<()> {
        let line = serde_json::to_string(result)?;
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{line}")?;
        Ok(())
    }
}
