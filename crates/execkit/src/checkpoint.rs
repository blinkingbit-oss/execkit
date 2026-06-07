// SPDX-License-Identifier: Apache-2.0
//! Remote workspace checkpoints: git-backed "undo" for an agent's file changes.
//!
//! Pure logic only - command strings, output parsing, and read-only command
//! classification. `Session` runs the commands over its transport (see
//! `session.rs`); keeping the logic transport-free makes it unit-testable.

use serde::Serialize;

/// A checkpoint identifier: a commit SHA in the shadow git repo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckpointId(pub String);

/// One checkpoint in the linear history.
#[derive(Debug, Clone, Serialize)]
pub struct Checkpoint {
    pub id: String,
    pub label: String,
    pub created: String,
}

/// What a restore changed.
#[derive(Debug, Clone, Serialize)]
pub struct RestoreReport {
    pub restored_to: String,
    pub files_changed: usize,
}
