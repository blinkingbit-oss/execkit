// SPDX-License-Identifier: Apache-2.0
//! Transports — how a session reaches an environment.
//!
//! v0.1 ships the local PTY. SSH (`russh`) lands in v0.1.x and the pluggable
//! `Transport` trait (so Docker/K8s share one `ExecResult` contract) in v0.2.

pub mod local;
