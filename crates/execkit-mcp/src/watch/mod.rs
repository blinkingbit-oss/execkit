// SPDX-License-Identifier: Apache-2.0
//! The `execkit-mcp watch` viewer: a live, read-only TUI over the audit log.
pub mod dirtail;
pub mod render;
pub mod state;
pub mod tail;
pub mod tui;

use std::io::IsTerminal;
use std::path::PathBuf;

pub fn run(path: PathBuf) -> anyhow::Result<()> {
    if !std::io::stdout().is_terminal() {
        anyhow::bail!("execkit-mcp watch needs a terminal (TTY)");
    }
    tui::run_loop(path)
}
