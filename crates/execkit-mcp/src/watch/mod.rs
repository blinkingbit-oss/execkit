// SPDX-License-Identifier: Apache-2.0
//! The `execkit-mcp watch` viewer: a live, read-only view over the audit log,
//! as an interactive TUI (`run`) or a plain streaming log (`follow`).
pub mod dirtail;
pub mod meta;
pub mod render;
pub mod source;
pub mod state;
pub mod tail;
pub mod tui;
pub mod web;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

use crate::watch::render::LineKind;
use crate::watch::source::Source;

pub fn run(path: PathBuf) -> anyhow::Result<()> {
    if !std::io::stdout().is_terminal() {
        anyhow::bail!("execkit-mcp watch needs a terminal (TTY)");
    }
    tui::run_loop(path)
}

/// Plain streaming view: print each new event as shell-transcript lines as they
/// arrive, prefixed with the session id. No TTY required - runs fine piped or as
/// a background process. Reads only; loops until interrupted (Ctrl+C).
pub fn follow(path: PathBuf) -> anyhow::Result<()> {
    let color = std::io::stdout().is_terminal();
    eprintln!(
        "execkit-mcp: following {} (read-only; Ctrl+C to stop)",
        path.display()
    );
    let mut src = Source::new(path);
    let mut out = std::io::stdout();
    // Runs until interrupted: SIGINT (Ctrl+C) terminates via the default
    // handler; a broken pipe (e.g. piped to `head`) returns Err from writeln!.
    loop {
        for ev in src.poll() {
            let sid = ev.session().to_string();
            for line in render::render_event(&ev) {
                if color {
                    writeln!(out, "[{sid}] \x1b[{}m{}\x1b[0m", ansi(line.kind), line.text)?;
                } else {
                    writeln!(out, "[{sid}] {}", line.text)?;
                }
            }
        }
        out.flush()?;
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn ansi(kind: LineKind) -> &'static str {
    match kind {
        LineKind::Prompt => "1;36", // cyan bold
        LineKind::Stdout => "0",
        LineKind::Stderr => "31",  // red
        LineKind::ExitOk => "32",  // green
        LineKind::ExitErr => "31", // red
        LineKind::Marker => "90",  // dim
    }
}
