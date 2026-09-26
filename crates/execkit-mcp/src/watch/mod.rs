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
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::audit::AuditEvent;
use crate::watch::render::LineKind;
use crate::watch::source::Source;

/// If `path`'s parent directory doesn't exist yet, the warning to print to the
/// operator - they likely pointed `watch` at an audit path before whatever
/// creates it (the MCP server, or `EXECKIT_MCP_AUDIT_DIR`) has run. Not fatal:
/// the poll-based tailers already cope with an absent file/dir and pick it up
/// once it appears, so this is purely informational.
pub fn missing_parent_warning(path: &Path) -> Option<String> {
    let parent = path.parent()?;
    if parent.as_os_str().is_empty() || parent.exists() {
        return None;
    }
    Some(format!(
        "warning: {} does not exist yet; waiting for it to appear",
        parent.display()
    ))
}

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
    let mut dates = render::DateSeparators::default();
    loop {
        for line in follow_lines(src.poll(), &mut dates, color) {
            writeln!(out, "{line}")?;
        }
        out.flush()?;
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// The `--follow` output lines for one poll batch. A single date line is
/// tracked for the whole stream (not per session). A directory source
/// returns a batch file by file, not in time order, so the batch is sorted
/// by display time first (stable, so one session's events keep their order).
fn follow_lines(
    mut events: Vec<AuditEvent>,
    dates: &mut render::DateSeparators,
    color: bool,
) -> Vec<String> {
    let paint = |kind: LineKind, text: &str| {
        if color {
            format!("\x1b[{}m{}\x1b[0m", ansi(kind), text)
        } else {
            text.to_string()
        }
    };
    events.sort_by_key(render::display_ts);
    let mut out = Vec::new();
    for ev in events {
        let sid = ev.session().to_string();
        if let Some(sep) = dates.before("", &ev) {
            out.push(paint(sep.kind, &sep.text));
        }
        for line in render::render_event_stamped(&ev) {
            out.push(format!("[{sid}] {}", paint(line.kind, &line.text)));
        }
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory source polls file by file, so one batch can hold a later
    /// day's session before an earlier one. `--follow` prints them in time
    /// order, so the date lines come out in order too.
    #[test]
    fn follow_orders_a_directory_batch_by_time() {
        let dir = std::env::temp_dir().join(format!("ek_follow_order_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Noon UTC on 2026-01-02 and 2026-01-01: distinct local dates in
        // every zone. The later day is in the file polled first.
        let day1: u64 = 1_767_268_800_000;
        let day2 = day1 + 86_400_000;
        let open = |sid: &str, ts: u64| {
            format!(r#"{{"event":"open","ts":{ts},"session":"{sid}","transport":"local"}}"#) + "\n"
        };
        std::fs::write(dir.join("a_2_local-1.jsonl"), open("2_local", day2)).unwrap();
        std::fs::write(dir.join("b_1_local-1.jsonl"), open("1_local", day1)).unwrap();
        let events = Source::new(dir.clone()).poll();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(events.len(), 2);

        let lines = follow_lines(events, &mut render::DateSeparators::default(), false);
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(
            lines[0].starts_with("-- ") && lines[2].starts_with("-- "),
            "{lines:?}"
        );
        assert!(lines[0] < lines[2], "date lines out of order: {lines:?}");
        assert!(lines[1].starts_with("[1_local] "), "{lines:?}");
        assert!(lines[3].starts_with("[2_local] "), "{lines:?}");
    }

    #[test]
    fn warns_when_parent_dir_is_missing() {
        let dir = std::env::temp_dir().join(format!("ek_watch_mod_missing_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("audit.jsonl");
        let msg = missing_parent_warning(&path).expect("should warn");
        assert!(msg.contains(&dir.display().to_string()), "{msg}");
        assert!(
            msg.contains("does not exist yet; waiting for it to appear"),
            "{msg}"
        );
    }

    #[test]
    fn no_warning_when_parent_dir_exists() {
        let path = std::env::temp_dir().join("audit.jsonl"); // temp_dir() always exists
        assert!(missing_parent_warning(&path).is_none());
    }

    #[test]
    fn no_warning_for_a_bare_relative_filename() {
        // Path::new("audit.jsonl").parent() is Some("") - not a real dir to warn about.
        assert!(missing_parent_warning(Path::new("audit.jsonl")).is_none());
    }
}
