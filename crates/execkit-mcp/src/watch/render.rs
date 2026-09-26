// SPDX-License-Identifier: Apache-2.0
//! Pure rendering of audit events into styled shell-transcript lines.
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::audit::AuditEvent;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LineKind {
    Prompt,
    Stdout,
    Stderr,
    ExitOk,
    ExitErr,
    Marker,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StyledLine {
    pub text: String,
    pub kind: LineKind,
}

fn split_stream(s: &str) -> impl Iterator<Item = &str> {
    s.strip_suffix('\n')
        .unwrap_or(s)
        .split('\n')
        .filter(|l| !l.is_empty())
}

pub fn render_event(ev: &AuditEvent) -> Vec<StyledLine> {
    match ev {
        AuditEvent::Open { transport, .. } => vec![StyledLine {
            text: format!("-- opened: {transport} --"),
            kind: LineKind::Marker,
        }],
        AuditEvent::Close { reason, .. } => vec![StyledLine {
            text: format!("-- closed ({reason}) --"),
            kind: LineKind::Marker,
        }],
        AuditEvent::Blocked {
            command, reason, ..
        } => vec![StyledLine {
            text: format!("! blocked: {command}  ({reason})"),
            kind: LineKind::ExitErr,
        }],
        AuditEvent::Exec {
            command,
            stdout,
            stderr,
            exit_code,
            duration_ms,
            cwd,
            truncated,
            timed_out,
            ..
        } => {
            let mut out = Vec::new();
            out.push(StyledLine {
                text: format!("{cwd} $ {command}"),
                kind: LineKind::Prompt,
            });
            for l in split_stream(stdout) {
                out.push(StyledLine {
                    text: l.to_string(),
                    kind: LineKind::Stdout,
                });
            }
            for l in split_stream(stderr) {
                out.push(StyledLine {
                    text: l.to_string(),
                    kind: LineKind::Stderr,
                });
            }
            if *truncated {
                out.push(StyledLine {
                    text: "... (output truncated)".to_string(),
                    kind: LineKind::Marker,
                });
            }
            let suffix = if *timed_out { "  [timed out]" } else { "" };
            let (mark, kind) = if *exit_code == 0 {
                ("ok exit 0", LineKind::ExitOk)
            } else {
                return {
                    out.push(StyledLine {
                        text: format!("x exit {exit_code}  ({duration_ms}ms){suffix}"),
                        kind: LineKind::ExitErr,
                    });
                    out
                };
            };
            out.push(StyledLine {
                text: format!("{mark}  ({duration_ms}ms){suffix}"),
                kind,
            });
            out
        }
    }
}

/// The time (unix ms) the viewers show for an event's lines. An exec event's
/// `ts` is written when the result is recorded, i.e. after the command
/// finished, so the command's start time is `ts - duration_ms`; every other
/// event uses its own `ts`.
pub fn display_ts(ev: &AuditEvent) -> u64 {
    match ev {
        AuditEvent::Exec {
            ts, duration_ms, ..
        } => ts.saturating_sub(*duration_ms),
        AuditEvent::Open { ts, .. }
        | AuditEvent::Close { ts, .. }
        | AuditEvent::Blocked { ts, .. } => *ts,
    }
}

extern "C" {
    fn tzset();
}

/// Local `YYYY-MM-DD` and `HH:MM:SS` of `ms` (unix ms), following `$TZ`.
/// None for 0 (no time recorded) or a time the C library cannot convert.
fn local_time(ms: u64) -> Option<(String, String)> {
    static TZSET: std::sync::Once = std::sync::Once::new();
    if ms == 0 {
        return None;
    }
    let secs = libc::time_t::try_from(ms / 1000).ok()?;
    // SAFETY: tzset only reads `$TZ` and sets the C library's zone state; it
    // runs once, before any localtime_r call here.
    TZSET.call_once(|| unsafe { tzset() });
    // SAFETY: an all-zero `tm` is a valid value, and localtime_r (the
    // reentrant form) writes only to the `tm` it is given.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
        return None;
    }
    Some((
        format!(
            "{:04}-{:02}-{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday
        ),
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec),
    ))
}

/// [`render_event`] for the terminal viewers: the event's first line (the
/// command prompt, or the opened / closed / blocked line) starts with its
/// local time, `[HH:MM:SS] `, taken from [`display_ts`]. The web viewer
/// stamps lines itself, so it uses the plain [`render_event`].
pub fn render_event_stamped(ev: &AuditEvent) -> Vec<StyledLine> {
    let mut lines = render_event(ev);
    if let (Some(first), Some((_, time))) = (lines.first_mut(), local_time(display_ts(ev))) {
        first.text = format!("[{time}] {}", first.text);
    }
    lines
}

/// Date lines for the terminal viewers, tracked per transcript (a session
/// id in the TUI; one shared key for `--follow`). Like the web viewer: a
/// `-- YYYY-MM-DD --` line goes before a transcript's first event when that
/// event is not from today, and before any event whose local date differs
/// from the previous event's.
#[derive(Debug, Default)]
pub struct DateSeparators {
    last: HashMap<String, String>,
}

impl DateSeparators {
    /// The date line to show before `ev` in transcript `key`, if any.
    pub fn before(&mut self, key: &str, ev: &AuditEvent) -> Option<StyledLine> {
        let (day, _) = local_time(display_ts(ev))?;
        let new_day = match self.last.get(key) {
            Some(prev) => *prev != day,
            None => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis() as u64);
                local_time(now).is_none_or(|(today, _)| today != day)
            }
        };
        self.last.insert(key.to_string(), day.clone());
        new_day.then(|| StyledLine {
            text: format!("-- {day} --"),
            kind: LineKind::Marker,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditEvent;

    fn exec(stdout: &str, stderr: &str, code: i32, truncated: bool) -> AuditEvent {
        AuditEvent::Exec {
            ts: 1,
            session: "sess_1".into(),
            transport: "local".into(),
            command: "ls -a".into(),
            stdout: stdout.into(),
            stderr: stderr.into(),
            exit_code: code,
            duration_ms: 42,
            cwd: "/tmp".into(),
            truncated,
            timed_out: false,
        }
    }

    #[test]
    fn exec_renders_prompt_streams_and_ok_status() {
        let lines = render_event(&exec("a\nb\n", "", 0, false));
        assert_eq!(
            lines[0],
            StyledLine {
                text: "/tmp $ ls -a".into(),
                kind: LineKind::Prompt
            }
        );
        assert_eq!(
            lines[1],
            StyledLine {
                text: "a".into(),
                kind: LineKind::Stdout
            }
        );
        assert_eq!(
            lines[2],
            StyledLine {
                text: "b".into(),
                kind: LineKind::Stdout
            }
        );
        let last = lines.last().unwrap();
        assert_eq!(last.kind, LineKind::ExitOk);
        assert_eq!(last.text, "ok exit 0  (42ms)");
    }

    #[test]
    fn exec_renders_stderr_truncated_and_err_status() {
        let lines = render_event(&exec("out", "boom", 1, true));
        assert!(lines
            .iter()
            .any(|l| l.kind == LineKind::Stderr && l.text == "boom"));
        assert!(lines
            .iter()
            .any(|l| l.kind == LineKind::Marker && l.text == "... (output truncated)"));
        let last = lines.last().unwrap();
        assert_eq!(last.kind, LineKind::ExitErr);
        assert_eq!(last.text, "x exit 1  (42ms)");
    }

    #[test]
    fn timed_out_exec_renders_a_marker_suffix() {
        let ev = AuditEvent::Exec {
            ts: 1,
            session: "sess_1".into(),
            transport: "local".into(),
            command: "sleep 30".into(),
            stdout: "".into(),
            stderr: "".into(),
            exit_code: 124,
            duration_ms: 1000,
            cwd: "/tmp".into(),
            truncated: false,
            timed_out: true,
        };
        let lines = render_event(&ev);
        let last = lines.last().unwrap();
        assert_eq!(last.kind, LineKind::ExitErr);
        assert!(last.text.contains("timed out"), "{:?}", last.text);
    }

    #[test]
    fn blocked_renders_a_red_marker_line() {
        let lines = render_event(&AuditEvent::Blocked {
            ts: 1,
            session: "1_local".into(),
            transport: "local".into(),
            command: "rm -rf /tmp/x".into(),
            reason: "matched deny pattern /\\brm\\b/".into(),
        });
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].kind, LineKind::ExitErr);
        assert!(lines[0].text.starts_with("! blocked: rm -rf /tmp/x"));
        assert!(lines[0].text.contains("deny pattern"));
    }

    #[test]
    fn open_and_close_render_markers() {
        let o = render_event(&AuditEvent::Open {
            ts: 1,
            session: "s".into(),
            transport: "ssh:web".into(),
        });
        assert_eq!(
            o,
            vec![StyledLine {
                text: "-- opened: ssh:web --".into(),
                kind: LineKind::Marker
            }]
        );
        let c = render_event(&AuditEvent::Close {
            ts: 1,
            session: "s".into(),
            reason: "reaped".into(),
        });
        assert_eq!(
            c,
            vec![StyledLine {
                text: "-- closed (reaped) --".into(),
                kind: LineKind::Marker
            }]
        );
    }

    fn at(ts: u64) -> AuditEvent {
        AuditEvent::Open {
            ts,
            session: "s".into(),
            transport: "local".into(),
        }
    }

    /// `[HH:MM:SS] ` then `rest`. The seconds do not depend on the time zone
    /// (offsets are whole minutes), so they are checked exactly.
    fn assert_stamped(text: &str, secs: &str, rest: &str) {
        let re = regex::Regex::new(r"^\[\d{2}:\d{2}:(\d{2})\] (.*)$").unwrap();
        let c = re
            .captures(text)
            .unwrap_or_else(|| panic!("no stamp: {text:?}"));
        assert_eq!(&c[1], secs, "{text:?}");
        assert_eq!(&c[2], rest, "{text:?}");
    }

    #[test]
    fn stamped_exec_shows_its_start_time_on_the_prompt_only() {
        let mut ev = exec("a\n", "", 0, false);
        if let AuditEvent::Exec { ts, .. } = &mut ev {
            *ts = 10_000; // recorded at 10s, ran 42ms: started at 9.958s
        }
        let lines = render_event_stamped(&ev);
        assert_stamped(&lines[0].text, "09", "/tmp $ ls -a");
        assert_eq!(lines[0].kind, LineKind::Prompt);
        assert_eq!(lines[1].text, "a");
        assert_eq!(lines.last().unwrap().text, "ok exit 0  (42ms)");
        // Plain render_event (web viewer, MCP notifications) stays unstamped.
        assert_eq!(render_event(&ev)[0].text, "/tmp $ ls -a");
    }

    #[test]
    fn stamped_open_close_blocked_use_the_event_time() {
        assert_stamped(
            &render_event_stamped(&at(65_000))[0].text,
            "05",
            "-- opened: local --",
        );
        let c = render_event_stamped(&AuditEvent::Close {
            ts: 7_000,
            session: "s".into(),
            reason: "destroyed".into(),
        });
        assert_stamped(&c[0].text, "07", "-- closed (destroyed) --");
        let b = render_event_stamped(&AuditEvent::Blocked {
            ts: 3_000,
            session: "s".into(),
            transport: "local".into(),
            command: "rm -rf /x".into(),
            reason: "deny".into(),
        });
        assert_stamped(&b[0].text, "03", "! blocked: rm -rf /x  (deny)");
        assert_eq!(b[0].kind, LineKind::ExitErr);
        // No time recorded: no stamp.
        assert_eq!(render_event_stamped(&at(0))[0].text, "-- opened: local --");
    }

    #[test]
    fn date_separator_before_first_line_of_another_day_and_on_each_change() {
        // Noon UTC on 2026-01-01 and 2026-01-02: distinct local dates in
        // every zone, and neither is today.
        let day1 = 1_767_268_800_000;
        let day2 = day1 + 86_400_000;
        let re = regex::Regex::new(r"^-- \d{4}-\d{2}-\d{2} --$").unwrap();
        let mut seps = DateSeparators::default();
        let first = seps.before("s", &at(day1)).expect("first line, not today");
        assert!(re.is_match(&first.text), "{:?}", first.text);
        assert_eq!(first.kind, LineKind::Marker);
        assert_eq!(seps.before("s", &at(day1 + 30_000)), None);
        let next = seps.before("s", &at(day2)).expect("date changed");
        assert!(re.is_match(&next.text) && next.text != first.text);
        // Tracked per key: another transcript starts fresh.
        assert_eq!(seps.before("t", &at(day2)), Some(next));
        assert_eq!(seps.before("s", &at(0)), None);
        // Today's first line needs no separator.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert_eq!(DateSeparators::default().before("s", &at(now)), None);
    }
}
