// SPDX-License-Identifier: Apache-2.0
//! Pure rendering of audit events into styled shell-transcript lines.
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
            let (mark, kind) = if *exit_code == 0 {
                ("ok exit 0", LineKind::ExitOk)
            } else {
                return {
                    out.push(StyledLine {
                        text: format!("x exit {exit_code}  ({duration_ms}ms)"),
                        kind: LineKind::ExitErr,
                    });
                    out
                };
            };
            out.push(StyledLine {
                text: format!("{mark}  ({duration_ms}ms)"),
                kind,
            });
            out
        }
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
}
