// SPDX-License-Identifier: Apache-2.0
//! ratatui rendering of the viewer state (two panes), plus the input/tail loop.
use std::io::Stdout;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::{Frame, Terminal};

use crate::watch::render::LineKind;
use crate::watch::source::Source;
use crate::watch::state::AppState;

pub fn run_loop(path: PathBuf) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut out: Stdout = std::io::stdout();
    if let Err(e) = execute!(out, EnterAlternateScreen) {
        // Entering the alternate screen failed after raw mode was enabled;
        // undo raw mode so we never leave the user's terminal corrupted.
        let _ = disable_raw_mode();
        return Err(e.into());
    }
    let res = (|| -> anyhow::Result<()> {
        let mut term = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
        let mut state = AppState::new();
        let mut source = Source::new(path);
        // u16::MAX means "pinned to the bottom"; draw() clamps it to the real
        // last line. Manual scrolling replaces it with a bounded offset.
        let mut scroll: u16 = u16::MAX;
        let mut follow = true;
        loop {
            for ev in source.poll() {
                state.apply(ev);
            }
            let mut max_scroll = 0u16;
            term.draw(|f| max_scroll = draw(f, &state, scroll))?;
            if follow {
                // Keep the latest line in view as the transcript grows.
                scroll = max_scroll;
            }
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(k) = event::read()? {
                    match k.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Down | KeyCode::Tab => {
                            state.select_next();
                            scroll = u16::MAX;
                            follow = true;
                        }
                        KeyCode::Up => {
                            state.select_prev();
                            scroll = u16::MAX;
                            follow = true;
                        }
                        KeyCode::Char(c @ '1'..='9') => {
                            state.select_index((c as usize) - ('1' as usize));
                            scroll = u16::MAX;
                            follow = true;
                        }
                        KeyCode::PageUp => {
                            // Clamp to the real bottom first, then step up.
                            scroll = scroll.min(max_scroll).saturating_sub(5);
                            follow = false;
                        }
                        KeyCode::PageDown => {
                            scroll = scroll.min(max_scroll).saturating_add(5);
                            follow = scroll >= max_scroll; // re-pin once at the bottom
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    })();
    // Always restore the terminal, even on error.
    let _ = disable_raw_mode();
    let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
    res
}

fn style_for(kind: LineKind) -> Style {
    match kind {
        LineKind::Prompt => Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
        LineKind::Stdout => Style::default(),
        LineKind::Stderr => Style::default().fg(Color::Red),
        LineKind::ExitOk => Style::default().fg(Color::Green),
        LineKind::ExitErr => Style::default().fg(Color::Red),
        LineKind::Marker => Style::default().fg(Color::DarkGray),
    }
}

/// Renders one frame and returns the maximum useful scroll offset for the
/// transcript (its line count minus the visible height), so the run loop can
/// keep "follow" pinned to the bottom and bound manual scrolling.
pub fn draw(frame: &mut Frame, state: &AppState, scroll: u16) -> u16 {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(40), Constraint::Min(10)])
        .split(frame.area());

    let items: Vec<ListItem> = state
        .sessions
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let marker = if i == state.selected { ">" } else { " " };
            // The id is self-identifying (number_transport_target), so the
            // transport column is redundant here; (N) is the command count.
            let label = format!("{marker}{} {} ({})", i + 1, s.id, s.cmd_count);
            let mut st = Style::default();
            if s.closed {
                st = st.fg(Color::DarkGray);
            }
            if i == state.selected {
                st = st.add_modifier(Modifier::REVERSED);
            }
            ListItem::new(label).style(st)
        })
        .collect();
    frame.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title("sessions")),
        cols[0],
    );

    let (title, lines): (String, Vec<Line>) = match state.selected_view() {
        Some(v) => {
            let status = if v.closed { "closed" } else { "active" };
            let title = format!("{}  ({})", v.id, status);
            let lines = v
                .transcript
                .iter()
                .map(|l| Line::from(Span::styled(l.text.clone(), style_for(l.kind))))
                .collect();
            (title, lines)
        }
        None => ("(no sessions yet)".to_string(), Vec::new()),
    };
    // ratatui's Paragraph does not clamp the scroll offset: a value past the
    // end blanks the pane. Bound it to keep the last line visible (inner height
    // is the pane height minus its top+bottom borders; lines are not wrapped).
    let inner_h = cols[1].height.saturating_sub(2);
    let max_scroll = (lines.len() as u16).saturating_sub(inner_h);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .scroll((scroll.min(max_scroll), 0)),
        cols[1],
    );
    max_scroll
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditEvent;
    use crate::watch::state::AppState;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn renders_session_list_and_transcript() {
        let mut s = AppState::new();
        s.apply(AuditEvent::Open {
            ts: 1,
            session: "sess_1".into(),
            transport: "local".into(),
        });
        s.apply(AuditEvent::Exec {
            ts: 2,
            session: "sess_1".into(),
            transport: "local".into(),
            command: "echo hi".into(),
            stdout: "hi".into(),
            stderr: "".into(),
            exit_code: 0,
            duration_ms: 3,
            cwd: "/tmp".into(),
            truncated: false,
        });
        let backend = TestBackend::new(80, 12);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            draw(f, &s, 0);
        })
        .unwrap();
        let buf = term.backend().buffer().clone();
        let dump: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(dump.contains("sess_1"), "session id in list");
        assert!(
            dump.contains("/tmp $ echo hi"),
            "prompt+command in transcript"
        );
        assert!(dump.contains("hi"), "stdout in transcript");
    }
}
