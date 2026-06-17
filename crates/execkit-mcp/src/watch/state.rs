// SPDX-License-Identifier: Apache-2.0
//! In-memory viewer state: one transcript per session, plus selection.
use crate::audit::AuditEvent;
use crate::watch::render::{render_event, StyledLine};

pub struct SessionView {
    pub id: String,
    pub transport: String,
    pub closed: bool,
    pub cmd_count: usize,
    pub transcript: Vec<StyledLine>,
}

pub struct AppState {
    pub sessions: Vec<SessionView>,
    pub selected: usize,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
            selected: 0,
        }
    }

    fn index_of(&self, id: &str) -> Option<usize> {
        self.sessions.iter().position(|s| s.id == id)
    }

    fn ensure(&mut self, id: &str, transport: &str) -> usize {
        if let Some(i) = self.index_of(id) {
            return i;
        }
        self.sessions.push(SessionView {
            id: id.to_string(),
            transport: transport.to_string(),
            closed: false,
            cmd_count: 0,
            transcript: Vec::new(),
        });
        self.sessions.len() - 1
    }

    pub fn apply(&mut self, ev: AuditEvent) {
        let (id, transport) = match &ev {
            AuditEvent::Open {
                session, transport, ..
            } => (session.clone(), transport.clone()),
            AuditEvent::Exec {
                session, transport, ..
            } => (session.clone(), transport.clone()),
            AuditEvent::Close { session, .. } => (session.clone(), String::new()),
        };
        let i = self.ensure(&id, &transport);
        match &ev {
            AuditEvent::Open { .. } => {}
            AuditEvent::Exec { .. } => self.sessions[i].cmd_count += 1,
            AuditEvent::Close { .. } => self.sessions[i].closed = true,
        }
        let mut lines = render_event(&ev);
        self.sessions[i].transcript.append(&mut lines);
    }

    pub fn selected_view(&self) -> Option<&SessionView> {
        self.sessions.get(self.selected)
    }
    pub fn select_index(&mut self, i: usize) {
        if i < self.sessions.len() {
            self.selected = i;
        }
    }
    pub fn select_next(&mut self) {
        if self.selected + 1 < self.sessions.len() {
            self.selected += 1;
        }
    }
    pub fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditEvent;

    fn open(id: &str) -> AuditEvent {
        AuditEvent::Open {
            ts: 1,
            session: id.into(),
            transport: "local".into(),
        }
    }
    fn exec(id: &str) -> AuditEvent {
        AuditEvent::Exec {
            ts: 2,
            session: id.into(),
            transport: "local".into(),
            command: "echo x".into(),
            stdout: "x".into(),
            stderr: "".into(),
            exit_code: 0,
            duration_ms: 1,
            cwd: "/".into(),
            truncated: false,
        }
    }

    #[test]
    fn apply_builds_sessions_and_transcripts() {
        let mut s = AppState::new();
        s.apply(open("sess_1"));
        s.apply(exec("sess_1"));
        s.apply(open("sess_2"));
        assert_eq!(s.sessions.len(), 2);
        let v = &s.sessions[0];
        assert_eq!(v.id, "sess_1");
        assert_eq!(v.cmd_count, 1);
        assert!(v.transcript.iter().any(|l| l.text == "/ $ echo x"));
        assert!(!v.closed);
    }

    #[test]
    fn close_marks_session_closed() {
        let mut s = AppState::new();
        s.apply(open("sess_1"));
        s.apply(AuditEvent::Close {
            ts: 3,
            session: "sess_1".into(),
            reason: "reaped".into(),
        });
        assert!(s.sessions[0].closed);
        assert!(s.sessions[0]
            .transcript
            .iter()
            .any(|l| l.text == "-- closed (reaped) --"));
    }

    #[test]
    fn selection_navigates_and_clamps() {
        let mut s = AppState::new();
        s.apply(open("a"));
        s.apply(open("b"));
        assert_eq!(s.selected, 0);
        s.select_next();
        assert_eq!(s.selected, 1);
        s.select_next(); // clamp at last
        assert_eq!(s.selected, 1);
        s.select_prev();
        assert_eq!(s.selected, 0);
        assert_eq!(s.selected_view().unwrap().id, "a");
    }

    #[test]
    fn exec_for_unknown_session_is_tolerated() {
        let mut s = AppState::new();
        s.apply(exec("ghost")); // no prior open
        assert_eq!(s.sessions.len(), 1);
        assert_eq!(s.sessions[0].id, "ghost");
        assert_eq!(s.sessions[0].cmd_count, 1);
    }
}
