// SPDX-License-Identifier: Apache-2.0
//! The viewer's display-only metadata store: aliases, pins, keeps, and UI prefs
//! the page persists via POST /state. This is the ONLY thing the viewer writes.
//! It never affects a session, execution, or the audit log. One fixed file.
use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Hard cap on an accepted /state body. Rejects oversized writes.
pub const MAX_STATE_BYTES: usize = 262144;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pinned: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keep: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UiPrefs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidebar_width: Option<u32>,
}

// NOTE: do NOT use `#[serde(flatten)]` for `sessions` - flatten is incompatible
// with `deny_unknown_fields`. Keep `sessions` an explicit field. The JSON shape
// is `{ "sessions": { "<id>": {...} }, "ui": {...} }`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewerState {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sessions: BTreeMap<String, SessionMeta>,
    #[serde(default, skip_serializing_if = "is_default_ui")]
    pub ui: UiPrefs,
}

fn is_default_ui(u: &UiPrefs) -> bool {
    *u == UiPrefs::default()
}

/// Parse + validate an incoming /state body. Enforces the size cap, JSON shape,
/// and per-field caps. Returns the validated state or a short error string.
pub fn parse_validated(body: &[u8]) -> Result<ViewerState, String> {
    if body.len() > MAX_STATE_BYTES {
        return Err(format!("state too large ({} > {})", body.len(), MAX_STATE_BYTES));
    }
    let mut st: ViewerState =
        serde_json::from_slice(body).map_err(|e| format!("invalid state json: {e}"))?;
    // Cap alias length; drop empty aliases. Session ids are arbitrary strings
    // (display keys only) but bounded by the overall size cap.
    for m in st.sessions.values_mut() {
        if let Some(a) = &m.alias {
            if a.is_empty() {
                m.alias = None;
            } else if a.len() > 200 {
                return Err("alias too long".into());
            }
        }
    }
    if let Some(w) = st.ui.sidebar_width {
        if !(120..=2000).contains(&w) {
            return Err("sidebar_width out of range".into());
        }
    }
    Ok(st)
}

/// Read the state file, returning a default (empty) state if it is missing or
/// unreadable - the viewer must still work without prior metadata.
pub fn load(path: &Path) -> ViewerState {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
        Err(_) => ViewerState::default(),
    }
}

/// Write the state file atomically-ish, mode 0600 on unix (created restricted
/// from the first byte). The parent dir is created if absent.
pub fn save(path: &Path, st: &ViewerState) -> anyhow::Result<()> {
    let body = serde_json::to_vec_pretty(st).context("serializing viewer state")?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("writing {}", path.display()))?;
        f.write_all(&body)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &body).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trips_a_valid_state() {
        let body = br#"{"sessions":{"1_local":{"alias":"build","pinned":true}},"ui":{"sidebar_width":320}}"#;
        let st = parse_validated(body).unwrap();
        assert_eq!(st.sessions["1_local"].alias.as_deref(), Some("build"));
        assert!(st.sessions["1_local"].pinned);
        assert_eq!(st.ui.sidebar_width, Some(320));
    }

    #[test]
    fn rejects_oversized_body() {
        let big = vec![b'x'; MAX_STATE_BYTES + 1];
        assert!(parse_validated(&big).is_err());
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(parse_validated(b"{ not json").is_err());
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        // deny_unknown_fields guards against typo'd / injected keys at the top.
        assert!(parse_validated(br#"{"sessions":{},"evil":1}"#).is_err());
    }

    #[test]
    fn rejects_out_of_range_width() {
        assert!(parse_validated(br#"{"ui":{"sidebar_width":99999}}"#).is_err());
    }

    #[test]
    fn save_then_load_round_trips_and_is_0600() {
        let p = std::env::temp_dir().join(format!("ek_meta_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let mut st = ViewerState::default();
        st.sessions.insert("2_ssh_u@h".into(), SessionMeta { alias: Some("db".into()), pinned: false, keep: true });
        save(&p, &st).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "state file must be 0600");
        }
        let back = load(&p);
        assert_eq!(back, st);
        let _ = std::fs::remove_file(&p);
    }
}
