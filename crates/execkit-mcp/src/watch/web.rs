// SPDX-License-Identifier: Apache-2.0
//! A live, read-only web viewer for the audit log. A hand-rolled HTTP/SSE
//! server (loopback only, token-gated) tails the same Source the TUI uses,
//! renders events with render_event, and streams the rendered lines as JSON to
//! a self-contained page. Read-only: no endpoint mutates anything.
use crate::watch::render::{LineKind, StyledLine};

/// 16 random bytes as 32 lowercase hex chars. Used as a URL token so other
/// local processes (or a CSRF from a visited page) cannot read the transcript.
pub fn gen_token() -> anyhow::Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("system RNG: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Stable wire name for a line kind, so the browser colors without re-deriving.
#[allow(dead_code)]
fn kind_str(k: LineKind) -> &'static str {
    match k {
        LineKind::Prompt => "prompt",
        LineKind::Stdout => "stdout",
        LineKind::Stderr => "stderr",
        LineKind::ExitOk => "exit_ok",
        LineKind::ExitErr => "exit_err",
        LineKind::Marker => "marker",
    }
}

/// One SSE message: a rendered line tagged with its session id.
#[allow(dead_code)]
fn wire_json(session: &str, line: &StyledLine) -> String {
    serde_json::json!({
        "session": session,
        "kind": kind_str(line.kind),
        "text": line.text,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_32_hex_chars_and_varies() {
        let a = gen_token().unwrap();
        let b = gen_token().unwrap();
        assert_eq!(a.len(), 32, "16 bytes -> 32 hex chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two tokens should differ");
    }

    #[test]
    fn kind_str_covers_every_variant() {
        assert_eq!(kind_str(LineKind::Prompt), "prompt");
        assert_eq!(kind_str(LineKind::Stdout), "stdout");
        assert_eq!(kind_str(LineKind::Stderr), "stderr");
        assert_eq!(kind_str(LineKind::ExitOk), "exit_ok");
        assert_eq!(kind_str(LineKind::ExitErr), "exit_err");
        assert_eq!(kind_str(LineKind::Marker), "marker");
    }

    #[test]
    fn wire_json_shape() {
        let line = StyledLine { text: "/tmp $ ls".into(), kind: LineKind::Prompt };
        let v: serde_json::Value = serde_json::from_str(&wire_json("1_local", &line)).unwrap();
        assert_eq!(v["session"], "1_local");
        assert_eq!(v["kind"], "prompt");
        assert_eq!(v["text"], "/tmp $ ls");
    }
}
