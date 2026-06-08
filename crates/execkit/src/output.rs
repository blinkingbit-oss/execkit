// SPDX-License-Identifier: Apache-2.0
//! Output hygiene: ANSI/control stripping and bounded (anti-flood) truncation.

/// Strip ANSI/VT escapes (CSI, OSC, simple two-char ESC).
///
/// The OSC branch must be handled before the generic two-char branch, since `]`
/// (0x5D) falls inside the generic `@-Z\-_` range and would otherwise swallow
/// only `ESC ]` and leave the title text behind.
pub fn strip_ansi(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == 0x1b {
            if i + 1 < b.len() && b[i + 1] == b'[' {
                i += 2; // CSI: params... final byte in 0x40..=0x7e
                while i < b.len() && !(0x40..=0x7e).contains(&b[i]) {
                    i += 1;
                }
                i += 1;
            } else if i + 1 < b.len() && b[i + 1] == b']' {
                i += 2; // OSC: until BEL or ST (ESC \)
                while i < b.len() && b[i] != 0x07 {
                    if b[i] == 0x1b && i + 1 < b.len() && b[i + 1] == b'\\' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                i += 1;
            } else {
                i += 2; // other two-char ESC
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Normalize PTY output: strip ANSI, drop CRs (ONLCR), strip C0 control bytes
/// (everything below 0x20 except `\n` and `\t`), then trim surrounding blanks.
///
/// Removing the remaining C0 bytes is defense-in-depth for the sentinel framing:
/// it scrubs any residual US (0x1f) or NUL (0x00) so a hostile command cannot
/// smuggle separators or embedded NULs into the final stdout/stderr/cwd fields.
pub fn clean(s: &str) -> String {
    strip_ansi(s)
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || c >= '\u{20}')
        .collect::<String>()
        .trim_matches('\n')
        .to_string()
    // Note: `\r` (0x0d) is < 0x20 and not `\n`/`\t`, so it is dropped here too -
    // this subsumes the old explicit CR strip used for ONLCR-translated output.
}

/// Bound output to roughly `max` characters using a head+tail keep with an
/// elision marker. Returns `(text, truncated)`. Char-based so it never splits a
/// UTF-8 boundary.
pub fn bound(s: &str, max: usize) -> (String, bool) {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return (s.to_string(), false);
    }
    if max < 2 {
        return (String::new(), true);
    }
    let half = max / 2;
    let head: String = chars[..half].iter().collect();
    let tail: String = chars[chars.len() - half..].iter().collect();
    let elided = chars.len() - 2 * half;
    (
        format!("{head}\n... {elided} chars elided ...\n{tail}"),
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_colors_cursor_and_osc() {
        assert_eq!(strip_ansi("\x1b[31mred\x1b[0m"), "red");
        assert_eq!(strip_ansi("abc\x1b[2Kdef"), "abcdef");
        assert_eq!(strip_ansi("\x1b]0;title\x07visible"), "visible");
    }

    #[test]
    fn clean_strips_c0_controls_but_keeps_tab_and_newline() {
        // CR removed, lines preserved, surrounding newlines trimmed.
        assert_eq!(clean("a\r\nb\r\n"), "a\nb");
        // US (0x1f) and NUL (0x00) scrubbed; tab kept.
        assert_eq!(clean("x\u{1f}y\0z\tw"), "xyz\tw");
        // ANSI still stripped before the control filter runs.
        assert_eq!(clean("\x1b[31mr\x1b[0m"), "r");
    }

    #[test]
    fn bound_keeps_head_and_tail() {
        let (out, t) = bound(&"x".repeat(100), 10);
        assert!(t);
        assert!(out.contains("elided"));
        let (out2, t2) = bound("short", 10);
        assert!(!t2);
        assert_eq!(out2, "short");
    }
}
