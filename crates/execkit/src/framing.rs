// SPDX-License-Identifier: Apache-2.0
//! Command framing: how one command is sent to the shell and how its result is
//! recovered from the byte stream.
//!
//! The command never reaches the shell's line reader as raw text. It is
//! base64-encoded, sent in short assignment lines, then decoded and `eval`'d
//! inside a group whose stdin is `/dev/null` and whose stderr goes to a temp
//! file. That is why comments, a trailing `&`, heredocs, `!`, tabs/control
//! bytes, syntax errors and unclosed quotes cannot leave the interactive
//! shell waiting for more input: the line reader only ever sees our own lines,
//! and a broken command is a failed `eval`, not a half-read line.
//!
//! After the command, a trailer prints
//! `\n<START>US<exit>US<cwd>US<stderr><END>\n` (US = 0x1f).

use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::output::clean;

const US: u8 = 0x1f; // unit separator

/// Base64 chunk size per assignment line. Keeps every payload line well under
/// 1 KB: canonical-mode PTYs (dash/busybox read without readline) cap a line at
/// 4 KB (MAX_CANON) and silently truncate beyond it.
const CHUNK: usize = 760;

/// 32 hex chars (128 bits) from /dev/urandom.
///
/// SEC: the token names the sentinels, so it must be unguessable - output that
/// could predict it could forge a result. A fresh one is used per command.
pub(crate) fn new_token() -> String {
    let mut rnd = [0u8; 16];
    let ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut rnd))
        .is_ok();
    if !ok {
        // No /dev/urandom (never expected on Unix): stay unique rather than
        // fail, so the session still works; uniqueness keeps framing correct
        // even though the token is then guessable.
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        rnd[..8].copy_from_slice(&nanos.to_le_bytes());
        rnd[8..].copy_from_slice(&n.to_le_bytes());
    }
    rnd.iter().map(|b| format!("{b:02x}")).collect()
}

/// Start/end sentinels for one command.
pub(crate) struct Markers {
    pub start: String,
    pub end: String,
}

impl Markers {
    pub fn new(token: &str) -> Self {
        Self {
            start: format!("__EXECKIT_{token}__"),
            end: format!("__EXECKITEND_{token}__"),
        }
    }
}

/// One command's result, fields already `clean()`ed.
pub(crate) struct Parsed {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub cwd: String,
}

/// Standard-alphabet base64 with `=` padding (hand-written: no new crates in
/// the core).
fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Build the bytes to write for one command. See the module docs.
///
/// SEC: the markers appear only on the final (run) line, which the shell has
/// read in full before the command starts, so a child cannot read them back
/// from the tty. The stderr temp file comes from `mktemp` (random, 0600) and
/// is unrelated to the token, so its name leaks nothing. Every framing step is
/// wrapped in `{ ...; } 2>/dev/null` so a user's `set -x` traces only their
/// own command, never the framing. `base64` output is `[A-Za-z0-9+/=]`, safe
/// inside double quotes.
///
/// `command eval`, not bare `eval`: `eval` is a special builtin, so a syntax
/// error inside it makes an interactive dash/busybox ash abandon the REST OF
/// THE LINE - the trailer would never print and the session would hang.
/// `command` strips the special-builtin status: the error becomes exit 2 and
/// the trailer still runs. The command still runs in the current shell.
pub(crate) fn build_payload(command: &str, token: &str) -> String {
    let m = Markers::new(token);
    let enc = b64(command.as_bytes());
    let mut p = String::with_capacity(enc.len() + enc.len() / CHUNK * 40 + 600);
    p.push_str("{ __ek_c=''; } 2>/dev/null\n");
    // base64 is ASCII, so byte chunks are char boundaries.
    for chunk in enc.as_bytes().chunks(CHUNK) {
        p.push_str("{ __ek_c=\"${__ek_c}");
        p.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        p.push_str("\"; } 2>/dev/null\n");
    }
    // `\037` is written as an octal escape for printf/tr: a raw 0x1f byte would
    // be mangled by the PTY line discipline. tr strips US from $PWD so a
    // directory name cannot inject a separator. The command runs in the current
    // shell (not a subshell) so cd/env changes persist.
    p.push_str(&format!(
        "{{ __ek_f=$(mktemp 2>/dev/null || printf '%s' \"${{TMPDIR:-/tmp}}/execkitE_$$_{t8}\"); \
: > \"$__ek_f\"; chmod 600 \"$__ek_f\"; }} 2>/dev/null; \
{{ command eval \"$(printf '%s' \"$__ek_c\" | $__ek_d)\"; }} </dev/null 2>\"$__ek_f\"; \
{{ __ek_rc=$?; printf '\\n%s\\037%d\\037%s\\037' '{start}' \"$__ek_rc\" \"$(printf %s \"$PWD\" | tr -d '\\037')\"; \
cat \"$__ek_f\"; rm -f \"$__ek_f\"; unset __ek_c __ek_f; printf '%s\\n' '{end}'; }} 2>/dev/null\n",
        t8 = &token[..token.len().min(8)],
        start = m.start,
        end = m.end,
    ));
    p
}

/// Extract a complete result from the accumulated output, or `None` if the
/// trailer has not fully arrived yet.
///
/// Uses the FIRST end marker and the LAST start marker before it: the command's
/// own stdout sits before the real start marker, so anything that looks like a
/// start marker there is skipped over rather than trusted.
pub(crate) fn parse(acc: &[u8], m: &Markers) -> Option<Parsed> {
    let (start_b, end_b) = (m.start.as_bytes(), m.end.as_bytes());
    let end_pos = find(acc, end_b)?;
    let start_pos = rfind(&acc[..end_pos], start_b)?;
    let between = &acc[start_pos + start_b.len()..end_pos];
    // Only the first three US separators matter (stderr may contain more).
    let mut us = between.iter().enumerate().filter(|(_, b)| **b == US);
    let (Some((s0, _)), Some((s1, _)), Some((s2, _))) = (us.next(), us.next(), us.next()) else {
        return None;
    };
    let exit_code: i32 = String::from_utf8_lossy(&between[s0 + 1..s1])
        .trim()
        .parse()
        .unwrap_or(-1);
    // Drop exactly the `\n` the trailer's printf put before the start marker.
    let out = &acc[..start_pos];
    let out = out.strip_suffix(b"\n").unwrap_or(out);
    Some(Parsed {
        stdout: clean(&String::from_utf8_lossy(out)),
        stderr: clean(&String::from_utf8_lossy(&between[s2 + 1..])),
        exit_code,
        cwd: clean(&String::from_utf8_lossy(&between[s1 + 1..s2])),
    })
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).rposition(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip_known_vectors() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64("é\t\x03".as_bytes()), "w6kJAw==");
    }

    #[test]
    fn payload_has_no_raw_command_bytes_and_short_lines() {
        let cmd = format!("echo hi # c\t!x & {}", "y".repeat(10_000));
        let p = build_payload(&cmd, &"a".repeat(32));
        assert!(!p.contains("echo hi"));
        assert!(!p.contains('\t'));
        assert!(p.lines().all(|l| l.len() < 1024), "a line >= 1 KB");
        assert!(p.ends_with('\n'));
    }

    #[test]
    fn parse_uses_last_start_before_first_end() {
        let m = Markers::new("t0");
        let raw = format!(
            "junk{s}\x1f9\x1f/x\x1fE\nout\n{s}\x1f0\x1f/tmp\x1ferr{e}\n",
            s = m.start,
            e = m.end
        );
        let p = parse(raw.as_bytes(), &m).unwrap();
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.cwd, "/tmp");
        assert_eq!(p.stderr, "err");
    }

    #[test]
    fn parse_incomplete_is_none() {
        let m = Markers::new("t1");
        assert!(parse(format!("x{}\x1f0\x1f/", m.start).as_bytes(), &m).is_none());
    }
}
