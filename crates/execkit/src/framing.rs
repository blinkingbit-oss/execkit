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
///
/// Decoding runs the init-resolved decoder path, quoted (`"$__ek_dp"
/// "$__ek_df"`), in its own silenced step: a user `IFS=`/`PATH=` change cannot
/// word-split or un-find it. If decoding still fails, the command reports
/// exit 125 with a stderr message rather than `eval ""` silently "succeeding"
/// with exit 0. The fallback is chosen inside the silenced step, so under
/// `set -x` only `command eval '<cmd>'` is traced. `2>|` rather than `2>`
/// so a user `set -C` (noclobber) cannot refuse the file mktemp just made.
/// The pre-create is `command : >|` for the same reason: `:` is a special
/// builtin, so a failed redirection on it (noclobber, unwritable TMPDIR) makes
/// dash/busybox ash abandon the whole run line; `command` stops that.
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
command : >|\"$__ek_f\"; chmod 600 \"$__ek_f\"; }} 2>/dev/null; \
{{ __ek_s=$(printf '%s' \"$__ek_c\" | \"$__ek_dp\" \"$__ek_df\") || \
__ek_s=\"printf 'execkit: could not decode command (was IFS/PATH changed?)\\\\n' >&2; (exit 125)\"; }} 2>/dev/null; \
{{ command eval \"$__ek_s\"; }} </dev/null 2>|\"$__ek_f\"; \
{{ __ek_rc=$?; printf '\\n%s\\037%d\\037%s\\037' '{start}' \"$__ek_rc\" \"$(printf %s \"$PWD\" | tr -d '\\037')\"; \
cat \"$__ek_f\"; rm -f \"$__ek_f\"; unset __ek_c __ek_f __ek_s; printf '%s\\n' '{end}'; }} 2>/dev/null\n",
        t8 = &token[..token.len().min(8)],
        start = m.start,
        end = m.end,
    ));
    p
}

/// Extract a complete result from the accumulated output, or `None` if the
/// trailer has not fully arrived yet.
///
/// Uses the first end marker that validates and the LAST start marker before
/// it: the command's own stdout sits before the real start marker, so anything
/// that looks like a start marker there is skipped over rather than trusted.
pub(crate) fn parse(acc: &[u8], m: &Markers) -> Option<Parsed> {
    let (start_b, end_b) = (m.start.as_bytes(), m.end.as_bytes());
    // An END whose block does not validate is skipped, not fatal: under
    // `set -v` the shell echoes the run line itself, which carries both
    // markers but a literal `\037` instead of real US bytes.
    let mut from = 0;
    let (start_pos, end_pos, s0, s1, s2) = loop {
        let end_pos = from + find(&acc[from..], end_b)?;
        from = end_pos + 1;
        let Some(start_pos) = rfind(&acc[..end_pos], start_b) else {
            continue;
        };
        let between = &acc[start_pos + start_b.len()..end_pos];
        // Only the first three US separators matter (stderr may contain more).
        let mut us = between.iter().enumerate().filter(|(_, b)| **b == US);
        if let (Some((s0, _)), Some((s1, _)), Some((s2, _))) = (us.next(), us.next(), us.next()) {
            break (start_pos, end_pos, s0, s1, s2);
        }
    };
    let between = &acc[start_pos + start_b.len()..end_pos];
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

/// Accumulates one command's raw output until its trailer arrives.
///
/// Linear in the output size, however large: each chunk is searched for the
/// end marker only in its own bytes plus `end.len() - 1` bytes of overlap
/// (so a marker split across chunks is still found), and the full [`parse`]
/// runs only once an end-marker candidate shows up. Past `cap` the buffer is
/// allowed to grow to `2 * cap` before [`compact`] cuts it back to `cap`, so
/// each compaction's copy is paid for by `cap` bytes of new input.
pub(crate) struct Accumulator {
    buf: Vec<u8>,
    cap: usize,
    /// `buf[..scanned]` has been searched: any end marker in it was already
    /// seen by `parse` and rejected (an invalid END never becomes valid, since
    /// its validity depends only on the bytes before it).
    scanned: usize,
    /// Total bytes dropped by compaction so far.
    elided: usize,
}

impl Accumulator {
    pub fn new(cap: usize) -> Self {
        Self {
            buf: Vec::new(),
            cap,
            scanned: 0,
            elided: 0,
        }
    }

    /// Append a chunk; return the parsed result once the trailer is complete.
    pub fn push(&mut self, chunk: &[u8], m: &Markers) -> Option<Parsed> {
        self.buf.extend_from_slice(chunk);
        let end = m.end.as_bytes();
        let from = self.scanned.saturating_sub(end.len().saturating_sub(1));
        // Search before compacting, so a trailer in this chunk is never cut.
        if find(&self.buf[from..], end).is_some() {
            if let Some(p) = parse(&self.buf, m) {
                return Some(p);
            }
        }
        if self.buf.len() > self.cap.saturating_mul(2) {
            compact(&mut self.buf, self.cap / 2, &mut self.elided);
        }
        // Everything now in the buffer has been searched; after a compaction
        // the tail (and so the overlap window) is unchanged.
        self.scanned = self.buf.len();
        None
    }

    /// Whether any output was dropped by compaction.
    pub fn overflowed(&self) -> bool {
        self.elided > 0
    }

    /// The raw bytes accumulated so far (for a timed-out command).
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }
}

fn elision_marker(elided: usize) -> String {
    format!("\n[execkit: {elided} bytes elided]\n")
}

/// Mid-stream anti-flood compaction: keep the first and last `keep` bytes,
/// joined by a `\n[execkit: {n} bytes elided]\n` separator where `n` is the
/// running total of `*elided` (updated here).
///
/// The separator stops a secret straddling the cut from being rejoined into
/// something redaction (which matches on the final text) fails to recognize:
/// head and tail bytes are never adjacent. On a later compaction the previous
/// separator sits right after the head and is dropped with the middle; it is
/// not counted as elided output.
fn compact(buf: &mut Vec<u8>, keep: usize, elided: &mut usize) {
    let old_sep = if *elided > 0 {
        elision_marker(*elided).len()
    } else {
        0
    };
    let tail_start = buf.len().saturating_sub(keep).max(keep + old_sep);
    *elided += tail_start - keep - old_sep;
    let sep = elision_marker(*elided);
    buf.splice(keep..tail_start, sep.into_bytes());
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
    fn parse_skips_end_marker_whose_block_does_not_validate() {
        // `set -v` echoes the run line: both markers, but a literal `\037`
        // instead of real US bytes. The real block follows it.
        let m = Markers::new("t2");
        let raw = format!(
            "{s}\\037%d\\037%s\\037' x; printf '%s\\n' '{e}'\nok\n{s}\x1f0\x1f/tmp\x1f{e}\n",
            s = m.start,
            e = m.end
        );
        let p = parse(raw.as_bytes(), &m).unwrap();
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.cwd, "/tmp");
        assert!(p.stdout.ends_with("ok"), "{:?}", p.stdout);
    }

    fn trailer(m: &Markers, rc: u8) -> String {
        format!("\n{}\x1f{rc}\x1f/tmp\x1ferr{}\n", m.start, m.end)
    }

    #[test]
    fn accumulator_finds_end_marker_split_across_chunks() {
        let m = Markers::new("split");
        let full = format!("out{}", trailer(&m, 0));
        let cut = full.find(&m.end).unwrap() + 5; // mid-END
        for split in [cut, full.len() - 2, 1] {
            let mut a = Accumulator::new(1 << 20);
            assert!(a.push(&full.as_bytes()[..split], &m).is_none());
            let p = a.push(&full.as_bytes()[split..], &m).expect("found");
            assert_eq!((p.stdout.as_str(), p.exit_code), ("out", 0));
        }
    }

    #[test]
    fn accumulator_byte_at_a_time() {
        let m = Markers::new("bytes");
        let full = format!("hello{}", trailer(&m, 3));
        // The result is complete exactly when the END marker's last byte lands.
        let done = full.find(&m.end).unwrap() + m.end.len();
        let mut a = Accumulator::new(1 << 20);
        let mut got = None;
        for (i, b) in full.bytes().enumerate().take(done) {
            let r = a.push(&[b], &m);
            if i + 1 < done {
                assert!(r.is_none(), "early result at byte {i}");
            }
            got = r;
        }
        let p = got.expect("found on the END's last byte");
        assert_eq!((p.stdout.as_str(), p.exit_code), ("hello", 3));
    }

    #[test]
    fn accumulator_skips_invalid_end_then_finds_valid_one_later() {
        // `set -v`: an invalid END (literal `\037`) arrives first, alone.
        let m = Markers::new("sv");
        let mut a = Accumulator::new(1 << 20);
        let echo = format!("{s}\\037%d\\037' x '{e}'\n", s = m.start, e = m.end);
        assert!(a.push(echo.as_bytes(), &m).is_none());
        assert!(a.push(b"ok", &m).is_none());
        let p = a.push(trailer(&m, 0).as_bytes(), &m).expect("found");
        assert!(p.stdout.ends_with("ok"), "{:?}", p.stdout);
    }

    #[test]
    fn accumulator_compacts_lazily_and_counts_all_elided_bytes() {
        let m = Markers::new("big");
        let cap = 1000;
        let mut a = Accumulator::new(cap);
        let mut sent = 0usize;
        for i in 0..500 {
            let line = format!("{i:07}\n"); // 8 bytes
            sent += line.len();
            assert!(a.push(line.as_bytes(), &m).is_none());
            assert!(a.bytes().len() <= 2 * cap + 64, "buffer grew past 2x cap");
        }
        assert!(a.overflowed());
        let raw_len = a.bytes().len();
        let p = a.push(trailer(&m, 0).as_bytes(), &m).expect("found");
        // Head and tail survive; the elided count is the true running total.
        assert!(p.stdout.starts_with("0000000\n"), "{:?}", &p.stdout[..20]);
        assert!(p.stdout.ends_with("0000499"));
        let n: usize = p
            .stdout
            .split("[execkit: ")
            .nth(1)
            .and_then(|r| r.split(' ').next())
            .and_then(|n| n.parse().ok())
            .expect("one elision marker");
        assert_eq!(p.stdout.matches("bytes elided]").count(), 1);
        let kept = raw_len - elision_marker(n).len();
        assert_eq!(n + kept, sent, "elided + kept == total");
    }

    #[test]
    fn compact_separates_head_and_tail_with_elision_marker() {
        // A secret whose first half ends the head and second half starts the
        // tail must never be rejoined.
        let head = format!("{}SECRET_PREFIX", "h".repeat(100));
        let tail = format!("SECRET_SUFFIX{}", "t".repeat(100));
        let mut buf = format!("{head}{}{tail}", "m".repeat(1000)).into_bytes();
        let mut elided = 0;
        compact(&mut buf, head.len(), &mut elided);
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("SECRET_PREFIX") && text.contains("SECRET_SUFFIX"));
        assert!(!text.contains("SECRET_PREFIXSECRET_SUFFIX"));
        assert!(text.contains("[execkit: 1000 bytes elided]"), "{text}");
        assert_eq!(elided, 1000);
    }

    #[test]
    fn compact_twice_accumulates_elided_count() {
        let mut buf = vec![b'x'; 1000];
        let mut elided = 0;
        compact(&mut buf, 50, &mut elided); // 900 elided
        buf.extend_from_slice(&[b'y'; 500]);
        compact(&mut buf, 50, &mut elided); // old sep + 500 more (tail 50 kept)
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(elided, 1400);
        assert!(text.contains("[execkit: 1400 bytes elided]"), "{text}");
        assert_eq!(text.matches("elided").count(), 1);
        assert!(text.starts_with(&"x".repeat(50)) && text.ends_with(&"y".repeat(50)));
    }

    #[test]
    fn parse_incomplete_is_none() {
        let m = Markers::new("t1");
        assert!(parse(format!("x{}\x1f0\x1f/", m.start).as_bytes(), &m).is_none());
    }
}
