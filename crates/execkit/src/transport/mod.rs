// SPDX-License-Identifier: Apache-2.0
//! Transports - how a session reaches an environment.
//!
//! `Session` frames commands on top of a byte-level [`Transport`], so the
//! framing / policy / redaction / audit logic is identical across local PTY,
//! SSH, and (later) Docker/K8s.

use std::time::{Duration, Instant};

use crate::error::{Error, Result};

pub mod docker;
pub mod local;
pub mod ssh;

/// A byte-level duplex link to a live shell.
pub trait Transport: Send {
    /// Write raw bytes to the shell's stdin.
    fn write_all(&mut self, bytes: &[u8]) -> Result<()>;
    /// Next available output chunk, or `None` on timeout/disconnect.
    fn recv_timeout(&self, dur: Duration) -> Option<Vec<u8>>;
}

/// Disable echo + prompts + history + job notices, pick a base64 decoder, then
/// block until the shell confirms readiness.
///
/// Transport-agnostic and race-free: the readiness tag is printed via
/// `EXECKITrdy''<n>` so the *output* is the contiguous tag while the *echoed
/// command line* contains the `''` - we match only real output, never the
/// pre-`stty -echo` echo. The tag ends in `ok` only if a decoder was found
/// (GNU/busybox `base64 -d`, or BSD/macOS `base64 -D`); framing needs one.
/// The decoder is stored as a resolved path (`__ek_dp`) plus flag (`__ek_df`)
/// and always run quoted, so a later `PATH=`/`unset PATH`/`IFS=` in the
/// user's session cannot break decoding (see `framing::build_payload`).
///
/// SEC: history is turned off (`set +o history`, `unset HISTFILE`) so agent
/// commands - which may carry secrets - are never written to a history file.
/// `set +H` stops `!` history expansion; `set +m` stops bash printing job
/// notices (`[1] pid`, `[1]+ Done`) into later commands' output. dash/busybox
/// reject some of these options, and `set` is a special builtin: its error
/// makes an interactive dash/ash drop the REST OF THE LINE (so the readiness
/// tag would never print). `command set` strips the special-builtin status so
/// the error is just a non-zero status, silenced by `2>/dev/null`. The line
/// must stay under 1 KB (canonical-mode PTY line limit, see `framing`).
pub(crate) fn shell_init(t: &mut dyn Transport) -> Result<()> {
    const READY: &[u8] = b"EXECKITrdy9f3a7cok";
    t.write_all(
        b"stty -echo 2>/dev/null; PS1=''; PS2=''; PROMPT_COMMAND=''; \
command set +o history 2>/dev/null; command set +H 2>/dev/null; command set +m 2>/dev/null; \
unset HISTFILE; \
__ek_dp=$(command -v base64 2>/dev/null); \
if printf 'YQ==' | \"$__ek_dp\" -d >/dev/null 2>&1; then __ek_df=-d; \
elif printf 'YQ==' | \"$__ek_dp\" -D >/dev/null 2>&1; then __ek_df=-D; \
else __ek_dp=''; fi; \
printf '%s\\n' EXECKITrdy''9f3a7c\"${__ek_dp:+ok}\"''\n",
    )?;
    let mut acc = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Transport("shell init timed out".into()));
        }
        match t.recv_timeout(remaining) {
            Some(c) => {
                acc.extend_from_slice(&c);
                if contains(&acc, READY) {
                    return Ok(());
                }
                // The bare tag followed by a line end (the PTY may send `\r\n`)
                // means the shell ran the probe and found no decoder.
                if contains(&acc, b"EXECKITrdy9f3a7c\n") || contains(&acc, b"EXECKITrdy9f3a7c\r") {
                    return Err(Error::Transport(
                        "execkit needs 'base64' on the target shell (coreutils or busybox)".into(),
                    ));
                }
            }
            None => return Err(Error::Transport("shell init: disconnected".into())),
        }
    }
}

pub(crate) fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && hay.len() >= needle.len()
        && hay.windows(needle.len()).any(|w| w == needle)
}
