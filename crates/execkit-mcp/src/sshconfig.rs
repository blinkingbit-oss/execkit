// SPDX-License-Identifier: Apache-2.0
//! Minimal parser for OpenSSH's `~/.ssh/config` `Host` blocks, just enough to
//! resolve `session_create`'s ssh `host` argument as a host alias when it
//! isn't a raw hostname/IP: `HostName`, `User`, `Port`, `IdentityFile`.
//!
//! Deliberately NOT a full ssh_config implementation: `Host` patterns are
//! matched by EXACT name only (a pattern containing `*`, `?`, or `!` is never
//! treated as a match for anything, including a literal alias that happens to
//! contain those characters - OpenSSH pattern semantics are out of scope), and
//! `Include`/`Match` directives are ignored entirely (skipped like any other
//! unrecognized keyword). This is deliberate: the file is operator-owned, but
//! still a config an untrusted agent can influence indirectly (via the alias
//! it picks), so the parser stays small and easy to audit rather than pulling
//! in a full ssh_config crate.

use std::path::{Path, PathBuf};

/// Resolved fields from the `Host` block(s) matching one alias.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostEntry {
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_files: Vec<PathBuf>,
}

/// Look up `alias` in the text of an ssh_config file.
///
/// `Host` lines are matched by exact name only: a pattern containing `*`,
/// `?`, or `!` is skipped (never matched). Keywords are matched
/// case-insensitively and accept both `Key value` and `Key=value` forms.
/// `~/`-prefixed `IdentityFile` values are expanded against `home`. Per
/// OpenSSH semantics, the FIRST value seen wins for a given single-valued
/// keyword (later `Host` blocks matching the same alias cannot override an
/// already-set field); `IdentityFile` accumulates in file order instead.
/// `Include` and `Match` lines are ignored. Returns `None` if no `Host` block
/// matches `alias`.
pub fn lookup(config_text: &str, alias: &str, home: &Path) -> Option<HostEntry> {
    let mut in_block = false;
    let mut matched = false;
    let mut entry = HostEntry::default();

    for raw_line in config_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = split_kv(line) else {
            continue;
        };
        if key.eq_ignore_ascii_case("host") {
            in_block = value
                .split_whitespace()
                .any(|pat| pat == alias && !pat.contains(['*', '?', '!']));
            if in_block {
                matched = true;
            }
            continue;
        }
        if !in_block {
            continue;
        }
        if key.eq_ignore_ascii_case("hostname") {
            entry.hostname.get_or_insert_with(|| value.to_string());
        } else if key.eq_ignore_ascii_case("user") {
            entry.user.get_or_insert_with(|| value.to_string());
        } else if key.eq_ignore_ascii_case("port") {
            if entry.port.is_none() {
                if let Ok(p) = value.parse::<u16>() {
                    entry.port = Some(p);
                }
            }
        } else if key.eq_ignore_ascii_case("identityfile") {
            entry.identity_files.push(expand_tilde(value, home));
        }
        // Any other keyword (Include, Match, ProxyJump, ...) is ignored.
    }

    matched.then_some(entry)
}

/// Split a trimmed, non-comment ssh_config line into `(keyword, argument)`.
/// Accepts `Key value`, `Key=value`, and `Key = value`; strips one pair of
/// surrounding double quotes from the value if present.
fn split_kv(trimmed: &str) -> Option<(&str, &str)> {
    let idx = trimmed.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = &trimmed[..idx];
    if key.is_empty() {
        return None;
    }
    let mut rest = trimmed[idx..].trim_start();
    if let Some(stripped) = rest.strip_prefix('=') {
        rest = stripped.trim_start();
    }
    let value = rest.trim_end();
    if value.is_empty() {
        return None;
    }
    Some((key, unquote(value)))
}

fn unquote(v: &str) -> &str {
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        &v[1..v.len() - 1]
    } else {
        v
    }
}

/// Expand a leading `~/` (or bare `~`) against `home`; anything else is
/// returned as-is (relative paths are left relative - `build_session`
/// resolves them the same way `validated_key_path` resolves any relative
/// `key_path`: via canonicalize against the current directory).
fn expand_tilde(value: &str, home: &Path) -> PathBuf {
    if let Some(rest) = value.strip_prefix("~/") {
        home.join(rest)
    } else if value == "~" {
        home.to_path_buf()
    } else {
        PathBuf::from(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> PathBuf {
        PathBuf::from("/home/op")
    }

    #[test]
    fn resolves_hostname_user_port_and_identity_file() {
        let cfg = "\
Host myalias
    HostName 10.0.0.5
    User deploy
    Port 2200
    IdentityFile ~/.ssh/id_deploy
";
        let e = lookup(cfg, "myalias", &home()).expect("alias should match");
        assert_eq!(e.hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(e.user.as_deref(), Some("deploy"));
        assert_eq!(e.port, Some(2200));
        assert_eq!(
            e.identity_files,
            vec![PathBuf::from("/home/op/.ssh/id_deploy")]
        );
    }

    #[test]
    fn wildcard_host_block_is_never_matched() {
        // A `Host *` catch-all (common for global defaults like
        // ServerAliveInterval) must never leak its fields into a specific
        // alias lookup, and the literal string "*" must never match either.
        let cfg = "\
Host *
    User globaluser
    Port 9999

Host myalias
    HostName 10.0.0.5
";
        let e = lookup(cfg, "myalias", &home()).expect("alias should match");
        assert_eq!(e.hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(e.user, None, "Host * must not fill User");
        assert_eq!(e.port, None, "Host * must not fill Port");
        assert!(lookup(cfg, "*", &home()).is_none());
    }

    #[test]
    fn accepts_key_equals_value_form() {
        let cfg = "Host myalias\n    Port=2222\n";
        let e = lookup(cfg, "myalias", &home()).unwrap();
        assert_eq!(e.port, Some(2222));
    }

    #[test]
    fn unknown_alias_returns_none() {
        let cfg = "Host myalias\n    HostName 10.0.0.5\n";
        assert!(lookup(cfg, "other", &home()).is_none());
    }

    #[test]
    fn first_value_wins_for_duplicate_user() {
        // Same block, User set twice.
        let cfg = "\
Host myalias
    User first
    User second
";
        let e = lookup(cfg, "myalias", &home()).unwrap();
        assert_eq!(e.user.as_deref(), Some("first"));

        // Two separate blocks both matching the alias: OpenSSH keeps the
        // FIRST block's value even though the second block also matches.
        let cfg2 = "\
Host myalias
    User first

Host myalias
    User second
";
        let e2 = lookup(cfg2, "myalias", &home()).unwrap();
        assert_eq!(e2.user.as_deref(), Some("first"));
    }

    #[test]
    fn identity_file_entries_accumulate_in_order() {
        let cfg = "\
Host myalias
    IdentityFile ~/.ssh/id_a
    IdentityFile ~/.ssh/id_b
";
        let e = lookup(cfg, "myalias", &home()).unwrap();
        assert_eq!(
            e.identity_files,
            vec![
                PathBuf::from("/home/op/.ssh/id_a"),
                PathBuf::from("/home/op/.ssh/id_b"),
            ]
        );
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let cfg = "\
# a comment
Host myalias
    # another comment
    HostName 10.0.0.5

    User deploy
";
        let e = lookup(cfg, "myalias", &home()).unwrap();
        assert_eq!(e.hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(e.user.as_deref(), Some("deploy"));
    }

    #[test]
    fn multiple_host_patterns_on_one_line_match_exact_name() {
        let cfg = "Host other myalias\n    HostName 10.0.0.5\n";
        assert!(lookup(cfg, "myalias", &home()).is_some());
    }

    #[test]
    fn keywords_are_case_insensitive() {
        let cfg = "hOsT myalias\n    hostname 10.0.0.5\n    USER deploy\n";
        let e = lookup(cfg, "myalias", &home()).unwrap();
        assert_eq!(e.hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(e.user.as_deref(), Some("deploy"));
    }
}
