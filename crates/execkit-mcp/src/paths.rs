// SPDX-License-Identifier: Apache-2.0
//! Default filesystem paths, resolved robustly so they stay correct even when
//! `$HOME` is unset (e.g. a server launched by a service manager). Every default
//! here is overridable by the operator via the matching `EXECKIT_MCP_*` env var.
use std::path::PathBuf;

/// The user's home directory, resolved by priority: `$HOME`, then the system
/// user database (passwd on Unix), then a last-resort `/root`. Same order ssh
/// and cargo use to find `~`, so `~/.ssh` resolves even with no `$HOME`.
///
/// An empty `$HOME` is treated as unset: `home` honors `HOME=""` literally,
/// which would yield a relative `.ssh` resolved against the CWD - never what we
/// want for a key directory - so we drop it and fall through to the fallback.
pub fn home_dir() -> PathBuf {
    home::home_dir()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("/root"))
}

/// Default SSH directory (`~/.ssh`). Override the key dir with
/// `EXECKIT_MCP_KEY_DIR` and the known_hosts file with `EXECKIT_MCP_KNOWN_HOSTS`.
pub fn ssh_dir() -> PathBuf {
    home_dir().join(".ssh")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_is_absolute_and_ssh_lives_under_it() {
        let home = home_dir();
        assert!(home.is_absolute(), "home should be absolute: {home:?}");
        assert_eq!(ssh_dir(), home.join(".ssh"));
        assert!(ssh_dir().ends_with(".ssh"));
    }
}
