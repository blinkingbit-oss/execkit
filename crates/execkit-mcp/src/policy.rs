// SPDX-License-Identifier: Apache-2.0
//! Operator command policy - an ADVISORY allow/deny fence loaded from a JSON
//! file the operator controls, NOT a per-call agent argument. It reuses
//! `execkit::Policy` for program-name matching and adds operator-only regex
//! `deny_patterns` for what names cannot express (subcommands, flags, wrappers).
//!
//! Advisory only: string matching is trivially bypassable (`/bin/rm`, base64,
//! `bash -c "..."`). The real boundary is a least-privilege user / container /
//! scoped SSH account. Never rely on this alone.

use std::path::Path;

use anyhow::Context;
use regex::Regex;
use serde::Deserialize;

/// The on-disk shape. `deny_unknown_fields` so a typo'd key is a loud error,
/// never a silently ignored security setting.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
    #[serde(default)]
    deny_patterns: Vec<String>,
}

/// Operator allow/deny, applied as a floor the agent cannot edit. Reuses
/// `execkit::Policy` for program-name matching (and its built-in dangerous
/// regex) and adds operator-only `deny_patterns` over the whole command line.
#[derive(Debug)]
pub struct OperatorPolicy {
    names: execkit::Policy,
    deny_patterns: Vec<Regex>,
}

impl OperatorPolicy {
    /// A no-op policy (nothing configured): only the names layer's built-in
    /// dangerous-pattern check applies.
    pub fn empty() -> Self {
        OperatorPolicy {
            names: execkit::Policy::default(),
            deny_patterns: Vec::new(),
        }
    }

    /// Read + parse + compile. Any failure is an error (callers fail fast).
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading policy file {}", path.display()))?;
        let pf: PolicyFile = serde_json::from_str(&text)
            .with_context(|| format!("parsing policy file {}", path.display()))?;
        let mut deny_patterns = Vec::with_capacity(pf.deny_patterns.len());
        for p in &pf.deny_patterns {
            // `regex` guarantees linear-time matching (no backtracking), so an
            // operator pattern cannot ReDoS the server. Do not swap in a
            // backtracking engine. Compiled once here, never per command.
            let re = Regex::new(p).with_context(|| format!("invalid deny_pattern /{p}/"))?;
            deny_patterns.push(re);
        }
        Ok(OperatorPolicy {
            names: execkit::Policy {
                allow: pf.allow,
                deny: pf.deny,
            },
            deny_patterns,
        })
    }

    /// Ok if allowed; Err(reason) if blocked. Operator deny patterns first
    /// (most specific operator intent), then the reused name-based check.
    /// Precedence (in `execkit::Policy`): deny wins over allow; an empty allow
    /// list means allow-all, a non-empty one is default-deny; the built-in
    /// dangerous-pattern check always applies.
    pub fn check(&self, command: &str) -> Result<(), String> {
        for re in &self.deny_patterns {
            if re.is_match(command) {
                return Err(format!("matched deny pattern /{}/", re.as_str()));
            }
        }
        self.names.check(command)
    }

    /// (allow names, deny names, deny patterns) - for `doctor`.
    pub fn counts(&self) -> (usize, usize, usize) {
        (
            self.names.allow.len(),
            self.names.deny.len(),
            self.deny_patterns.len(),
        )
    }
}

/// Load from `EXECKIT_MCP_POLICY_FILE`; unset means an empty (pass-through)
/// policy. A configured-but-broken file is an error so the server fails fast.
pub fn load_from_env() -> anyhow::Result<OperatorPolicy> {
    match std::env::var_os("EXECKIT_MCP_POLICY_FILE") {
        Some(p) => OperatorPolicy::from_file(Path::new(&p)),
        None => Ok(OperatorPolicy::empty()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(name: &str, body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ek_pol_{}_{name}", std::process::id()));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    #[test]
    fn empty_policy_passes_through_but_keeps_the_builtin_dangerous_check() {
        let p = OperatorPolicy::empty();
        assert!(
            p.check("echo hi").is_ok(),
            "no allow/deny configured -> allowed"
        );
        // empty allow/deny still inherits execkit::Policy's built-in dangerous regex.
        assert!(
            p.check("rm -rf /tmp/x").is_err(),
            "built-in dangerous pattern still blocks"
        );
        assert_eq!(p.counts(), (0, 0, 0));
    }

    #[test]
    fn name_deny_and_allow_and_priority() {
        let path = write_tmp("a.json", r#"{ "allow": ["echo","ls"], "deny": ["ls"] }"#);
        let p = OperatorPolicy::from_file(&path).unwrap();
        assert!(p.check("echo hi").is_ok());
        assert!(p.check("cat /etc/passwd").is_err(), "not in allowlist");
        assert!(p.check("ls -a").is_err(), "deny wins over allow");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn deny_pattern_catches_subcommand_and_wrapper_that_name_deny_misses() {
        let path = write_tmp(
            "b.json",
            r#"{ "deny": ["rm"], "deny_patterns": ["\\brm\\b", "kubectl\\s+delete"] }"#,
        );
        let p = OperatorPolicy::from_file(&path).unwrap();
        // name deny "rm" does NOT see argv0 of a wrapper; the pattern does.
        assert!(
            p.check("sudo rm -rf /tmp/x").is_err(),
            "wrapper caught by pattern"
        );
        assert!(
            p.check("kubectl delete pod x").is_err(),
            "subcommand caught by pattern"
        );
        assert!(p.check("kubectl get pods").is_ok(), "allowed subcommand");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_an_error() {
        let p = OperatorPolicy::from_file(std::path::Path::new("/no/such/ek-policy.json"));
        assert!(p.is_err());
    }

    #[test]
    fn malformed_json_is_an_error() {
        let path = write_tmp("c.json", "{ not json");
        assert!(OperatorPolicy::from_file(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unknown_field_is_an_error() {
        let path = write_tmp("d.json", r#"{ "alloww": ["echo"] }"#);
        assert!(
            OperatorPolicy::from_file(&path).is_err(),
            "deny_unknown_fields"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn uncompilable_regex_is_an_error_naming_the_pattern() {
        let path = write_tmp("e.json", r#"{ "deny_patterns": ["foo(bar"] }"#);
        let err = OperatorPolicy::from_file(&path).unwrap_err().to_string();
        assert!(
            err.contains("foo(bar"),
            "error names the bad pattern, got {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_from_env_unset_is_empty() {
        // env is process-global; save + restore so this does not clobber the
        // var for any other test sharing the binary.
        let prior = std::env::var_os("EXECKIT_MCP_POLICY_FILE");
        std::env::remove_var("EXECKIT_MCP_POLICY_FILE");
        let p = load_from_env().unwrap();
        assert_eq!(p.counts(), (0, 0, 0));
        if let Some(v) = prior {
            std::env::set_var("EXECKIT_MCP_POLICY_FILE", v);
        }
    }
}
