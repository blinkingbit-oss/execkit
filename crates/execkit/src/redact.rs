// SPDX-License-Identifier: Apache-2.0
//! Secret redaction - keep credentials out of the model and the logs.
//!
//! Matching is by value shape: fixed-prefix tokens, full PEM key blocks, URL
//! userinfo passwords, and `name=value`/`name: value` pairs whose name looks
//! secret-shaped. [`Redactor`] adds a session-scoped third mechanism: literal
//! values assigned (via `export NAME=value` or `NAME=value`) to a
//! secret-shaped env var name in a command the session ran, so a value with
//! no recognizable shape (e.g. a locally-generated password) still gets
//! redacted once it has been seen.

use regex::Regex;
use std::sync::OnceLock;

/// A compiled pattern plus the `Regex::replace_all` replacement template to
/// apply. Plain shape matches use `"[REDACTED]"`; patterns that capture
/// context to keep (URL scheme/user, the `name=` prefix) use `${1}` etc.
struct Pattern {
    re: Regex,
    replacement: &'static str,
}

fn simple(re: &str) -> Pattern {
    templated(re, "[REDACTED]")
}

fn templated(re: &str, replacement: &'static str) -> Pattern {
    Pattern {
        re: Regex::new(re).unwrap(),
        replacement,
    }
}

fn patterns() -> &'static [Pattern] {
    static P: OnceLock<Vec<Pattern>> = OnceLock::new();
    P.get_or_init(|| {
        vec![
            // Fixed-width patterns use {N,} (greedy/open-ended) so a longer token
            // does not leak its tail after the matched prefix+N chars.
            simple(r"AKIA[0-9A-Z]{16,}"), // AWS access key id
            simple(r"ghp_[A-Za-z0-9]{36,}"), // GitHub PAT (classic)
            simple(r"gh[ousr]_[A-Za-z0-9]{36,}"), // GitHub OAuth/user-to-server/server-to-server/refresh token
            simple(r"github_pat_[A-Za-z0-9_]{20,}"), // GitHub fine-grained PAT
            simple(r"glpat-[A-Za-z0-9_-]{20,}"), // GitLab PAT
            simple(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), // JWT
            // Full PEM private-key block, not just the header. (?s) lets `.`
            // cross newlines; the body is non-greedy up to the END marker (or
            // end-of-string, if the block was truncated by budgeting).
            templated(
                r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)",
                "[REDACTED]",
            ),
            simple(r"xox[baprs]-[A-Za-z0-9-]{10,}"), // Slack token
            simple(r"sk_live_[A-Za-z0-9]{16,}"),     // Stripe live secret key
            simple(r"sk-ant-[A-Za-z0-9_-]{20,}"),    // Anthropic API key
            simple(r"sk-(?:proj-)?[A-Za-z0-9_-]{32,}"), // OpenAI API key
            simple(r"AIza[A-Za-z0-9_-]{35,}"),       // Google API key
            // URL userinfo password: `scheme://user:` and `@host` survive; the
            // password between them is redacted.
            templated(
                r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]+@",
                "${1}[REDACTED]@",
            ),
            // `name=value` / `name: value` secrets by name. The `{4,}` floor
            // keeps short/empty values (`token=`) untouched, and the literal
            // `[:=]` right after the name (no separator allowed in between)
            // keeps lookalikes like `password_field = ...` or `tokenizer =
            // load()` untouched, since nothing there follows the name.
            templated(
                r#"(?i)\b((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)["']?\s*[:=]\s*["']?)[^\s"']{4,}"#,
                "${1}[REDACTED]",
            ),
        ]
    })
}

/// Replace known secret shapes with `[REDACTED]`. Stateless - see [`Redactor`]
/// for redaction that also covers values learned from earlier commands.
pub fn redact(text: &str) -> String {
    let mut out = text.to_string();
    for p in patterns() {
        out = p.re.replace_all(&out, p.replacement).into_owned();
    }
    out
}

/// Matches a shell assignment: optional `export `, `NAME=value`, where
/// `value` is a double- or single-quoted string or a bare run up to
/// whitespace/`;`/`&`/`|`.
fn assignment_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?:^|[\s;&|])(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;&|]+)"#,
        )
        .unwrap()
    })
}

/// Matches an env var name that looks like it holds a secret.
fn secret_name_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(token|secret|passw|api_?key|private_?key|credential|auth)").unwrap()
    })
}

fn strip_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Session-scoped redaction: the fixed shape [`patterns`] plus literal values
/// learned (via [`Redactor::learn_from_command`]) from commands the session
/// has run, so a value with no recognizable shape still gets redacted once
/// it's been assigned to a secret-shaped name.
#[derive(Default)]
pub struct Redactor {
    literals: Vec<String>,
}

impl Redactor {
    /// Scan `cmd` for `NAME=value` (optionally `export NAME=value`)
    /// assignments whose name looks secret-shaped, and remember `value`
    /// (quotes stripped) for future [`Redactor::redact`] calls. Values
    /// shorter than 6 characters are ignored - too easy to appear by
    /// coincidence in unrelated output.
    pub fn learn_from_command(&mut self, cmd: &str) {
        for caps in assignment_pattern().captures_iter(cmd) {
            let name = &caps[1];
            if !secret_name_pattern().is_match(name) {
                continue;
            }
            let value = strip_quotes(&caps[2]);
            if value.chars().count() < 6 {
                continue;
            }
            if !self.literals.iter().any(|l| l == value) {
                self.literals.push(value.to_string());
            }
        }
    }

    /// Redact known secret shapes (as [`redact`]) plus any literals learned
    /// via [`Redactor::learn_from_command`]. Literals are applied longest
    /// first so a shorter learned value that happens to be a prefix/substring
    /// of a longer one doesn't clobber part of it first.
    pub fn redact(&self, text: &str) -> String {
        let mut out = redact(text);
        let mut literals: Vec<&String> = self.literals.iter().collect();
        literals.sort_by_key(|l| std::cmp::Reverse(l.len()));
        for lit in literals {
            out = out.replace(lit.as_str(), "[REDACTED]");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_aws_and_jwt() {
        let s = "key=AKIAIOSFODNN7EXAMPLE tok=eyJhbGciOi.JzdWIiOiI.SflKxwRJ";
        let r = redact(s);
        assert!(!r.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn github_pat_tail_not_leaked() {
        // A token longer than 36 chars must be FULLY consumed; no tail may leak.
        // SEC-6: fixed-width {36} would leave "EXTRA" visible; {36,} must not.
        let pat_36 = "A".repeat(36);
        let extra = "EXTRA";
        let input = format!("tok=ghp_{pat_36}{extra}");
        let r = redact(&input);
        assert!(
            !r.contains(extra),
            "tail of oversized ghp_ token must not leak; got: {r}"
        );
        assert!(r.contains("[REDACTED]"), "ghp_ token must be redacted");
    }

    #[test]
    fn new_secret_prefixes_are_redacted() {
        // Slack
        let slack = "xoxb-abc123def456";
        let r = redact(slack);
        assert!(
            !r.contains("xoxb-abc123def456"),
            "Slack token must be redacted"
        );
        assert!(r.contains("[REDACTED]"));

        // Stripe live secret key
        let stripe = "sk_live_abcdefghij123456";
        let r = redact(stripe);
        assert!(
            !r.contains("sk_live_abcdefghij123456"),
            "Stripe key must be redacted"
        );
        assert!(r.contains("[REDACTED]"));

        // Google API key (exactly 39 chars after AIza prefix = 35 token chars)
        let gkey = format!("AIza{}", "A".repeat(35));
        let r = redact(&gkey);
        assert!(!r.contains(&gkey), "Google API key must be redacted");
        assert!(r.contains("[REDACTED]"));

        // GitHub fine-grained PAT
        let fgpat = format!("github_pat_{}", "A".repeat(20));
        let r = redact(&fgpat);
        assert!(
            !r.contains(&fgpat),
            "GitHub fine-grained PAT must be redacted"
        );
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn benign_strings_are_not_redacted() {
        let plain = "hello world, no secrets here";
        assert_eq!(redact(plain), plain);
    }

    #[test]
    fn full_pem_private_key_body_is_redacted() {
        let body_line1 = "MIIEowIBAAKCAQEAtotallysecretkeymaterialgoeshere1234567890abcdef";
        let body_line2 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789==";
        let pem = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{body_line1}\n{body_line2}\n-----END RSA PRIVATE KEY-----\n"
        );
        let r = redact(&pem);
        assert!(
            !r.contains(body_line1) && !r.contains(body_line2),
            "PEM body must not leak; got: {r}"
        );
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn anthropic_key_is_redacted() {
        let key = format!("sk-ant-{}", "a".repeat(20));
        let r = redact(&format!("KEY={key}"));
        assert!(!r.contains(&key), "sk-ant- key must be redacted");
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn openai_style_key_is_redacted() {
        let key = format!("sk-{}", "a".repeat(32));
        let r = redact(&format!("KEY={key}"));
        assert!(!r.contains(&key), "sk- key must be redacted");
        assert!(r.contains("[REDACTED]"));

        let proj_key = format!("sk-proj-{}", "b".repeat(32));
        let r2 = redact(&format!("KEY={proj_key}"));
        assert!(!r2.contains(&proj_key), "sk-proj- key must be redacted");
        assert!(r2.contains("[REDACTED]"));
    }

    #[test]
    fn gitlab_pat_is_redacted() {
        let key = format!("glpat-{}", "a".repeat(20));
        let r = redact(&format!("TOKEN={key}"));
        assert!(!r.contains(&key), "glpat- token must be redacted");
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn gh_bracket_underscore_tokens_are_redacted() {
        for prefix in ["gho_", "ghu_", "ghs_", "ghr_"] {
            let key = format!("{prefix}{}", "a".repeat(36));
            let r = redact(&format!("TOKEN={key}"));
            assert!(!r.contains(&key), "{prefix} token must be redacted");
            assert!(r.contains("[REDACTED]"));
        }
    }

    #[test]
    fn google_api_key_tail_not_leaked() {
        // {35,} (open-ended) must not leave a longer key's tail visible.
        let key = format!("AIza{}{}", "A".repeat(35), "EXTRA");
        let r = redact(&key);
        assert!(
            !r.contains("EXTRA"),
            "tail of oversized key must not leak; got: {r}"
        );
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn url_userinfo_password_is_redacted() {
        let s = "postgres://admin:S3cretPass@db:5432/x";
        let r = redact(s);
        assert_eq!(r, "postgres://admin:[REDACTED]@db:5432/x");
    }

    #[test]
    fn key_value_secret_is_redacted() {
        let r = redact("password=hunter2");
        assert_eq!(r, "password=[REDACTED]");
    }

    #[test]
    fn innocuous_lines_are_not_redacted() {
        let path_line = "export PATH=/usr/bin";
        assert_eq!(redact(path_line), path_line);

        let tokenizer_line = "tokenizer = load()";
        assert_eq!(redact(tokenizer_line), tokenizer_line);

        let field_line = "password_field = form.get(name)";
        assert_eq!(redact(field_line), field_line);

        let short_value = "token=";
        assert_eq!(redact(short_value), short_value);
    }

    #[test]
    fn redactor_learns_export_and_redacts_literal_from_later_output() {
        let mut r = Redactor::default();
        r.learn_from_command("export MY_API_KEY=abcd1234efgh5678ijkl");
        let out = r.redact("later output contains abcd1234efgh5678ijkl in it");
        assert!(!out.contains("abcd1234efgh5678ijkl"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redactor_does_not_learn_short_values() {
        let mut r = Redactor::default();
        r.learn_from_command("export TOKEN=abcde"); // 5 chars, below the 6-char floor
        let out = r.redact("value is abcde here");
        assert_eq!(out, "value is abcde here");
    }
}
