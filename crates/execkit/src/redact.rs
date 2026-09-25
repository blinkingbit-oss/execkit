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
            // Full PEM private-key block, not just the header. When an END
            // marker follows, the whole block up to (and including) it is
            // consumed. When it doesn't (a truncated/streamed block), only
            // the *following lines that still look like PEM content* are
            // consumed - a base64 body line, or a real PEM header line
            // (`Proc-Type:`/`DEK-Info:`, matched case-insensitively; NOT any
            // arbitrary `word: ...` line - `Error: ...` or `note: ...` must
            // survive) - so a lone BEGIN doesn't blank unrelated output that
            // happens to come after it.
            // Each alternative's trailing `(?:\r?\n|\z)` is load-bearing: it
            // forces the line to be consumed in full, not just a
            // PEM-charset-looking prefix of it (e.g. "hello" out of "hello
            // world") - regex has no look-around, so the boundary has to be
            // matched literally as part of the same repetition.
            templated(
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:\r?\n(?:(?:[A-Za-z0-9+/=]+|(?i:Proc-Type|DEK-Info):[^\r\n]*)(?:\r?\n|\z))*)?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----)?",
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
            // load()` untouched, since nothing there follows the name. The
            // optional `(?:[a-z0-9_]*_)?` prefix (must end in `_`) catches
            // compound names like `DB_PASSWORD`/`AWS_SECRET_ACCESS_KEY`
            // without also matching `OLDPWD` or `tokenizer` (R8). `pwd` is
            // deliberately not a keyword (R9): `PWD` is an ordinary,
            // non-secret shell env var (current working directory).
            templated(
                r#"(?i)\b((?:[a-z0-9_]*_)?(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)["']?\s*[:=]\s*["']?)[^\s"']{4,}"#,
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
#[derive(Default, Clone)]
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

/// Redact a command line the way a session redacts its own `command` field:
/// known secret shapes plus the values the command itself assigns to
/// secret-shaped names (`export MY_AUTH=...`). For commands that never reach
/// a session (e.g. blocked by an operator policy) - see also
/// [`crate::Session::redact_command`], which also applies what the session
/// learned earlier.
pub fn redact_command(cmd: &str) -> String {
    Redactor::default().redact_command(cmd)
}

impl Redactor {
    /// [`Redactor::redact`] of `cmd` after also learning from `cmd`, without
    /// keeping what was learned.
    pub(crate) fn redact_command(&self, cmd: &str) -> String {
        let mut r = self.clone();
        r.learn_from_command(cmd);
        r.redact(cmd)
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

    #[test]
    fn r9_pwd_alone_is_not_redacted() {
        // `pwd` must not be a stateless key/value keyword -
        // PWD is a common, non-secret shell env var (current working dir).
        let s = "PWD=/tmp";
        assert_eq!(redact(s), s);
    }

    #[test]
    fn r8_underscore_prefixed_secret_names_are_redacted() {
        // The keyword may be preceded by an
        // underscore-terminated prefix, so compound env var names like
        // `DB_PASSWORD` and `AWS_SECRET_ACCESS_KEY` are caught too.
        assert_eq!(redact("DB_PASSWORD=hunter22"), "DB_PASSWORD=[REDACTED]");
        assert_eq!(
            redact("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG"),
            "AWS_SECRET_ACCESS_KEY=[REDACTED]"
        );
    }

    #[test]
    fn r8_underscore_prefix_false_positives_still_survive() {
        // The optional prefix must end in `_`, so `OLDPWD` (no underscore
        // before any keyword) and `tokenizer`/`password_field` (keyword not
        // immediately followed by `[:=]`) must not match. `pwd` alone is no
        // longer a keyword at all.
        let old_pwd = "OLDPWD=/home/x";
        assert_eq!(redact(old_pwd), old_pwd);

        let pwd = "PWD=/tmp";
        assert_eq!(redact(pwd), pwd);

        let path_line = "export PATH=/usr/bin";
        assert_eq!(redact(path_line), path_line);

        let tokenizer_line = "tokenizer = load()";
        assert_eq!(redact(tokenizer_line), tokenizer_line);

        let field_line = "password_field = form.get(x)";
        assert_eq!(redact(field_line), field_line);
    }

    #[test]
    fn r10_pem_without_end_marker_only_consumes_pem_looking_lines() {
        // A lone BEGIN with no END must not blank all
        // subsequent output - only lines that look like PEM content
        // (base64, or `Key: value` PEM headers) are consumed.
        let body_line1 = "MIIEowIBAAKCAQEAtotallysecretkeymaterialgoeshere1234567890abcdef";
        let body_line2 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789==";
        let text =
            format!("-----BEGIN RSA PRIVATE KEY-----\n{body_line1}\n{body_line2}\nhello world");
        let r = redact(&text);
        assert!(
            !r.contains(body_line1) && !r.contains(body_line2),
            "key lines must be redacted; got: {r}"
        );
        assert!(
            r.ends_with("hello world"),
            "trailing non-PEM text must survive; got: {r}"
        );
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn r10_pem_full_block_with_end_marker_still_redacted() {
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
    fn r10_pem_header_lines_are_consumed_as_pem_content() {
        // Encrypted PEM blocks carry `Key: value` header lines before the
        // base64 body (e.g. Proc-Type/DEK-Info); these must be treated as
        // PEM-looking content, not as the line that stops the match.
        let text = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC,1234567890ABCDEF\nMIIEowIBAAKCAQEAsecretkeybodyhere1234567890abcdef\n-----END RSA PRIVATE KEY-----\n";
        let r = redact(text);
        assert!(!r.contains("secretkeybodyhere"));
        assert!(!r.contains("DEK-Info"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn r10_pem_header_allowance_does_not_swallow_arbitrary_colon_lines() {
        // The header alternative must only match real PEM header
        // keys (Proc-Type / DEK-Info), not any `word: ...`-shaped line - an
        // unrelated `Error: ...` or `note: ...` line after a lone BEGIN must
        // survive untouched.
        let text = "-----BEGIN RSA PRIVATE KEY-----\nError: something\nrest of output";
        let r = redact(text);
        assert!(
            r.contains("Error: something"),
            "unrelated colon-shaped line must survive; got: {r}"
        );
        assert!(
            r.ends_with("rest of output"),
            "trailing output must survive; got: {r}"
        );
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn r10_pem_header_allowance_case_insensitive_still_not_arbitrary() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nnote: hello\nrest of output";
        let r = redact(text);
        assert!(
            r.contains("note: hello"),
            "unrelated colon-shaped line must survive; got: {r}"
        );
        assert!(
            r.ends_with("rest of output"),
            "trailing output must survive; got: {r}"
        );
        assert!(r.contains("[REDACTED]"));
    }
}
