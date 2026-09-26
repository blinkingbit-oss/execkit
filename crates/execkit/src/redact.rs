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

use regex::{Captures, Regex};
use std::sync::OnceLock;

/// A compiled pattern plus how to replace a match. Plain shape matches use
/// the template `"[REDACTED]"`; patterns that capture context to keep (URL
/// scheme/user, `Bearer`) use `${1}` etc. The key/value pattern needs logic
/// the regex cannot express (no look-around), so it uses a function.
struct Pattern {
    re: Regex,
    replacement: Replacement,
}

enum Replacement {
    Template(&'static str),
    Func(fn(&Captures) -> String),
}

fn simple(re: &str) -> Pattern {
    templated(re, "[REDACTED]")
}

fn templated(re: &str, replacement: &'static str) -> Pattern {
    Pattern {
        re: Regex::new(re).unwrap(),
        replacement: Replacement::Template(replacement),
    }
}

/// Replacement for the key/value pattern: group 1 is the `name=` prefix,
/// then one of: a double-quoted value (group 2), a single-quoted value
/// (group 3) - each may hold the other kind of quote - or an unquoted one
/// (group 5) with an optional unmatched opening quote (group 4, e.g. a
/// value whose closing quote is on a later line) and the quote right after
/// it (group 6, consumed so it can be seen here and put back). Quoted
/// values are always redacted, keeping their quotes. An unquoted value is
/// left alone when it is code.
///
/// The regex lets an unquoted value run through `)`; the value really ends
/// at its first `)` that has no `(` before it inside the value (see
/// `split_at_unmatched_paren`), so `(API_KEY=v)&& y` keeps its `)` while
/// `password=Pass(word)!` is redacted in full. What follows that `)` is
/// matched again on its own.
fn key_value_replace(c: &Captures) -> String {
    let prefix = &c[1];
    if c.get(2).is_some() {
        return format!("{prefix}\"[REDACTED]\"");
    }
    if c.get(3).is_some() {
        return format!("{prefix}'[REDACTED]'");
    }
    let open = c.get(4).map_or("", |m| m.as_str());
    let full = c.get(5).map_or("", |m| m.as_str());
    let after = c.get(6).map_or("", |m| m.as_str());
    let (value, rest) = split_at_unmatched_paren(full);
    let rest = key_value_pattern().replace_all(rest, key_value_replace);
    // The code check sees the value cut at its first `)`, with that `)` as
    // the next character (`self.tokens.first(` then `)`).
    let (code_value, code_next) = match full.find(')') {
        Some(i) => (&full[..i], Some(')')),
        None => (full, after.chars().next()),
    };
    if value.chars().count() < 4 || looks_like_code(code_value, code_next) {
        return format!("{prefix}{open}{value}{rest}{after}");
    }
    format!("{prefix}{open}[REDACTED]{rest}{after}")
}

/// Split `value` at its first `)` that closes nothing opened inside it: that
/// `)` closes a group opened before the value (`(TOKEN=v)`), so it and
/// everything after it are not part of the value.
fn split_at_unmatched_paren(value: &str) -> (&str, &str) {
    let mut depth = 0usize;
    for (i, ch) in value.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' if depth == 0 => return value.split_at(i),
            ')' => depth -= 1,
            _ => {}
        }
    }
    (value, "")
}

/// An unquoted value is code, not a secret, only in these narrow shapes -
/// an identifier (letters, digits, `_`, `.`, `::`; 3+ chars, not starting
/// with a digit) immediately followed by a bracket, and:
/// - the identifier is a path (has `.` or `::`), the value ends right at
///   the bracket, and a quote or `)` follows (`cfg.get(` then `"x")`,
///   `self.tokens.first(` then `)`) - `my.pass(` at end of line is redacted;
/// - the bracket is `<` followed by an uppercase letter (`Option<String>`,
///   `Map<K,`);
/// - the bracket is `(` followed by a quote (`get(` then `"abcdef")`).
///
/// Everything else is redacted, including real code like `vec[0]` or
/// `load(x)`: human passwords (`Pass[123]`, `Summer{2024}`, `abc(def)`)
/// have the same shape, and leaking one is worse. `next` is the character
/// right after the value (a quote or `)`), if any.
fn looks_like_code(value: &str, next: Option<char>) -> bool {
    let id_len = value
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | ':')))
        .unwrap_or(value.len());
    let (id, rest) = value.split_at(id_len);
    let mut rest_chars = rest.chars();
    let Some(bracket) = rest_chars.next().filter(|b| "(<[{".contains(*b)) else {
        return false;
    };
    if id.len() < 3 || id.starts_with(|ch: char| ch.is_ascii_digit()) {
        return false;
    }
    let after = rest_chars.as_str();
    let first_after = after.chars().next().or(next);
    let is_path = id.contains('.') || id.contains("::");
    (is_path && after.is_empty() && next.is_some())
        || (bracket == '<' && first_after.is_some_and(|ch| ch.is_ascii_uppercase()))
        || (bracket == '(' && after.is_empty() && matches!(next, Some('"' | '\'')))
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
            // HTTP bearer credentials: the word `Bearer` survives. Before the
            // key/value pattern, so `token: Bearer <tok>` loses the token, not
            // just the word `Bearer`.
            // The token runs to whitespace, a quote, `,` or `;`, so an odd
            // character (`%2F`) cannot cut it short and leak its tail.
            templated(r#"(?i)\b(Bearer)\s+[^\s"',;]{16,}"#, "${1} [REDACTED]"),
            // HTTP Basic credentials (base64 `user:pass`). Anchored on the
            // `Authorization:` header so prose like "Basic Authentication"
            // survives.
            templated(
                r"(?i)\b(Authorization:\s*Basic)\s+[A-Za-z0-9+/=]{8,}",
                "${1} [REDACTED]",
            ),
            // `name=value` / `name: value` secrets by name. The `{4,}` floor
            // keeps short/empty values (`token=`) untouched, and the literal
            // `[:=]` right after the name (no separator allowed in between)
            // keeps lookalikes like `password_field = ...` or `tokenizer =
            // load()` untouched, since nothing there follows the name. The
            // optional `(?:[a-z0-9_]*_)?` prefix (must end in `_`) catches
            // compound names like `DB_PASSWORD`/`AWS_SECRET_ACCESS_KEY`
            // without also matching `OLDPWD` or `tokenizer`. `pwd` is
            // deliberately not a keyword: `PWD` is an ordinary,
            // non-secret shell env var (current working directory). The value
            // stops at `;`, `&`, `|` and at a `)` with no matching `(` in the
            // value, so in `X_TOKEN=v&&echo ok` only `v` is redacted and the
            // rest of the command stays readable. A
            // comma does NOT end it: `password=abcd,efg` must not leak `efg`
            // (losing a trailing `,` after a redacted value is the price).
            // A quoted value runs to the next quote and may hold anything
            // (`"p(ss)word"`). An unquoted value may contain brackets too
            // (`Xk9(mQ2!zR`); only a few narrow code shapes (`cfg.get("x")`,
            // `Option<String>`, `get("x")` - see `looks_like_code`) are left
            // alone, decided in `key_value_replace` since `regex` has no
            // look-around. A bare
            // identifier value (TS `password: string`) still matches.
            Pattern {
                re: key_value_pattern().clone(),
                replacement: Replacement::Func(key_value_replace),
            },
        ]
    })
}

/// The `name=value` / `name: value` pattern (see [`patterns`]).
fn key_value_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b((?:[a-z0-9_]*_)?(?:password|passwd|secret[_-]?key|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)["']?\s*[:=]\s*)(?:"([^"\r\n]{4,})"|'([^'\r\n]{4,})'|(["']?)([^\s"';&|]{4,})(["'])?)"#,
        )
        .unwrap()
    })
}

/// Replace known secret shapes with `[REDACTED]`. Stateless - see [`Redactor`]
/// for redaction that also covers values learned from earlier commands.
pub fn redact(text: &str) -> String {
    let mut out = text.to_string();
    for p in patterns() {
        out = match p.replacement {
            Replacement::Template(t) => p.re.replace_all(&out, t),
            Replacement::Func(f) => p.re.replace_all(&out, f),
        }
        .into_owned();
    }
    out
}

/// Matches a shell assignment: optional `export `, `NAME=value`, where
/// `value` is a double- or single-quoted string or a bare run up to
/// whitespace/`;`/`&`/`|`. A bare run is cut at its first unmatched `)` by
/// the caller. An assignment may follow `(` (a subshell).
fn assignment_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?:^|[\s;&|(])(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;&|]+)"#,
        )
        .unwrap()
    })
}

/// Matches an env var name that looks like it holds a secret.
///
/// `auth` counts only as its own `_`-delimited word (`AUTH`, `MY_AUTH`,
/// `BASIC_AUTH_PASS`, `OAUTH_...`) or run into `KEY`/`TOKEN`/`PASS`
/// (`AUTHKEY`), never inside another word: `GIT_AUTHOR_NAME` and
/// `AUTHORITY_URL` are not secrets. `authoriz` and `authent` match anywhere
/// (`HTTP_AUTHORIZATION`, `AUTHENTICATION_TOKEN`).
fn secret_name_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(token|secret|passw|api_?key|private_?key|credential|authoriz|authent|(?:^|_)o?auth(?:$|_|key|token|pass))",
        )
        .unwrap()
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
            let raw = &caps[2];
            let stripped = strip_quotes(raw);
            let value = if stripped.len() != raw.len() {
                stripped
            } else {
                let (value, rest) = split_at_unmatched_paren(raw);
                // `(A_TOKEN=x)(B_TOKEN=y)`: the rest may hold more assignments.
                self.learn_from_command(rest);
                value
            };
            if !secret_name_pattern().is_match(&caps[1]) {
                continue;
            }
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

    #[test]
    fn auth_matches_only_as_a_word_not_inside_author() {
        let mut r = Redactor::default();
        r.learn_from_command(
            r#"export GIT_AUTHOR_NAME="Jay Shankar"; export AUTHORITY_URL=https://x.example"#,
        );
        let out = r.redact("Author: Jay Shankar via https://x.example");
        assert_eq!(out, "Author: Jay Shankar via https://x.example");

        for cmd in [
            "export MY_AUTH=secretvalue",
            "AUTH_TOKEN=secretvalue",
            "export AUTH=secretvalue",
            "export BASIC_AUTH_PASS=secretvalue",
            "export OAUTH_CLIENT=secretvalue",
            "export X_AUTHKEY=secretvalue",
        ] {
            let mut r = Redactor::default();
            r.learn_from_command(cmd);
            assert_eq!(r.redact("v=secretvalue"), "v=[REDACTED]", "{cmd}");
        }
    }

    #[test]
    fn key_value_redaction_stops_at_shell_operators() {
        assert_eq!(
            redact("export X_TOKEN=abcdef123&&echo ok"),
            "export X_TOKEN=[REDACTED]&&echo ok"
        );
        assert_eq!(
            redact("export GH_TOKEN=abcdef123; echo ok"),
            "export GH_TOKEN=[REDACTED]; echo ok"
        );
        assert_eq!(
            redact("export GH_TOKEN=abcdef123;echo ok"),
            "export GH_TOKEN=[REDACTED];echo ok"
        );
        assert_eq!(redact("PASSWORD=abcdef123|cat"), "PASSWORD=[REDACTED]|cat");
        assert_eq!(
            redact("(API_KEY=abcdef123)&& x"),
            "(API_KEY=[REDACTED])&& x"
        );
    }

    #[test]
    fn learned_value_stops_at_shell_operators() {
        let mut r = Redactor::default();
        r.learn_from_command("export MY_SECRET=abcdef123&&echo ok;(MY_PASSWD=zyxwvu987)");
        assert_eq!(r.redact("abcdef123 zyxwvu987"), "[REDACTED] [REDACTED]");
        // `&&echo` / `)` were not learned as part of a value.
        assert_eq!(r.redact("&&echo ok )"), "&&echo ok )");
    }

    #[test]
    fn key_value_redaction_leaves_source_code_intact() {
        for line in [
            "pub token: Option<String>,",
            r#"let access_key = cfg.get("x");"#,
            "password: Map<K, V>",
            "token: self.tokens.first()",
        ] {
            assert_eq!(redact(line), line, "source line must survive");
            assert_eq!(redact_command(line), line, "source line must survive");
        }
    }

    #[test]
    fn key_value_redaction_still_catches_real_secrets() {
        for (input, want) in [
            ("password=hunter22", "password=[REDACTED]"),
            ("DB_PASSWORD=x9!kQ2", "DB_PASSWORD=[REDACTED]"),
            (r#"api_key: "abc123xyz""#, r#"api_key: "[REDACTED]""#),
            ("token: abcd1234efgh", "token: [REDACTED]"),
            (
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG",
                "AWS_SECRET_ACCESS_KEY=[REDACTED]",
            ),
            (
                "export X_TOKEN=abcdef123&&echo ok",
                "export X_TOKEN=[REDACTED]&&echo ok",
            ),
            (
                "export GH_TOKEN=abcdef123;echo ok",
                "export GH_TOKEN=[REDACTED];echo ok",
            ),
            ("token=abcd1234, next", "token=[REDACTED] next"),
            (
                "password=hunter22\nsecret=hunter33",
                "password=[REDACTED]\nsecret=[REDACTED]",
            ),
            (
                "password=abcd;token=efgh",
                "password=[REDACTED];token=[REDACTED]",
            ),
        ] {
            assert_eq!(redact(input), want, "{input}");
        }
    }

    #[test]
    fn passwords_with_brackets_are_still_redacted() {
        for (input, secret) in [
            ("DB_PASSWORD=Xk9(mQ2!zR", "Xk9(mQ2!zR"),
            ("password=p<ssw0rd", "p<ssw0rd"),
            ("password=abc[1]def", "abc[1]def"),
            ("password=x9!k{Q2}zz", "x9!k{Q2}zz"),
            ("token={abcdefgh}", "{abcdefgh}"),
            ("password=a.b(c", "a.b(c"),
            (r#"api_key: "abc<defgh""#, "abc<defgh"),
            (r#"password: "p(ss)word123""#, "p(ss)word123"),
            ("password='ab{cd}ef'", "ab{cd}ef"),
        ] {
            let r = redact(input);
            assert!(r.contains("[REDACTED]"), "{input} -> {r}");
            // No 3+ char run of the secret may survive after the key.
            let key = &input[..input.find(secret).unwrap()];
            let shown = r.strip_prefix(key).expect("key kept");
            let chars: Vec<char> = secret.chars().collect();
            for w in chars.windows(3) {
                let w: String = w.iter().collect();
                assert!(!shown.contains(&w), "{input} leaked {w:?}: {r}");
            }
        }
        assert_eq!(
            redact(r#"api_key: "abc<defgh""#),
            r#"api_key: "[REDACTED]""#
        );
        assert_eq!(redact("password='ab{cd}ef'"), "password='[REDACTED]'");
        assert_eq!(
            redact(r#"{"password":"hunter22","api_key": "a(b)c<d", "user":"jay"}"#),
            r#"{"password":"[REDACTED]","api_key": "[REDACTED]", "user":"jay"}"#
        );
        assert_eq!(
            redact("(API_KEY=abcdef123)&& x"),
            "(API_KEY=[REDACTED])&& x"
        );
    }

    #[test]
    fn code_shapes_survive_key_value_redaction() {
        for line in [
            "pub token: Option<String>,",
            r#"let access_key = cfg.get("x");"#,
            r#"let token = get("abcdef");"#,
            "password: Map<K, V>",
            "token: self.tokens.first()",
            "let token = std::env::var(\"T\");",
            "token = std::env::var('T')",
        ] {
            assert_eq!(redact(line), line);
        }
    }

    #[test]
    fn unterminated_and_mixed_quote_values_are_redacted() {
        for (input, want) in [
            (r#"password: "hunter22"#, r#"password: "[REDACTED]"#),
            (r#"PASSWORD="first-line-of"#, r#"PASSWORD="[REDACTED]"#),
            (r#"token="abcdefgh123"#, r#"token="[REDACTED]"#),
            (r#"password="abc'defghij""#, r#"password="[REDACTED]""#),
            (r#"password="it's-a-secret""#, r#"password="[REDACTED]""#),
            (r#"password='say "hi" now1'"#, "password='[REDACTED]'"),
            ("token=abcdef123'", "token=[REDACTED]'"),
        ] {
            assert_eq!(redact(input), want, "{input}");
        }
    }

    #[test]
    fn dotted_path_at_end_of_line_is_not_code() {
        for (input, want) in [
            ("password=my.pass(", "password=[REDACTED]"),
            ("password=Hunter.2024(", "password=[REDACTED]"),
            ("password=abc.def[", "password=[REDACTED]"),
            ("password=my.pass(\nnext", "password=[REDACTED]\nnext"),
        ] {
            assert_eq!(redact(input), want, "{input}");
        }
        for code in [
            r#"let access_key = cfg.get("x");"#,
            "token: self.tokens.first()",
            "token = std::env::var('T')",
        ] {
            assert_eq!(redact(code), code);
        }
    }

    /// Only the narrow code shapes survive; bracket shapes that also look
    /// like human passwords are redacted, even when they are really code.
    #[test]
    fn ambiguous_bracket_values_are_redacted() {
        for (input, want) in [
            ("let secret = vec[0];", "let secret = [REDACTED];"),
            ("token = load(x);", "token = [REDACTED];"),
            ("api_key = build{x}", "api_key = [REDACTED]"),
        ] {
            assert_eq!(redact(input), want);
        }
    }

    #[test]
    fn human_passwords_with_brackets_are_redacted_in_output() {
        for (input, secret) in [
            ("password=abc(def)", "abc(def"),
            ("DB_PASSWORD=Pass[123]", "Pass[123]"),
            ("password=Hunter[2024]", "Hunter[2024]"),
            ("password=Summer{2024}", "Summer{2024}"),
            ("password=Pass(word)!", "Pass(word"),
            ("password=Passw0rd(", "Passw0rd("),
            ("token=abc<def>", "abc<def>"),
            ("SECRET=Tr0ub4dor[3]", "Tr0ub4dor[3]"),
            ("secret: s3cr3t(1)", "s3cr3t(1"),
            ("token: Abc123(def)", "Abc123(def"),
            ("password=a.b(c", "a.b(c"),
        ] {
            // Output path (a `cat .env`), not only the command path.
            let r = redact(input);
            assert!(!r.contains(secret), "{input} -> {r}");
            let key = &input[..input.find(secret).unwrap()];
            assert!(r.starts_with(&format!("{key}[REDACTED]")), "{input} -> {r}");
        }
    }

    #[test]
    fn secret_key_names_are_redacted() {
        assert_eq!(
            redact("SECRET_KEY=django-insecure-abc123"),
            "SECRET_KEY=[REDACTED]"
        );
        assert_eq!(redact("secret-key: abcdefgh"), "secret-key: [REDACTED]");
    }

    #[test]
    fn bearer_tail_after_odd_characters_does_not_leak() {
        assert_eq!(
            redact("Authorization: Bearer abcdefghijklmnop%2Fxyz"),
            "Authorization: Bearer [REDACTED]"
        );
        assert_eq!(
            redact(r#"-H "Authorization: Bearer abcdefghijklmnop%2Fxyz", next"#),
            r#"-H "Authorization: Bearer [REDACTED]", next"#
        );
    }

    #[test]
    fn basic_auth_is_redacted() {
        assert_eq!(
            redact("Authorization: Basic dXNlcjpwYXNzd29yZA=="),
            "Authorization: Basic [REDACTED]"
        );
        assert_eq!(
            redact(r#"curl -H "authorization: basic dXNlcjpwYXNz" x"#),
            r#"curl -H "authorization: basic [REDACTED]" x"#
        );
        for benign in ["Basic Authentication is enabled", "Basic usage: foo"] {
            assert_eq!(redact(benign), benign);
        }
    }

    #[test]
    fn comma_does_not_end_a_redacted_value() {
        let r = redact("password=abcd,efg");
        assert!(!r.contains("efg"), "partial secret leak: {r}");
        assert_eq!(r, "password=[REDACTED]");
        let r = redact("token: abcd1234efgh,");
        assert!(!r.contains("abcd1234efgh"), "{r}");
        assert!(r.starts_with("token: [REDACTED]"), "{r}");
    }

    #[test]
    fn bearer_tokens_are_redacted_keeping_the_word() {
        assert_eq!(
            redact("Authorization: Bearer abcdefghijklmnop1234"),
            "Authorization: Bearer [REDACTED]"
        );
        assert_eq!(
            redact(r#"curl -H "Authorization: Bearer eyJ0eXAi.abc-def_123+/=xyz" https://x"#),
            r#"curl -H "Authorization: Bearer [REDACTED]" https://x"#
        );
        assert_eq!(
            redact("authorization: bearer ABCDEFGHIJKLMNOP.qrs"),
            "authorization: bearer [REDACTED]"
        );
        assert_eq!(
            redact("token: Bearer abcdefghijklmnop1234"),
            "token: [REDACTED] [REDACTED]"
        );
        assert_eq!(
            redact_command(r#"curl -H "Authorization: Bearer <token>" https://x"#),
            r#"curl -H "Authorization: Bearer <token>" https://x"#
        );
        for benign in [
            "Bearer x",
            "Authorization: Bearer short123",
            "the bearer of news",
        ] {
            assert_eq!(redact(benign), benign);
        }
    }

    #[test]
    fn close_paren_inside_a_value_does_not_leak_its_tail() {
        for (input, want) in [
            (
                "SECRET_KEY=django-insecure-(abc)xyz123",
                "SECRET_KEY=[REDACTED]",
            ),
            ("password=Pass(word)!", "password=[REDACTED]"),
            ("token=getX(y)z12", "token=[REDACTED]"),
            ("(API_KEY=abcdef123)&& y", "(API_KEY=[REDACTED])&& y"),
            (
                "(a_token=abcdef123)password=ghijkl99",
                "(a_token=[REDACTED])password=[REDACTED]",
            ),
        ] {
            assert_eq!(redact(input), want, "{input}");
        }
        for line in [
            "pub token: Option<String>,",
            r#"let access_key = cfg.get("x");"#,
            r#"let token = get("abcdef");"#,
            "token: self.tokens.first()",
        ] {
            assert_eq!(redact(line), line);
        }
    }

    #[test]
    fn learned_value_keeps_balanced_parens() {
        let mut r = Redactor::default();
        r.learn_from_command(
            "export SECRET_KEY=django-insecure-(abc)xyz123; (MY_TOKEN=abcdef123)(B_TOKEN=zyxwvu987)",
        );
        assert_eq!(
            r.redact("key django-insecure-(abc)xyz123 end"),
            "key [REDACTED] end"
        );
        assert_eq!(r.redact("abcdef123 zyxwvu987 )"), "[REDACTED] [REDACTED] )");
    }

    #[test]
    fn authorization_and_authentication_names_are_learned() {
        for cmd in [
            "export AUTHORIZATION=opaquevalue123",
            "HTTP_AUTHORIZATION=opaquevalue123",
            "export AUTHENTICATION_TOKEN=opaquevalue123",
            "export X_AUTHENTICATE=opaquevalue123",
        ] {
            let mut r = Redactor::default();
            r.learn_from_command(cmd);
            assert_eq!(r.redact("v opaquevalue123"), "v [REDACTED]", "{cmd}");
        }
        for cmd in [
            "export GIT_AUTHOR_NAME=opaquevalue123",
            "export AUTHORITY_URL=opaquevalue123",
            "export GIT_AUTHOR_EMAIL=opaquevalue123",
        ] {
            let mut r = Redactor::default();
            r.learn_from_command(cmd);
            assert_eq!(r.redact("v opaquevalue123"), "v opaquevalue123", "{cmd}");
        }
    }
}
