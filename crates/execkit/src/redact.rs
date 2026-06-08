// SPDX-License-Identifier: Apache-2.0
//! Secret redaction - keep credentials out of the model and the logs.
//!
//! v0.1 matches by value shape. A real deployment should also redact by env-var
//! name and allow custom patterns.

use regex::Regex;
use std::sync::OnceLock;

fn patterns() -> &'static [Regex] {
    static P: OnceLock<Vec<Regex>> = OnceLock::new();
    P.get_or_init(|| {
        vec![
            // Fixed-width patterns use {N,} (greedy/open-ended) so a longer token
            // does not leak its tail after the matched prefix+N chars.
            Regex::new(r"AKIA[0-9A-Z]{16,}").unwrap(), // AWS access key id
            Regex::new(r"ghp_[A-Za-z0-9]{36,}").unwrap(), // GitHub PAT (classic)
            Regex::new(r"github_pat_[A-Za-z0-9_]{20,}").unwrap(), // GitHub fine-grained PAT
            Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}").unwrap(), // JWT
            Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap(), // PEM
            Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap(),       // Slack token
            Regex::new(r"sk_live_[A-Za-z0-9]{16,}").unwrap(),           // Stripe live secret key
            Regex::new(r"AIza[A-Za-z0-9_-]{35}").unwrap(),              // Google API key
        ]
    })
}

/// Replace known secret shapes with `[REDACTED]`.
pub fn redact(text: &str) -> String {
    let mut out = text.to_string();
    for re in patterns() {
        out = re.replace_all(&out, "[REDACTED]").into_owned();
    }
    out
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
}
