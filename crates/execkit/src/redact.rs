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
            Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), // AWS access key id
            Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap(), // GitHub PAT
            Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}").unwrap(), // JWT
            Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap(), // PEM
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
}
