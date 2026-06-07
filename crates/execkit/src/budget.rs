// SPDX-License-Identifier: Apache-2.0
//! Output budgets: per-stream shaping of command output so huge logs do not
//! blow an agent's context window. Pure logic - the pipeline (grep -> line-keep
//! -> char-cap) operates on already ANSI-stripped, secret-redacted text and is
//! applied independently to stdout and stderr by `Session`.

use serde::{Deserialize, Serialize};

/// A per-stream output-shaping pipeline. `Budget::default()` is a no-op.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// 1. Keep only lines matching this regex (plus context). None = keep all.
    pub grep: Option<Grep>,
    /// 2. Bound the survivors to a line window.
    pub keep: Keep,
    /// 3. Final char backstop for THIS call. None falls back to the session cap.
    pub max_chars: Option<usize>,
}

/// A regex line filter with symmetric context (like `grep -C`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grep {
    pub pattern: String,
    /// Lines of context kept on EACH side of a match. 0 = match only.
    pub context: usize,
}

/// How to bound the lines that survive the grep filter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Keep {
    #[default]
    All,
    Tail(usize),
    Head(usize),
    HeadTail(usize, usize),
}

impl Budget {
    pub fn tail(n: usize) -> Self {
        Budget {
            keep: Keep::Tail(n),
            ..Default::default()
        }
    }
    pub fn head(n: usize) -> Self {
        Budget {
            keep: Keep::Head(n),
            ..Default::default()
        }
    }
    pub fn head_tail(head: usize, tail: usize) -> Self {
        Budget {
            keep: Keep::HeadTail(head, tail),
            ..Default::default()
        }
    }
    /// Grep filter (context 0, keep all matches). Chain `.context`/`.keep`/`.max_chars`.
    pub fn grep(pattern: impl Into<String>) -> Self {
        Budget {
            grep: Some(Grep {
                pattern: pattern.into(),
                context: 0,
            }),
            ..Default::default()
        }
    }
    /// Set grep context lines (no-op if there is no grep filter).
    pub fn context(mut self, n: usize) -> Self {
        if let Some(g) = self.grep.as_mut() {
            g.context = n;
        }
        self
    }
    pub fn keep(mut self, keep: Keep) -> Self {
        self.keep = keep;
        self
    }
    pub fn max_chars(mut self, n: usize) -> Self {
        self.max_chars = Some(n);
        self
    }
}

#[cfg(test)]
mod builder_tests {
    use super::*;

    #[test]
    fn constructors_build_expected_budgets() {
        assert_eq!(Budget::tail(10).keep, Keep::Tail(10));
        assert_eq!(Budget::head(5).keep, Keep::Head(5));
        assert_eq!(Budget::head_tail(2, 3).keep, Keep::HeadTail(2, 3));
        assert_eq!(Budget::default(), Budget::default());
        assert!(Budget::default().grep.is_none());
    }

    #[test]
    fn grep_builder_chains() {
        let b = Budget::grep("err")
            .context(2)
            .keep(Keep::Tail(50))
            .max_chars(100);
        assert_eq!(b.grep.as_ref().unwrap().pattern, "err");
        assert_eq!(b.grep.as_ref().unwrap().context, 2);
        assert_eq!(b.keep, Keep::Tail(50));
        assert_eq!(b.max_chars, Some(100));
    }

    #[test]
    fn context_without_grep_is_noop() {
        let b = Budget::tail(5).context(3);
        assert!(b.grep.is_none());
    }
}

/// Indices of `content` to keep: every line matching `re`, plus `context` lines
/// on each side, merged and sorted. Empty input -> empty.
fn grep_keep_indices(content: &[&str], re: &regex::Regex, context: usize) -> Vec<usize> {
    let mut keep = vec![false; content.len()];
    for (i, line) in content.iter().enumerate() {
        if re.is_match(line) {
            let lo = i.saturating_sub(context);
            let hi = (i + context).min(content.len().saturating_sub(1));
            for k in keep.iter_mut().take(hi + 1).skip(lo) {
                *k = true;
            }
        }
    }
    (0..content.len()).filter(|&i| keep[i]).collect()
}

#[cfg(test)]
mod grep_tests {
    use super::*;

    fn idx(text: &str, pat: &str, ctx: usize) -> Vec<usize> {
        let content: Vec<&str> = text.lines().collect();
        grep_keep_indices(&content, &regex::Regex::new(pat).unwrap(), ctx)
    }

    #[test]
    fn match_only_no_context() {
        assert_eq!(idx("a\nERR\nb\nERR\nc", "ERR", 0), vec![1, 3]);
    }

    #[test]
    fn context_expands_and_merges_overlaps() {
        // matches at 1 and 3, context 1 -> {0,1,2} and {2,3,4} merge to 0..=4
        assert_eq!(idx("a\nERR\nb\nERR\nc", "ERR", 1), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn context_clamps_at_edges() {
        assert_eq!(idx("ERR\nb\nc", "ERR", 5), vec![0, 1, 2]);
    }

    #[test]
    fn no_match_is_empty() {
        assert!(idx("a\nb\nc", "ZZZ", 2).is_empty());
    }
}
