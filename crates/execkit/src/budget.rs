// SPDX-License-Identifier: Apache-2.0
//! Output budgets: per-stream shaping of command output so huge logs do not
//! blow an agent's context window. Pure logic - the pipeline (grep -> line-keep
//! -> char-cap) operates on already ANSI-stripped, secret-redacted text and is
//! applied independently to stdout and stderr by `Session`.

use crate::error::{Error, Result};
use crate::output::bound;
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

/// Reduce a sorted index list to the head/tail window requested by `keep`.
fn keep_subset(idx: &[usize], keep: Keep) -> Vec<usize> {
    let n = idx.len();
    match keep {
        Keep::All => idx.to_vec(),
        Keep::Tail(k) => idx[n.saturating_sub(k)..].to_vec(),
        Keep::Head(k) => idx[..k.min(n)].to_vec(),
        Keep::HeadTail(h, t) => {
            if h + t >= n {
                idx.to_vec()
            } else {
                let mut v = idx[..h].to_vec();
                v.extend_from_slice(&idx[n - t..]);
                v
            }
        }
    }
}

/// Render the kept lines with `... N lines elided ...` markers for every gap
/// (leading, internal, trailing) relative to the original `total` lines.
fn render(content: &[&str], kept: &[usize], total: usize) -> String {
    if kept.is_empty() {
        return if total == 0 {
            String::new()
        } else {
            format!("... {total} lines elided ...")
        };
    }
    let mut out: Vec<String> = Vec::new();
    let marker = |n: usize| format!("... {n} lines elided ...");
    if kept[0] > 0 {
        out.push(marker(kept[0]));
    }
    for (pos, &i) in kept.iter().enumerate() {
        if pos > 0 {
            let prev = kept[pos - 1];
            if i > prev + 1 {
                out.push(marker(i - prev - 1));
            }
        }
        out.push(content[i].to_string());
    }
    let last = *kept.last().unwrap();
    if last < total - 1 {
        out.push(marker(total - 1 - last));
    }
    out.join("\n")
}

#[cfg(test)]
mod keep_tests {
    use super::*;

    #[test]
    fn tail_head_headtail_windows() {
        let idx: Vec<usize> = (0..10).collect();
        assert_eq!(keep_subset(&idx, Keep::Tail(3)), vec![7, 8, 9]);
        assert_eq!(keep_subset(&idx, Keep::Head(2)), vec![0, 1]);
        assert_eq!(keep_subset(&idx, Keep::HeadTail(2, 2)), vec![0, 1, 8, 9]);
        assert_eq!(keep_subset(&idx, Keep::All), idx);
    }

    #[test]
    fn keep_windows_clamp() {
        let idx: Vec<usize> = (0..3).collect();
        assert_eq!(keep_subset(&idx, Keep::Tail(99)), idx); // n>len -> all
        assert_eq!(keep_subset(&idx, Keep::Head(99)), idx);
        assert_eq!(keep_subset(&idx, Keep::HeadTail(2, 2)), idx); // h+t>=n -> all
        assert!(keep_subset(&idx, Keep::Tail(0)).is_empty());
    }

    #[test]
    fn render_marks_leading_internal_trailing_gaps() {
        let content: Vec<&str> = "l0\nl1\nl2\nl3\nl4".lines().collect();
        // keep indices 1 and 3 of 5 total
        let r = render(&content, &[1, 3], 5);
        assert_eq!(
            r,
            "... 1 lines elided ...\nl1\n... 1 lines elided ...\nl3\n... 1 lines elided ..."
        );
    }

    #[test]
    fn render_empty_kept() {
        let content: Vec<&str> = "a\nb".lines().collect();
        assert_eq!(render(&content, &[], 2), "... 2 lines elided ...");
        assert_eq!(render(&[], &[], 0), "");
    }
}

/// What a budget did to one stream. Present on `ExecResult` only when a
/// non-default budget was applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamReport {
    /// Short label of the pipeline that ran: "all","tail","head","head_tail",
    /// "grep", or composed like "grep+tail".
    pub mode: String,
    pub lines_total: usize,
    pub lines_kept: usize,
}

/// Per-stream reports for a shaped `ExecResult`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetReport {
    pub stdout: StreamReport,
    pub stderr: StreamReport,
}

fn keep_label(keep: Keep) -> Option<&'static str> {
    match keep {
        Keep::All => None,
        Keep::Tail(_) => Some("tail"),
        Keep::Head(_) => Some("head"),
        Keep::HeadTail(_, _) => Some("head_tail"),
    }
}

/// Shape one already-redacted stream. Returns (text, report, char_capped).
pub(crate) fn apply(
    text: &str,
    budget: &Budget,
    fallback_max_chars: usize,
) -> Result<(String, StreamReport, bool)> {
    let content: Vec<&str> = text.lines().collect();
    let total = content.len();

    let mut idx: Vec<usize> = (0..total).collect();
    let mut parts: Vec<&str> = Vec::new();
    if let Some(g) = &budget.grep {
        let re = regex::Regex::new(&g.pattern)
            .map_err(|e| Error::Budget(format!("invalid grep pattern: {e}")))?;
        idx = grep_keep_indices(&content, &re, g.context);
        parts.push("grep");
    }
    idx = keep_subset(&idx, budget.keep);
    if let Some(l) = keep_label(budget.keep) {
        parts.push(l);
    }
    let lines_kept = idx.len();
    let rendered = render(&content, &idx, total);

    let cap = budget.max_chars.unwrap_or(fallback_max_chars);
    let (capped_text, capped) = bound(&rendered, cap);

    let mode = if parts.is_empty() {
        "all".to_string()
    } else {
        parts.join("+")
    };
    Ok((
        capped_text,
        StreamReport {
            mode,
            lines_total: total,
            lines_kept,
        },
        capped,
    ))
}

#[cfg(test)]
mod apply_tests {
    use super::*;

    #[test]
    fn default_budget_is_passthrough_until_cap() {
        let (t, r, capped) = apply("a\nb\nc", &Budget::default(), 1000).unwrap();
        assert_eq!(t, "a\nb\nc");
        assert_eq!(r.mode, "all");
        assert_eq!((r.lines_total, r.lines_kept), (3, 3));
        assert!(!capped);
    }

    #[test]
    fn tail_keeps_last_n_with_report() {
        let text = (0..100)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let (t, r, _) = apply(&text, &Budget::tail(3), 100_000).unwrap();
        assert!(t.starts_with("... 97 lines elided ..."));
        assert!(t.ends_with("97\n98\n99"));
        assert_eq!(
            (r.lines_total, r.lines_kept, r.mode.as_str()),
            (100, 3, "tail")
        );
    }

    #[test]
    fn grep_then_tail_composes() {
        let mut lines: Vec<String> = (0..50).map(|i| format!("info {i}")).collect();
        lines[10] = "ERROR ten".into();
        lines[40] = "ERROR forty".into();
        let text = lines.join("\n");
        let b = Budget::grep("ERROR").keep(Keep::Tail(1));
        let (t, r, _) = apply(&text, &b, 100_000).unwrap();
        assert!(t.contains("ERROR forty"));
        assert!(!t.contains("ERROR ten")); // tail(1) of the 2 matches
        assert_eq!((r.lines_kept, r.mode.as_str()), (1, "grep+tail"));
    }

    #[test]
    fn invalid_regex_errors() {
        let err = apply("x", &Budget::grep("("), 100).unwrap_err();
        assert!(matches!(err, Error::Budget(_)));
    }

    #[test]
    fn char_cap_flags_capped() {
        let text = "x".repeat(1000);
        let (_t, _r, capped) = apply(&text, &Budget::default(), 10).unwrap();
        assert!(capped);
    }
}
