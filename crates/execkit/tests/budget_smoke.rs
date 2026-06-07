// SPDX-License-Identifier: Apache-2.0
//! Local-PTY integration for output budgets (no network/containers).
use execkit::{Budget, Session};

fn many_lines(n: usize) -> String {
    format!("for i in $(seq 1 {n}); do echo line$i; done")
}

#[test]
fn exec_budgeted_tail_keeps_last_n_and_reports() {
    let mut s = Session::local().unwrap();
    let r = s
        .exec_budgeted(&many_lines(500), &Budget::tail(10))
        .unwrap();
    assert!(r.stdout.ends_with("line500"));
    assert!(r.stdout.contains("lines elided"));
    let rep = r.budget.expect("budget report present");
    assert_eq!(rep.stdout.lines_total, 500);
    assert_eq!(rep.stdout.lines_kept, 10);
    assert!(r.truncated);
}

#[test]
fn plain_exec_has_no_budget_report() {
    let mut s = Session::local().unwrap();
    let r = s.exec("echo hi").unwrap();
    assert_eq!(r.stdout, "hi");
    assert!(r.budget.is_none());
}

#[test]
fn session_default_budget_applies_and_grep_filters() {
    let mut s = Session::local()
        .unwrap()
        .with_output_budget(Budget::grep("line3$"));
    let r = s.exec(&many_lines(40)).unwrap();
    // only "line3" matches `line3$` among line1..line40
    assert!(r.stdout.contains("line3"));
    assert!(!r.stdout.contains("line30"));
    let rep = r.budget.expect("default budget produces a report");
    assert_eq!(rep.stdout.mode, "grep");
}

#[test]
fn invalid_regex_fails_before_running() {
    let mut s = Session::local().unwrap();
    let err = s.exec_budgeted("echo hi", &Budget::grep("(")).unwrap_err();
    assert!(matches!(err, execkit::Error::Budget(_)));
}
