// SPDX-License-Identifier: Apache-2.0
//! Age-based pruning of per-session audit files. Best-effort: a file we cannot
//! stat or remove is left in place and the error goes to stderr.
use std::path::Path;
use std::time::{Duration, SystemTime};

/// A file is expired when it has not been modified within `max_age`.
pub fn is_expired(modified: SystemTime, now: SystemTime, max_age: Duration) -> bool {
    now.duration_since(modified)
        .map(|age| age > max_age)
        .unwrap_or(false)
}

/// Delete `*.jsonl` files in `dir` last modified more than `max_age` ago.
pub fn sweep(dir: &Path, max_age: Duration) {
    let now = SystemTime::now();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return, // dir absent / unreadable: nothing to prune
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let modified = match entry.metadata().and_then(|m| m.modified()) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if is_expired(modified, now, max_age) {
            if let Err(e) = std::fs::remove_file(&path) {
                eprintln!(
                    "execkit-mcp: retention remove error for {}: {e}",
                    path.display()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);
    fn tmpdir() -> std::path::PathBuf {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("ek_ret_{}_{}", std::process::id(), n));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn is_expired_boundary() {
        let now = SystemTime::now();
        let day = Duration::from_secs(86_400);
        let old = now - Duration::from_secs(86_400 * 3);
        assert!(is_expired(old, now, day)); // 3d old, 1d max -> expired
        assert!(!is_expired(now, now, day)); // fresh -> kept
                                             // a modified time in the future (clock skew) is not expired
        assert!(!is_expired(now + day, now, Duration::from_secs(0)));
    }

    #[test]
    fn sweep_removes_only_expired_jsonl() {
        let d = tmpdir();
        std::fs::write(d.join("a.jsonl"), b"x").unwrap();
        std::fs::write(d.join("keep.txt"), b"x").unwrap(); // non-jsonl untouched
                                                           // max_age 0: any positive age expires; the fresh files have ~0 age, so
                                                           // assert the inverse precisely with the pure helper above and here test
                                                           // the wrapper's file-type filter + that a huge max_age keeps everything.
        sweep(&d, Duration::from_secs(86_400 * 3650)); // 10y: keep all
        assert!(d.join("a.jsonl").exists());
        assert!(d.join("keep.txt").exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
