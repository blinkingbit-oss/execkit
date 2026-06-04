"""
R2 — stdout/stderr separation (the second hard risk).

A PTY merges stdout and stderr onto one stream by design. First we *demonstrate
the problem* (naive merged read), then we prove our side-channel redirect splits
them cleanly while keeping the sentinel framing intact.
"""
import os
import pty
import select
import sys
import time

from _session import PtySession, strip_ansi


def _naive_merged_demo():
    """Show that a raw PTY shell merges stdout+stderr (the problem we solve)."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("bash", ["bash", "--norc", "--noprofile", "-c",
                            "echo OUT; echo ERR 1>&2"])
        os._exit(127)
    buf = b""
    deadline = time.time() + 2
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.2)
        if not r:
            continue
        try:
            c = os.read(fd, 4096)
        except OSError:
            break
        if not c:
            break
        buf += c
    os.close(fd)
    merged = strip_ansi(buf.decode(errors="replace"))
    # Both appear in ONE stream with no way to tell them apart.
    both_present = "OUT" in merged and "ERR" in merged
    return both_present, merged.replace("\n", "\\n")


def run():
    results = []

    merged_ok, merged_text = _naive_merged_demo()
    results.append(("naive PTY merges streams (problem)", merged_ok,
                    f"single stream={merged_text!r}"))

    s = PtySession()
    try:
        # The fix: stderr -> side channel, stdout stays on PTY.
        r = s.exec("echo OUT; echo ERR 1>&2")
        clean_split = r["stdout"] == "OUT" and r["stderr"] == "ERR"
        results.append(("side-channel splits cleanly", clean_split,
                        f"stdout={r['stdout']!r} stderr={r['stderr']!r}"))

        # stderr-only command: stdout must be empty, stderr captured
        r = s.exec("echo 'only on stderr' 1>&2")
        results.append(("stderr-only", r["stdout"] == "" and "only on stderr" in r["stderr"],
                        f"stdout={r['stdout']!r} stderr={r['stderr']!r}"))

        # interleaved writes still separate correctly + exit code intact
        r = s.exec("echo a; echo x 1>&2; echo b; echo y 1>&2; false")
        ok = (r["stdout"].split() == ["a", "b"]
              and r["stderr"].split() == ["x", "y"]
              and r["exit_code"] == 1)
        results.append(("interleaved + exit code", ok,
                        f"out={r['stdout'].split()} err={r['stderr'].split()} exit={r['exit_code']}"))
    finally:
        s.close()

    return results


if __name__ == "__main__":
    rs = run()
    ok = all(p for _, p, _ in rs)
    for label, passed, detail in rs:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label:34} {detail}")
    print(f"R2 {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
