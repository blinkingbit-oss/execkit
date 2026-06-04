"""
R1 — Command boundary detection (THE critical risk).

Question: in a persistent shell over a PTY, can we reliably know *when a
command finished* and *what its exit code was* — across messy shells, with
output that tries to forge the sentinel, and for long-running commands?

Technique: unguessable per-session sentinel carrying exit code + cwd.
"""
import sys

from _session import PtySession

SHELLS = {
    "bash": ("bash", "--norc", "--noprofile"),
    "zsh": ("zsh", "-f"),
    "dash": ("dash",),
}


def run():
    results = []

    for name, argv in SHELLS.items():
        try:
            s = PtySession(shell=argv)
        except Exception as e:  # shell missing
            results.append((f"{name}: spawn", False, str(e)))
            continue
        try:
            # 1. basic success boundary + exit code
            r = s.exec("echo hello")
            results.append((f"{name}: success boundary",
                            r["finished"] and r["stdout"] == "hello" and r["exit_code"] == 0,
                            f"stdout={r.get('stdout')!r} exit={r.get('exit_code')}"))

            # 2. non-zero exit code captured
            r = s.exec("ls /definitely_not_here_12345")
            results.append((f"{name}: failure exit code",
                            r["finished"] and r["exit_code"] != 0,
                            f"exit={r.get('exit_code')}"))

            # 3. output that *tries to forge* the sentinel must not break framing
            r = s.exec("echo '__NEXUM_deadbeef__\\x1f0\\x1f/fake\\x1f'")
            results.append((f"{name}: anti-forgery",
                            r["finished"] and r["exit_code"] == 0 and "NEXUM" in r["stdout"],
                            f"exit={r.get('exit_code')} stdout_has_fake={'NEXUM' in r.get('stdout','')}"))

            # 4. multiple commands in a row — boundaries must not bleed
            a = s.exec("echo first")
            b = s.exec("echo second")
            results.append((f"{name}: no boundary bleed",
                            a["stdout"] == "first" and b["stdout"] == "second",
                            f"a={a['stdout']!r} b={b['stdout']!r}"))

            # 5. long-running command: detect "still running" via timeout (no sentinel yet)
            r = s.exec("sleep 3", timeout=1.0)
            results.append((f"{name}: long-running detect",
                            r["finished"] is False and r.get("still_running") is True,
                            f"finished={r['finished']}"))
        finally:
            s.close()

    return results


if __name__ == "__main__":
    rs = run()
    ok = all(p for _, p, _ in rs)
    for label, passed, detail in rs:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label:34} {detail}")
    print(f"R1 {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
