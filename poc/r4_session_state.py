"""
R4 — Persistent session state.

Prove that a session is "a place, not a connection": cwd, env vars, and shell
functions survive across separate exec() calls, and cwd is reported in the
structured result.
"""
import sys

from _session import PtySession


def run():
    results = []
    s = PtySession()
    try:
        # cwd persists and is reported structurally
        s.exec("cd /tmp")
        r = s.exec("pwd")
        results.append(("cwd persists across calls",
                        r["stdout"] == "/tmp" and r["cwd"] == "/tmp",
                        f"stdout={r['stdout']!r} cwd={r['cwd']!r}"))

        # env var set in one call is visible in the next
        s.exec("export EXECKIT_FLAG=heaven")
        r = s.exec("echo $EXECKIT_FLAG")
        results.append(("env var persists", r["stdout"] == "heaven", f"stdout={r['stdout']!r}"))

        # shell function defined once, callable later
        s.exec("greet() { echo hi-$1; }")
        r = s.exec("greet execkit")
        results.append(("shell function persists", r["stdout"] == "hi-execkit", f"stdout={r['stdout']!r}"))

        # exit code is per-command and accurate
        r = s.exec("false")
        results.append(("exit code: false==1", r["exit_code"] == 1, f"exit={r['exit_code']}"))
        r = s.exec("(exit 42)")
        results.append(("exit code: custom==42", r["exit_code"] == 42, f"exit={r['exit_code']}"))

        # relative cd accumulates (real statefulness)
        s.exec("mkdir -p /tmp/execkit_poc_dir/sub")
        s.exec("cd /tmp/execkit_poc_dir")
        r = s.exec("cd sub; pwd")
        results.append(("relative cd accumulates",
                        r["stdout"] == "/tmp/execkit_poc_dir/sub",
                        f"stdout={r['stdout']!r}"))
    finally:
        s.close()

    return results


if __name__ == "__main__":
    rs = run()
    ok = all(p for _, p, _ in rs)
    for label, passed, detail in rs:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label:30} {detail}")
    print(f"R4 {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
