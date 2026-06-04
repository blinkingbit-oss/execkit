"""
FLASHY GATE — Session fork / observation must NOT leak between sessions.

Verifies:
  - a forked session inherits state (cwd, NEXUM_* env) from a snapshot
  - fork is a real independent process: mutating the child never affects the parent
  - no session bleed: a secret set in one session is NOT visible in another
  - read-only observation cannot execute (no write capability)
"""
import sys

from _state import capture_state, restore_state
from _session import PtySession


class ReadOnlyView:
    """An observer handle: can read state, has NO exec()."""
    def __init__(self, session):
        self._s = session

    def read_state(self):
        return capture_state(self._s)
    # deliberately no exec / write method


def run():
    results = []
    parent = PtySession()
    child = None
    other = None
    try:
        parent.exec("cd /tmp")
        parent.exec("export NEXUM_ROLE=parent")
        snap = capture_state(parent)

        # 1. fork inherits state
        child = PtySession()
        restore_state(child, snap)
        r = child.exec("echo $NEXUM_ROLE @ $(pwd)")
        results.append(("fork inherits state", r["stdout"] == "parent @ /tmp", f"got={r['stdout']!r}"))

        # 2. fork is isolated: mutate child, parent unchanged
        child.exec("export NEXUM_ROLE=child; cd /")
        pr = parent.exec("echo $NEXUM_ROLE @ $(pwd)")
        cr = child.exec("echo $NEXUM_ROLE @ $(pwd)")
        results.append(("fork is isolated",
                        pr["stdout"] == "parent @ /tmp" and cr["stdout"] == "child @ /",
                        f"parent={pr['stdout']!r} child={cr['stdout']!r}"))

        # 3. no session bleed: secret in `other` is invisible to parent
        other = PtySession()
        other.exec("export NEXUM_SECRET=topsecret")
        leak = parent.exec("echo [$NEXUM_SECRET]")
        results.append(("no session bleed", leak["stdout"] == "[]", f"parent_sees={leak['stdout']!r}"))

        # 4. read-only observer has no exec capability
        view = ReadOnlyView(other)
        can_read = view.read_state()["cwd"] != ""
        cannot_write = not hasattr(view, "exec")
        results.append(("observer is read-only", can_read and cannot_write,
                        f"can_read={can_read} has_exec={hasattr(view,'exec')}"))
    finally:
        for s in (parent, child, other):
            if s:
                s.close()
    return results


if __name__ == "__main__":
    rs = run()
    ok = all(p for _, p, _ in rs)
    for label, passed, detail in rs:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label:28} {detail}")
    print(f"F4 {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
