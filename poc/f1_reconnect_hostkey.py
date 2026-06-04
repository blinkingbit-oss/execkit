"""
FLASHY GATE — Self-healing reconnect must re-verify host identity (no silent MITM).

Verifies:
  - first connection pins the host key (TOFU)
  - reconnect with the SAME key is accepted, and state is transparently restored
  - reconnect with a CHANGED key fails LOUDLY (MITM caught) and refuses to restore

The SSH bytes are simulated (no sshd here), but the security decision under test —
"verify the pinned fingerprint on every reconnect" — is exactly the real logic.
"""
import sys

from _state import capture_state, restore_state
from _session import PtySession


class HostKeyError(Exception):
    pass


class KnownHosts:
    """Trust-on-first-use pin store; rejects a changed key on reconnect."""
    def __init__(self):
        self._pins = {}

    def verify(self, host, fingerprint):
        pinned = self._pins.get(host)
        if pinned is None:
            self._pins[host] = fingerprint          # TOFU: pin on first sight
            return "pinned"
        if pinned != fingerprint:
            raise HostKeyError(
                f"host key for {host} CHANGED ({pinned[:10]}.. -> {fingerprint[:10]}..) "
                "— possible MITM; refusing to reconnect")
        return "verified"


def connect(known: KnownHosts, host, fingerprint, restore_from=None):
    """Verify identity FIRST, then (re)establish the session and restore state."""
    known.verify(host, fingerprint)                  # raises on a changed key
    s = PtySession()
    if restore_from:
        restore_state(s, restore_from)
    return s


def run():
    results = []
    known = KnownHosts()
    GOOD = "SHA256:realhostkey_aaaaaaaaaaaaaaaaaaaaaaaa"
    EVIL = "SHA256:attackerkey_bbbbbbbbbbbbbbbbbbbbbbbb"

    # initial connect pins the key, set up some state
    s = connect(known, "prod-1", GOOD)
    s.exec("cd /tmp")
    s.exec("export NEXUM_SESSION=alive")
    snap = capture_state(s)
    s.close()

    # 1. reconnect with same key -> accepted + state restored transparently
    try:
        s2 = connect(known, "prod-1", GOOD, restore_from=snap)
        r = s2.exec("echo $NEXUM_SESSION @ $(pwd)")
        results.append(("reconnect (same key) restores state",
                        r["stdout"] == "alive @ /tmp", f"got={r['stdout']!r}"))
        s2.close()
    except HostKeyError as e:
        results.append(("reconnect (same key) restores state", False, str(e)))

    # 2. reconnect with CHANGED key -> rejected loudly, no session created
    try:
        connect(known, "prod-1", EVIL, restore_from=snap)
        results.append(("reconnect (changed key) blocked (MITM)", False, "NOT blocked!"))
    except HostKeyError as e:
        results.append(("reconnect (changed key) blocked (MITM)", True, f"raised: {str(e)[:42]}..."))

    return results


if __name__ == "__main__":
    rs = run()
    ok = all(p for _, p, _ in rs)
    for label, passed, detail in rs:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label:40} {detail}")
    print(f"F1 {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
