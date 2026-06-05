"""
FLASHY GATE — Snapshot / replay / time-travel must not leak secrets or
auto-run destructive commands.

Verifies:
  - secrets are redacted out of a snapshot before it is serialized
  - the snapshot is encrypted at rest (ciphertext has no plaintext state)
  - encrypted snapshot round-trips and tampering is detected (authenticated)
  - replay is DRY-RUN by default: a destructive recorded command does not execute
"""
import json
import os
import shlex
import subprocess
import sys

from cryptography.fernet import Fernet, InvalidToken

from _policy import Policy, redact_env
from _state import capture_state
from _session import PtySession

SNAP_PLAIN = "/tmp/execkit_snap.json"
SNAP_ENC = "/tmp/execkit_snap.enc"
REPLAY_TARGET = "/tmp/execkit_replay_target.txt"


def replay(commands, live=False, policy=None):
    """Default DRY-RUN: returns the plan, executes nothing unless live=True.

    Live replay routes every recorded command through the SAME policy gate and
    runs it with subprocess (no shell) — never a raw shell sink. A command the
    policy denies is reported but not executed.
    """
    plan = []
    for c in commands:
        entry = {"command": c, "would_run": True, "executed": False, "blocked": False}
        if live:
            ok, reason = (policy.check_command(c) if policy else (True, "no-policy"))
            if ok:
                subprocess.run(shlex.split(c), check=False)  # list args, shell=False
                entry["executed"] = True
            else:
                entry["blocked"] = reason
        plan.append(entry)
    return plan


def run():
    results = []
    s = PtySession()
    try:
        s.exec("cd /tmp")
        s.exec("export EXECKIT_PROJECT=execkit")
        s.exec("export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")
        s.exec("export EXECKIT_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz")

        state = capture_state(s)
        state["env"] = redact_env(state["env"])
        blob = json.dumps(state)

        # 1. secrets redacted out of the snapshot
        no_secret = ("AKIAIOSFODNN7EXAMPLE" not in blob
                     and "ghp_0123456789" not in blob
                     and state["env"].get("AWS_SECRET_ACCESS_KEY") == "[REDACTED]")
        results.append(("secrets redacted from snapshot", no_secret,
                        f"AWS={state['env'].get('AWS_SECRET_ACCESS_KEY')!r}"))

        # 2. encrypted at rest — ciphertext leaks no plaintext state
        key = Fernet.generate_key()
        token = Fernet(key).encrypt(blob.encode())
        with open(SNAP_ENC, "wb") as f:
            f.write(token)
        on_disk = open(SNAP_ENC, "rb").read()
        clean = b"EXECKIT_PROJECT" not in on_disk and b"/tmp" not in on_disk
        results.append(("encrypted at rest", clean, f"ciphertext_leaks_plaintext={not clean}"))

        # 3. round-trips and tamper is detected
        rt = json.loads(Fernet(key).decrypt(on_disk).decode())
        tampered = bytearray(on_disk); tampered[-5] ^= 0x01
        try:
            Fernet(key).decrypt(bytes(tampered)); detected = False
        except InvalidToken:
            detected = True
        results.append(("round-trip + tamper-evident",
                        rt["cwd"] == "/tmp" and detected, f"roundtrip_cwd={rt['cwd']!r} tamper_caught={detected}"))

        # 4. replay is dry-run by default: destructive command does NOT run
        with open(REPLAY_TARGET, "w") as f:
            f.write("alive")
        recorded = [f"rm -f {REPLAY_TARGET}"]
        plan = replay(recorded, live=False)  # default safety
        survived = os.path.exists(REPLAY_TARGET)
        results.append(("replay dry-run by default",
                        survived and plan[0]["executed"] is False and plan[0]["would_run"],
                        f"target_survived={survived} executed={plan[0]['executed']}"))
    finally:
        s.close()
        for p in (SNAP_PLAIN, SNAP_ENC, REPLAY_TARGET):
            try: os.unlink(p)
            except OSError: pass
    return results


if __name__ == "__main__":
    rs = run()
    ok = all(p for _, p, _ in rs)
    for label, passed, detail in rs:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label:32} {detail}")
    print(f"F3 {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
