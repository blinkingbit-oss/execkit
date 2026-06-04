"""
R5 — Interactive process control.

Prove we can drive a live, stateful interactive program (a Python REPL):
write to its stdin, read its typed reaction, and have in-process state persist.
This is the basis for the "talk to REPLs / vim / sudo prompts" dream feature.
"""
import os
import pty
import re
import select
import sys
import time


class InteractiveProc:
    def __init__(self, argv):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvp(argv[0], argv)
            os._exit(127)
        time.sleep(0.4)
        self._drain()

    def _drain(self):
        while True:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if not r:
                return
            try:
                if not os.read(self.fd, 65536):
                    return
            except OSError:
                return

    def send_expect(self, data, pattern, timeout=4.0):
        os.write(self.fd, data.encode())
        buf = b""
        deadline = time.time() + timeout
        rx = re.compile(pattern)
        while time.time() < deadline:
            r, _, _ = select.select([self.fd], [], [], deadline - time.time())
            if not r:
                break
            try:
                c = os.read(self.fd, 65536)
            except OSError:
                break
            if not c:
                break
            buf += c
            if rx.search(buf.decode(errors="replace")):
                return True, buf.decode(errors="replace")
        return False, buf.decode(errors="replace")

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except OSError:
            pass


def run():
    results = []
    p = InteractiveProc(["python3", "-i", "-q"])
    try:
        ok, out = p.send_expect("2+2\n", r"\b4\b")
        results.append(("REPL evaluates expression", ok, f"saw 4 = {ok}"))

        ok, out = p.send_expect('name = "nexum"\n', r">>>|\n")
        # state persists: use the variable defined in the previous write
        ok2, out2 = p.send_expect("print(name.upper())\n", r"NEXUM")
        results.append(("REPL state persists across writes", ok2, f"saw NEXUM = {ok2}"))

        ok3, out3 = p.send_expect("import math; print(math.factorial(5))\n", r"\b120\b")
        results.append(("REPL multi-step interaction", ok3, f"saw 120 = {ok3}"))
    finally:
        p.close()

    return results


if __name__ == "__main__":
    rs = run()
    ok = all(p for _, p, _ in rs)
    for label, passed, detail in rs:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label:36} {detail}")
    print(f"R5 {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
