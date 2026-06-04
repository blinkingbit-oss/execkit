"""
R3 — Clean output (ANSI / control-sequence stripping fidelity).

Agents must receive readable text, not escape soup. Test colors, cursor moves,
OSC title sequences, and a real colorized command run through a session.
"""
import sys

from _session import PtySession, strip_ansi

CASES = [
    ("colors", "\x1b[31mred\x1b[0m \x1b[1;32mgreen\x1b[0m", "red green"),
    ("cursor moves", "abc\x1b[2Kdef\x1b[1Aghi", "abcdefghi"),
    ("osc title", "\x1b]0;my title\x07visible", "visible"),
    ("clear+reset", "\x1b[2J\x1b[H\x1b[0mclean", "clean"),
    ("256 color", "\x1b[38;5;208mhi\x1b[0m", "hi"),
]


def run():
    results = []
    for name, raw, expect in CASES:
        got = strip_ansi(raw)
        results.append((f"strip: {name}", got == expect, f"got={got!r} expect={expect!r}"))

    # End-to-end: force color from a real command and confirm it comes out clean.
    s = PtySession()
    try:
        r = s.exec("printf '\\033[31mERR-RED\\033[0m\\n'")
        clean = r["stdout"] == "ERR-RED"
        results.append(("e2e: colorized command", clean, f"stdout={r['stdout']!r}"))
    finally:
        s.close()

    return results


if __name__ == "__main__":
    rs = run()
    ok = all(p for _, p, _ in rs)
    for label, passed, detail in rs:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label:30} {detail}")
    print(f"R3 {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
