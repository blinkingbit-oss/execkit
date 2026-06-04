"""
nexum PoC — the core technique a real implementation would use.

A persistent shell lives inside a PTY. Each command is framed by an
*unguessable* sentinel that carries the exit code AND the cwd in a single
round-trip. The command's stderr is redirected to a side channel so we can
split stdout/stderr (a PTY merges them by design).

This is intentionally written against raw OS syscalls (os.openpty via
pty.fork, os.read/os.write, select) — the exact primitives that Rust's
`portable-pty` wraps. If this works here, it ports 1:1 to the Rust core.
"""
import os
import pty
import re
import select
import secrets
import tempfile
import termios
import time

# OSC (title) branch MUST come before the generic two-char ESC branch, because
# ']' (0x5D) falls inside the generic [@-Z\-_] range and would otherwise swallow
# only the ESC + ']' and leave the title text behind.
ANSI_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"   # OSC ... BEL / ST
    r"|\x1b\[[0-?]*[ -/]*[@-~]"            # CSI (colors, cursor, clears)
    r"|\x1b[@-Z\\-_]"                       # other two-char ESC sequences
)


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def _clean(s: str) -> str:
    """Normalize PTY output: drop CRs (ONLCR), strip surrounding blank lines."""
    return strip_ansi(s).replace("\r", "").strip("\n")


class PtySession:
    """A persistent shell session with structured, framed command execution."""

    def __init__(self, shell=("bash", "--norc", "--noprofile")):
        self.shell = shell
        # Per-session random token => command output can never forge the sentinel.
        self.token = secrets.token_hex(6)
        ef = tempfile.NamedTemporaryFile(prefix="nexum_err_", delete=False)
        self.errpath = ef.name
        ef.close()

        self.pid, self.fd = pty.fork()
        if self.pid == 0:  # child
            os.execvp(shell[0], list(shell))
            os._exit(127)
        self._tty_raw()
        self._init_shell()

    def _tty_raw(self):
        # Disable echo + NL->CRNL translation at the OS/termios level (what a real
        # portable-pty core does). Shell-agnostic; beats sending `stty` into a
        # shell whose line editor (zsh ZLE) would win the race.
        attrs = termios.tcgetattr(self.fd)
        attrs[1] &= ~termios.ONLCR          # oflag: stop \n -> \r\n
        attrs[3] &= ~(termios.ECHO | termios.ECHONL)  # lflag: no input echo
        termios.tcsetattr(self.fd, termios.TCSANOW, attrs)

    def _init_shell(self):
        # Belt-and-suspenders: quiet prompts and disable zsh's line editor.
        os.write(
            self.fd,
            b"stty -echo 2>/dev/null; PS1=''; PS2=''; PROMPT_COMMAND='' "
            b"2>/dev/null; unsetopt zle 2>/dev/null; setopt no_prompt_cr "
            b"2>/dev/null; true\n",
        )
        time.sleep(0.25)
        self._drain()

    def _drain(self):
        while True:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if not r:
                return
            try:
                if not os.read(self.fd, 65536):
                    return
            except OSError:
                return

    def _read_until(self, pattern, timeout):
        buf = b""
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return buf, None
            r, _, _ = select.select([self.fd], [], [], remaining)
            if not r:
                return buf, None
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                return buf, None
            if not chunk:
                return buf, None
            buf += chunk
            m = pattern.search(buf.decode(errors="replace"))
            if m:
                return buf, m

    def exec(self, command: str, timeout: float = 10.0) -> dict:
        """Run a command; return a structured ExecResult-like dict."""
        marker = f"__NEXUM_{self.token}__"
        # \037 == \x1f (unit separator); octal works in bash/zsh/dash printf.
        # stderr of the command group -> side channel; sentinel goes to the PTY
        # *outside* the group so it always arrives even if the user redirects.
        payload = (
            "{ " + command + " ; } 2> " + self.errpath + " ; "
            f"printf '\\n{marker}\\037%d\\037%s\\037\\n' \"$?\" \"$PWD\"\n"
        )
        open(self.errpath, "w").close()  # reset side channel
        os.write(self.fd, payload.encode())

        pat = re.compile(re.escape(marker) + r"\x1f(\d+)\x1f(.*?)\x1f", re.S)
        buf, m = self._read_until(pat, timeout)
        text = buf.decode(errors="replace")

        if not m:
            return {
                "finished": False,
                "still_running": True,
                "stdout_so_far": strip_ansi(text),
            }

        exit_code = int(m.group(1))
        cwd = m.group(2)
        stdout = text.split(marker, 1)[0]
        with open(self.errpath) as f:
            stderr = f.read()

        return {
            "finished": True,
            "command": command,
            "stdout": _clean(stdout),
            "stderr": _clean(stderr),
            "exit_code": exit_code,
            "cwd": cwd,
        }

    def close(self):
        try:
            os.write(self.fd, b"exit\n")
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except OSError:
            pass
        try:
            os.unlink(self.errpath)
        except OSError:
            pass
