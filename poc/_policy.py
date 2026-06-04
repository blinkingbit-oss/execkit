"""
Shared security primitives for the flashy-feature PoCs:
  - a capability/permission engine (capabilities come from CONFIG, never the agent)
  - secret redaction (by env-var name and by value shape)
  - a guarded session wrapper that enforces policy *before* a command runs

These are the gates that make the flashy features safe. The PoCs prove the gates
actually hold.
"""
import os
import re
import shlex

# --- secret redaction -------------------------------------------------------

# env-var NAMES that are secrets regardless of value
SECRET_NAME = re.compile(r"(?i)(secret|token|password|passwd|api[_-]?key|private[_-]?key|access[_-]?key)")

# value SHAPES that look like secrets even in free text / command output
SECRET_VALUE = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                                  # AWS access key id
    re.compile(r"ghp_[A-Za-z0-9]{36}"),                               # GitHub PAT
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),                # PEM key
]


def redact_text(text: str) -> str:
    for p in SECRET_VALUE:
        text = p.sub("[REDACTED]", text)
    return text


def redact_env(env: dict) -> dict:
    out = {}
    for k, v in env.items():
        out[k] = "[REDACTED]" if SECRET_NAME.search(k) else redact_text(v)
    return out


# --- capability / permission engine -----------------------------------------

DANGEROUS = re.compile(
    r"\brm\s+-[a-z]*f|\bdd\b|\bmkfs|\bshutdown\b|\breboot\b|:\(\)\s*\{|"
    r"(curl|wget)[^|]*\|\s*(sh|bash)"
)


def _programs(command: str):
    """Best-effort list of program tokens across a pipeline/sequence."""
    progs = []
    for seg in re.split(r"\|\||&&|[;|&\n]", command):
        seg = seg.strip()
        if not seg:
            continue
        try:
            toks = shlex.split(seg)
        except ValueError:
            toks = seg.split()
        # skip leading VAR=val assignments
        i = 0
        while i < len(toks) and re.match(r"^\w+=", toks[i]):
            i += 1
        if i < len(toks):
            progs.append(os.path.basename(toks[i]))
    return progs


class Policy:
    """Default-deny capability fence. Granted by config only."""

    def __init__(self, allow_cmds=(), deny_cmds=(), allow_paths=()):
        self.allow = set(allow_cmds)
        self.deny = set(deny_cmds)
        self.allow_paths = [os.path.realpath(p) for p in allow_paths]

    def check_command(self, command: str):
        if DANGEROUS.search(command):
            return False, "dangerous pattern blocked"
        for prog in _programs(command):
            if prog in self.deny:
                return False, f"'{prog}' is denylisted"
            if self.allow and prog not in self.allow:
                return False, f"'{prog}' not in allowlist"
        return True, "ok"

    def check_path(self, path: str):
        """realpath() resolves symlinks AND .. before the jail check."""
        rp = os.path.realpath(path)
        for root in self.allow_paths:
            if rp == root or rp.startswith(root + os.sep):
                return True, rp
        return False, rp

    def agent_requests_capability(self, _caps):
        # CRITICAL: an agent asking for more capability changes NOTHING.
        return "ignored — capabilities are config-granted, never agent-claimed"


class GuardedSession:
    """Wraps a session; refuses to execute anything the policy denies."""

    def __init__(self, session, policy: Policy):
        self.s = session
        self.policy = policy
        self.blocked = []

    def exec(self, command: str):
        ok, reason = self.policy.check_command(command)
        if not ok:
            self.blocked.append((command, reason))
            return {"allowed": False, "reason": reason, "executed": False}
        r = self.s.exec(command)
        r["allowed"] = True
        r["executed"] = True
        return r
