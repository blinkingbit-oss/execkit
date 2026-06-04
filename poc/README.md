# nexum — Feasibility PoC

**Goal:** before writing a line of the real library, prove the *scary* techniques
actually work. Not production code — throwaway spikes to de-risk the idea.

## Verdict: FEASIBLE ✅ (33/33 checks pass)

```
R1  PASS   Command boundary detection      (bash, zsh, dash)
R2  PASS   stdout/stderr split
R3  PASS   Clean output (ANSI strip)
R4  PASS   Persistent session state
R5  PASS   Interactive process control
R6  PASS   Multi-transport (Docker)
```

Run it: `python3 run_all.py` (each `rN_*.py` is also standalone).

## The real core is Rust — and the critical risks are now proven in Rust

`rust/` contains a `portable-pty` PoC (the actual target stack) that reproduces
the two make-or-break risks. **`cd rust && cargo run` → 12/12 pass** (bash + dash):

```
R1 success boundary, R1 failure exit code, R1 anti-forgery, R1 long-running detect,
R2 stdout/stderr split, state cwd persists   — for both bash and dash
```

The Python suite below proved the *technique* fast at the syscall level; the Rust
PoC proves it survives in `portable-pty` specifically. Porting surfaced two real
findings the Python spike had masked:

1. **bash runs interactive under portable-pty** (tty + no script arg) and emits
   bracketed-paste codes (`\e[?2004h/l`). Python's `strip_ansi` silently ate
   them; Rust needed an explicit ANSI stripper. → the core must ALWAYS strip
   ANSI, never assume clean bytes.
2. **A still-running command pollutes a shared session** — after a timeout, the
   pending command's late sentinel corrupts the next read. → after a
   "still-running" timeout the library must interrupt (Ctrl-C/SIGINT) and resync
   before reusing the session. Designed-in now rather than discovered in prod.

(Earlier note: the crates.io "403" was a false alarm — that's crates.io's HTML
endpoint refusing bots. `cargo` uses `index.crates.io` / `static.crates.io`,
which work fine here; `cargo run` fetches and builds normally.)

## The core technique (this is what the real library does)

A persistent shell lives in a PTY. Each command is wrapped so a single
round-trip yields a structured result:

```
{ <command> ; } 2> <side-channel> ; printf '\n<MARKER>\037%d\037%s\037\n' "$?" "$PWD"
```

- **MARKER** = `__NEXUM_<random-per-session-token>__` → command output can never
  forge the boundary (proven by the anti-forgery test).
- **`\037` (unit separator)** frames exit code + cwd unambiguously.
- **stderr → side channel**, stdout stays on the PTY → the two streams split
  cleanly even though a raw PTY merges them.
- **No sentinel within timeout ⇒ "still running"** → long-running/interactive
  processes are detected, not hung on.

## What each risk proved

| Risk | Proved | Notes |
|---|---|---|
| **R1** Boundary detection | Knowing *when* a command ends + its exit code, on bash/zsh/dash, resistant to output forging fake markers, with long-running detection | The make-or-break risk — solid |
| **R2** stdout/stderr split | A raw PTY merges them (demonstrated), the side-channel redirect splits them cleanly with exit code intact | |
| **R3** Clean output | ANSI colors, cursor moves, OSC titles, 256-color all stripped to readable text | OSC branch ordering matters |
| **R4** Session state | `cd`, env vars, shell functions persist across calls; cwd reported structurally; accurate per-command exit codes | "a place, not a connection" |
| **R5** Interactive control | Drive a live Python REPL — write stdin, read typed reaction, state persists | basis for REPL/vim/sudo dream |
| **R6** Multi-transport | Same `ExecResult` shape over `docker exec`; non-TTY docker pipes split stdout/stderr **natively** (no merge problem) | transport abstraction holds |

## Hard-won gotchas (these will bite the Rust impl too)

1. **Disable echo + ONLCR at the termios level from the parent**, not by sending
   `stty -echo` into the shell. zsh's line editor (ZLE) treats any tty stdin as
   interactive and re-echoes the command, winning the race. `tcsetattr` on the
   PTY (clearing `ECHO`/`ECHONL` + `ONLCR`) fixes it shell-agnostically.
2. **Use a random per-session marker token.** A static sentinel can be forged by
   command output. (Tested.)
3. **`printf '\037'` (octal), not `\x1f`** — dash's printf doesn't do `\xNN`.
4. **Sentinel goes *outside* the redirected command group** so it always reaches
   the PTY even if the user's command redirects its own stdout.
5. Normalize `\r` and strip surrounding blank lines from PTY-sourced stdout.

## Honest limits of this PoC (not yet proven — for the real build)

- **SSH transport** not exercised (no sshd here). Low novel risk: it's the same
  PTY-over-a-channel; `russh` gives an interactive channel with the same I/O.
- **Windows ConPTY** untested (deferred to v1.0 anyway).
- The temp-file side channel for stderr is a PoC shortcut; the real core would
  use a second pipe/fd or OSC-133 shell integration for streaming split.
- Throughput/concurrency (many sessions on one daemon) not benchmarked.

**Bottom line:** the two risks that could have killed the project — *command
boundary detection* and *stdout/stderr split* — are solved with a clean,
shell-portable technique. Greenlight to build v0.1.

---

# Flashy-feature security PoC (`run_flashy.py`)

The flashy features are only worth building if their **security gate actually
holds** — a flashy-but-insecure feature is a liability. These PoCs verify the
gate, not just the capability. **19/19 pass.**

```
F1  PASS   Self-healing reconnect re-verifies host key — MITM caught, no silent trust
F3  PASS   Snapshot: secrets redacted + encrypted at rest (Fernet) + tamper-evident;
           replay is DRY-RUN by default (destructive recorded command does NOT run)
F4  PASS   Fork inherits state but is process-isolated; no cross-session bleed;
           read-only observer has no exec capability
F5  PASS   Capability fence is default-deny + dangerous-pattern block; a blocked
           `rm` truly never touches the fs; agent CANNOT self-grant capabilities
F6  PASS   Native read_file honors the jail: absolute, `../`, and symlink
           traversal all blocked (realpath resolves before the check)

F2  CUT    Cross-host federated sessions — no PoC; attack surface > real value
```

Run it: `python3 run_flashy.py` (each `fN_*.py` is standalone).

## What each gate proves (the security claim, tested)

| Gate | Flashy feature | Security property verified |
|---|---|---|
| **F1** | Self-healing reconnect | A *changed* host fingerprint raises and refuses to reconnect/restore — the convenience can't become a silent MITM. State restore only happens *after* identity re-verification. |
| **F3** | Snapshot / replay / time-travel | Secrets are redacted before serialization; the at-rest blob is authenticated-encrypted (tamper flips → `InvalidToken`); replay executes nothing unless explicitly `live=True`, and live replay routes through the same policy gate (no raw shell). |
| **F4** | Fork / handoff / observation | A fork shares a *snapshot*, not a live process — mutating the child leaves the parent untouched; unrelated sessions can't see each other's env; the observer handle structurally lacks `exec`. |
| **F5** | Capability negotiation | Capabilities come from config only; `agent_requests_capability()` is a no-op; denied destructive commands are stopped *before* the shell sees them (verified by the file still existing). |
| **F6** | Native file primitives | `os.path.realpath()` collapses `..` and resolves symlinks *before* the jail-root check, so the structured primitive can't be used to escape the permission fence the shell would enforce. |

## Honest limits

- **F1** simulates the SSH bytes (no sshd here) but tests the exact decision —
  "verify the pinned fingerprint on every reconnect". Real impl: `russh` +
  a known-hosts store.
- **F3** encryption uses Fernet (AES-128-CBC+HMAC) as a stand-in; production
  would likely use AES-256-GCM / ChaCha20-Poly1305 with a real KMS-backed key.
- The capability engine's pipeline parser (`_programs`) is best-effort; a
  production fence needs a hardened parser + a deny-by-default sandbox transport
  as defense-in-depth (don't rely on string matching alone).

**Bottom line:** every flashy feature we kept has a working gate; the one whose
gate wasn't worth the surface (federated sessions) is cut. Security is
demonstrably a *precondition* of these features, not an afterthought.
