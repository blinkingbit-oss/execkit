# nexum — The "Heaven-Tier" Feature Vision

> The dream version. Every feature here is **theoretically possible** — technical
> feasibility is checked separately (see `poc/`). This is the north star we steer
> toward, not the v0.1 scope.
>
> **One-line pitch:** *What `libssh2` is to SSH, nexum is to agent shell sessions* —
> an embeddable, language-agnostic library that turns "a terminal" into a
> **semantically rich, stateful, safe execution surface** that any AI agent can use
> as naturally as a human uses a terminal — and better.

---

## North-Star Principles (the feeling we sell)

0. **Secure by construction — the agent is the adversary.** The thing issuing
   commands (the LLM) can be hijacked by prompt injection from any data it reads.
   nexum's first job is to *contain its own caller*. A feature is not "tempting"
   and not "done" until its security guarantee ships *with* it. Flashy + insecure
   = a liability, not a feature. The most tempting thing we sell is **safe
   autonomy**: trust an agent with a real environment without fear.
1. **An agent should never see raw terminal garbage.** Every interaction returns
   meaning, not bytes.
2. **A session is a place, not a connection.** State persists. `cd` sticks. The
   agent "lives" there.
3. **Never blow up the agent's context window.** Output is the single biggest
   silent cost in agent loops — nexum treats tokens as a first-class budget.
4. **Same call everywhere.** Local, SSH, Docker, K8s, serial — one API, identical
   results.
5. **Safe by construction.** Running arbitrary commands is a loaded gun; nexum
   makes it hard to shoot yourself.
6. **Embeddable, never a service.** `cargo add` / `pip install` and it's *inside*
   your process. No daemon you don't control, no vendor.

---

## Tier 0 — Table Stakes (without these, no one stays)

| Feature | The dream |
|---|---|
| **Persistent stateful sessions** | `cd`, env vars, shell functions, and `$?` survive across commands — exactly like a human terminal left open. |
| **Structured `ExecResult`** | Every command returns a typed object: `stdout`, `stderr` (split!), `exit_code`, `duration_ms`, `cwd`, `env_delta`, `truncated`. Never a raw byte blob. |
| **Reliable command-boundary detection** | The library *knows* when a command finished, even on a messy remote shell — no guessing, no "sleep 2 and hope". |
| **Clean output** | ANSI/VT escape stripping, control-char sanitization, encoding normalization — by default. Raw mode available on request. |
| **Multi-transport, one API** | Local PTY, SSH, Docker exec, K8s exec — swap transport, keep the exact same `exec()` contract. |
| **First-class SDKs** | Python (PyO3), Node (napi-rs), Go, Rust — each feels *native*, not a subprocess wrapper. |
| **MCP server mode, day one** | `stdio` JSON-RPC so Claude Code / Cursor / any MCP agent points at it with zero glue. |

---

## Tier 1 — The Differentiators (why people *switch*)

### Output that respects the agent's brain
- **Token-aware output budgeting.** The agent declares its context window /
  per-call budget; nexum pre-counts tokens and adapts truncation *before*
  delivery. "Give me at most 2k tokens of this build log."
- **Semantic compression, not dumb truncation.** When output exceeds budget,
  compress *by meaning*: keep the error and the failing lines, summarize the 4,000
  lines of webpack progress into `… 4,012 progress lines elided …`.
- **Head/tail/grep-aware slicing.** First N + last N + lines matching a pattern,
  returned as one coherent slice with elision markers.
- **Secret redaction before delivery (tempting *and* secure).** Output passes a
  redaction pass — AWS keys, tokens, `.env` values, private keys, JWTs — *before*
  it reaches the LLM, so secrets never get shipped to the model provider or into
  logs. The agent gets `[REDACTED:aws_key]`, not your credentials.

### Sessions that don't break
- **Self-healing reconnect *with identity re-verification*.** Network drops →
  nexum reconnects and restores `cwd`/env transparently — but **re-verifies the
  SSH host key on every reconnect**; a changed key fails loudly (no silent MITM).
- **Session snapshot / restore.** Serialize a session's shell state and rehydrate
  it later (or on another host).
- **Connection pooling & multiplexing.** 50 agent sessions over one SSH/Docker
  connection — no 50 handshakes.

### Reacting to the world in real time
- **Streaming `ExecResult`** as an async iterator of typed events
  (`CommandStarted`, `OutputChunk`, `ProcessWaiting`, `CommandFinished`).
- **Semantic event detection.** Pre-parsed signals the agent would otherwise
  regex for: `server listening on :3000`, `tests: 3 failed`, `waiting for
  password`, `build succeeded`. Surfaced as typed events.
- **Long-running process monitoring.** Attach to `tail -f`, dev servers, watchers;
  get structured deltas, not a firehose.

### Talking to interactive things
- **Interactive stdin to live processes.** Drive a Python REPL, `vim`, `fzf`,
  `sudo` password prompts, `ssh` host-key prompts — write input, read the typed
  reaction.
- **Process-tree awareness.** Know what children a command spawned, their PIDs,
  and signal them cleanly.
- **Background/detached process management.** Start it, get a handle, poll status,
  collect output later, kill on demand.

---

## Tier 2 — The "Oh Wow" Magic (god-tier acceptance)

These are the features that make a developer tell three friends.

- **Capability negotiation / self-description.** On session init the agent declares
  what it can handle (streaming? images? max tokens? formats?), and nexum
  *auto-tunes* output format, verbosity, and chunking to match. The tool adapts to
  the agent instead of the reverse.
- **Environment diff after every command.** `env_delta` is just the start: surface
  *what changed in the world* — files created/modified, ports newly listening,
  processes started, packages installed — as a structured diff. "After `npm i`, 312
  files changed, 1 new lockfile, node_modules now 240MB."
- **Native structured primitives that bypass the shell.** `list_dir`, `read_file`,
  `stat`, `find`, `grep` return *typed data*, not text to be re-parsed — and work
  identically over local/SSH/Docker. Shell-out only when you actually need a shell.
- **Time-travel & deterministic replay.** Every session is an append-only log;
  replay any session command-by-command, or fork from any point ("git for shell
  state").
- **Dry-run / what-if mode.** Ask "what would this command change?" and get a
  predicted environment diff without executing (best-effort, for known commands).
- **Auto-error-context.** When a command fails, nexum attaches the *relevant*
  context automatically: the failing file+line, the last meaningful stderr lines,
  the exit-code meaning, and likely-related recent commands.
- **Visual terminal capture.** A pixel/screenshot API for TUI apps (`htop`, `vim`,
  ncurses) so computer-use agents can *see* a terminal, not just read text.
- **Format-agnostic responses.** JSON, MessagePack, XML, or a token-optimized
  binary — negotiated per consumer, same semantic payload.

---

## Tier 1.5 — Security IS the tempting feature (promoted, not garnish)

The reason teams *don't* let agents run shell unsupervised is fear. Remove the
fear and you unlock the use case — so these belong next to the magnets, not in a
back tier. Each is tempting *because* it is secure.

- **Default-deny capability model.** Allowlist/denylist commands, paths, env vars,
  and hosts — per session, per agent identity. The agent operates inside a fence
  it cannot widen. Capabilities are granted by **human/config only** — the agent
  can never self-declare elevated access (that would be privilege escalation).
- **Dangerous-command interception (HITL).** A pre-execution hook fires on
  destructive patterns (`rm -rf`, `dd`, `curl | sh`, `git push --force`); the
  owner approves / denies / edits. Autonomy with a seatbelt.
- **Secret redaction** (see Tier 1) — keeps credentials out of the model and logs.
- **Sandbox transports.** Run a command inside WASM/WASI, a throwaway container,
  or a Linux-namespace / macOS-Seatbelt profile — same `exec()` API. "Let the
  agent experiment" becomes safe because the blast radius is bounded.
- **Resource quotas & TTL.** Per-session CPU/mem/IO/command-count/idle limits stop
  a runaway agent loop from fork-bombing or draining the host (safety *and* cost).
- **Tamper-evident audit log.** Every command, result, agent identity, timestamp —
  non-repudiable, and the basis for forensics and replay.

---

## Flashy-but-dangerous — gated or cut (the honest part)

These read great on a roadmap but expand the attack surface. Each is kept **only
with its named mitigation**, or cut. A flashy feature with no security story is a
liability, not a differentiator.

| Feature | Hidden footgun | Decision |
|---|---|---|
| Self-healing reconnect | Silently accepts a *changed* SSH host key → MITM | **Keep** — re-verify host identity every reconnect; changed key fails loudly |
| Cross-host federated sessions | Lateral-movement path; magic routing blurs trust boundaries | **Cut** from the vision — too much surface for too little real need |
| Snapshot / replay / time-travel | Serializes shell state (secrets) to disk; replay re-runs destructive commands | **Gate** — encrypted + redacted snapshots; replay is dry-run by default |
| Session fork / handoff / observation | Session bleed; passing a live root session; one agent reading another's secrets | **Gate** behind hard namespacing + explicit grant, else cut |
| Capability negotiation | Agent self-declaring capabilities = privilege escalation | **Gate** — capabilities come from human/config, agent only *discovers* them |
| Native `read_file` / `find` primitives | Path traversal that bypasses the shell allowlist | **Gate** — honor the same permission layer; no backdoor around the fence |

---

## Tier 3 — Trust, Observability & Ecosystem

- **OpenTelemetry-native.** Spans for every session and exec, out of the box.
- **Deterministic replay from the audit log** for debugging and forensics
  (dry-run by default; see gating above).
- **Ecosystem integrations.** Tested guides for LangChain, CrewAI, LlamaIndex,
  AutoGen, OpenHands; benchmark suite; runnable-example docs.
- **Multi-agent coordination** *(gated)*. Read-only observation, live hand-off,
  A2A-compatible session refs — only under hard tenant namespacing + explicit
  grant (see "flashy-but-dangerous"). Cut if the isolation story isn't airtight.

---

## What nexum deliberately **refuses** to be (the strategic anchor)

- ❌ Not a hosted service / SaaS. It's a library you embed and own.
- ❌ Not a GUI / web terminal product.
- ❌ Not a managed cloud runtime (no lock-in, no per-seat billing).
- ❌ Not a 40-method kitchen sink. The core API stays tiny; richness lives in the
  *result*, not the surface.

---

## The minimal API surface that delivers all of the above

```text
session.create(transport, options)         -> SessionId
session.exec(id, command, budget?)         -> ExecResult            (structured)
session.stream(id, command, budget?)       -> AsyncIterator<Event>  (reactive)
session.write(id, input)                   -> ()                    (interactive)
session.state(id)                          -> ShellState
session.snapshot(id) / session.restore(s)  -> SessionId             (time-travel)
session.fork(id)                           -> SessionId             (multi-agent)
session.destroy(id)                        -> ()
```

> Seven verbs. Everything in Tiers 0–3 is expressed through the *richness of
> `ExecResult` / `Event` / `ShellState`* and the *pluggable transport + budget +
> policy* objects — never by bloating the verb list.

---

## Risk map (which dreams are scary, validated in `poc/`)

| Dream feature | Underlying risk | PoC |
|---|---|---|
| Structured `ExecResult` | **Knowing when a command finished** on any shell | R1 |
| `stdout`/`stderr` split | PTYs **merge** the two streams | R2 |
| Clean output | ANSI/control-char stripping fidelity | R3 |
| Stateful sessions | `cwd`/env/exit-code persistence + capture | R4 |
| Interactive stdin | Driving a live REPL/process | R5 |
| Multi-transport | Same contract over Docker exec | R6 |

If R1 and R2 hold, the entire vision is structurally feasible.
