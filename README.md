<div align="center">

# nexum

**The safety layer that lets an AI agent run shell on real infrastructure — without you holding your breath.**

Persistent SSH / Docker / K8s / local sessions · default-deny by construction · secret-safe · embeddable · open source

*What `libssh2` is to SSH, nexum is to agent shell sessions.*

</div>

> **Status: pre-v0.1, design + feasibility stage.** The hard parts are already
> proven — see [`poc/`](./poc/) (Rust `portable-pty` 12/12, Python technique
> 33/33, security gates 19/19). The plan is [`ROADMAP.md`](./ROADMAP.md); the full
> vision is [`FEATURE_VISION.md`](./FEATURE_VISION.md). Not yet shippable. Stars
> and feedback welcome; production use is not.

---

## The problem

Letting an autonomous agent run shell commands is the most useful — and most
terrifying — thing you can give it. Today your options are bad:

- **Built-in harness shells** (Claude Code, Cursor) are local-only and have no
  real guardrails for autonomous, unsupervised runs.
- **Managed sandboxes** (E2B, Daytona) are great but cloud-hosted — you can't
  embed them, and you inherit vendor lock-in and latency.
- **Raw SSH / tmux hacks** are stateless-per-command, leak escape codes, and have
  zero notion of "is this command allowed?"

So most teams just... don't let agents touch real infrastructure. nexum exists to
remove that fear.

## The core idea: the agent is the adversary

A traditional tool trusts its caller. nexum can't — the LLM driving it can be
**hijacked by prompt injection** from any data it reads (a poisoned file, a web
page, a CI log). So nexum's first job is to **contain its own caller.**

Every command passes through a fence *before* it reaches a shell:

```
agent ──▶ nexum ──▶ [ default-deny policy ] ──▶ [ dangerous-pattern intercept ]
                          │ blocked                    │ HITL approval
                          ▼                             ▼
                    never executed              human approves / denies
                                                        │ allowed
                                                        ▼
                                          transport (local · SSH · Docker · K8s)
                                                        │
                          structured result ◀── [ secret redaction ] ◀── output
```

A blocked `rm -rf` **never touches the filesystem**. An AWS key in the output is
**redacted before it ever reaches the model or your logs**. A changed SSH host
key **fails loudly instead of silently reconnecting into a MITM**. These aren't
roadmap promises — each gate is verified in [`poc/run_flashy.py`](./poc/).

## What you get

```python
# target API (v0.1) — illustrative
sess = nexum.create(transport="ssh://deploy@prod-1", policy=Policy.default_deny(
    allow=["ls", "cat", "systemctl status", "docker ps"],
))

r = sess.exec("systemctl status api")
# ExecResult(exit_code=0, stdout="● api active (running)...",
#            stderr="", duration_ms=120, cwd="/home/deploy")

sess.exec("rm -rf /var/lib")
# Blocked(reason="dangerous pattern") — the shell never saw it

sess.exec("env | grep AWS")
# ExecResult(stdout="AWS_SECRET_ACCESS_KEY=[REDACTED]")  # never leaves the box
```

- **Safe autonomy** — default-deny capability fence, dangerous-command
  interception (human-in-the-loop), secret redaction, tamper-evident audit.
- **Persistent sessions** — `cd`/env/state stick across commands, like a real
  terminal left open. Not a new connection per command.
- **One API, every transport** — local PTY, SSH, Docker exec, K8s exec return the
  identical structured result.
- **Token-aware output** — compress a 4,000-line log to the part that matters, so
  agent context (and cost) doesn't blow up.
- **Embeddable, never a service** — `cargo add` / `pip install`, in *your*
  process. No daemon you don't control, no vendor.

> Structured output is a feature, not the pitch. LLMs read raw terminal text
> fine. nexum's value is **trust**: persistence, multi-transport reach, and the
> safety to point an agent at infrastructure you actually care about.

## Using it from an AI agent

- **Claude Code · Cursor · Gemini CLI** — nexum ships an **MCP server** (v0.1).
  Add it to your MCP config and the agent calls its tools directly; no model
  changes, no special access.
- **Custom agents** (Claude / Gemini / OpenAI APIs, LangChain, CrewAI, OpenHands)
  — native Python SDK (v0.1), Node (v0.2), Go (v0.3).

## Why Rust

Concurrent session handling, zero-cost FFI to every language SDK, and PTY
correctness via `portable-pty` — memory-safe where a C core would get ugly fast.
The critical path is already proven in Rust: [`poc/rust/`](./poc/rust/).

## Status & roadmap

| Version | Theme |
|---|---|
| **v0.1** | Proven core + non-negotiable safety: PTY+SSH, `ExecResult`, capability fence, secret redaction, MCP mode, Python SDK |
| v0.2 | Docker/K8s transports, pooling, output budgets, Node SDK |
| v0.3 | Streaming, interactive stdin, semantic events, token-aware compression, Go SDK |
| v0.4 | Sandbox transport, host-key-verified reconnect, encrypted snapshots, audit + OTel |
| v1.0 | Windows ConPTY, stable API, framework guides, benchmarks |

Full detail in [`ROADMAP.md`](./ROADMAP.md). **Cut on purpose:** cross-host
federated sessions (attack surface > value).

## License

Apache 2.0 — embed it freely, including commercially.
