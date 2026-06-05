<div align="center">

# execkit

**The safety layer that lets an AI agent run shell on real infrastructure — without you holding your breath.**

Persistent local + SSH sessions · structured results · secret-safe · default-deny policy · embeddable · open source

*What `libssh2` is to SSH, execkit is to agent shell sessions.*

[![CI](https://github.com/execkit/execkit/actions/workflows/ci.yml/badge.svg)](https://github.com/execkit/execkit/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/execkit.svg)](https://crates.io/crates/execkit)
[![docs.rs](https://img.shields.io/docsrs/execkit)](https://docs.rs/execkit)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

</div>

> **Status: v0.1, pre-release.** The core is built and reviewed — local + SSH
> transports, structured results, advisory policy, secret redaction, and an MCP
> server — all verified end-to-end (see [`poc/`](./poc/) and the test suite).
> Not yet published, and **not production-ready** (see [Limitations](#limitations-v01)).
> The plan is [`ROADMAP.md`](./ROADMAP.md); the vision is [`FEATURE_VISION.md`](./FEATURE_VISION.md).

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

So most teams just... don't let agents touch real infrastructure. execkit exists to
remove that fear.

## The core idea: the agent is the adversary

A traditional tool trusts its caller. execkit can't — the LLM driving it can be
**hijacked by prompt injection** from any data it reads (a poisoned file, a web
page, a CI log). So execkit's first job is to **contain its own caller.**

Every command passes through a fence *before* it reaches a shell:

```
agent ──▶ execkit ──▶ [ default-deny policy ] ──▶ [ dangerous-pattern intercept ]
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
sess = execkit.create(transport="ssh://deploy@prod-1", policy=Policy.default_deny(
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
> fine. execkit's value is **trust**: persistence, multi-transport reach, and the
> safety to point an agent at infrastructure you actually care about.

## Using it from an AI agent

- **Claude Code · Cursor · Gemini CLI** — execkit ships an **MCP server** (v0.1).
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

## Limitations (v0.1)

Be upfront — this is a young library. Today:

- **Not a sandbox.** The command policy is an *advisory* tripwire (string-matching,
  bypassable). The load-bearing control is the *environment* — run the agent and
  SSH user with least privilege. A real sandbox transport is on the roadmap (v0.4).
- **A timed-out command poisons the session.** There's no interrupt-and-resync yet;
  on timeout you get a clear error and should create a new session.
- **Unix-only.** Local transport needs a POSIX shell (`bash`); Windows (ConPTY) is
  v1.0.
- **Synchronous core.** Fine for typical agent use; not yet tuned for thousands of
  concurrent sessions.
- **SSH `AcceptAny` host-key mode exists** for testing and is gated behind an
  explicit insecure opt-in — never use it in production.
- **Recovery/time-travel, Docker/K8s transports, streaming, and more SDKs** are
  roadmap, not built. See [`ROADMAP.md`](./ROADMAP.md).

Found something rough? Please [open an issue](https://github.com/execkit/execkit/issues).

## Contributing & security

- Contributions: see [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- Found a vulnerability? Please follow [`SECURITY.md`](./SECURITY.md) — do **not**
  open a public issue for security reports.

## License

Apache 2.0 — embed it freely, including commercially. See [`LICENSE`](./LICENSE)
and [`NOTICE`](./NOTICE).
