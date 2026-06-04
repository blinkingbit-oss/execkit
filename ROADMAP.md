# nexum — Roadmap

An embeddable library that gives AI agents **stateful, structured, safe** shell
sessions on real infrastructure. *What `libssh2` is to SSH, nexum is to agent
shell sessions.*

**Operating principle:** ship the simplest thing that works now; defer every
complex variant until a real user/use-case justifies it. Decisions for later
releases are made *when we build them*. See [`README.md`](./README.md),
[`FEATURE_VISION.md`](./FEATURE_VISION.md), [`poc/`](./poc/), [`docs/adr/`](./docs/adr/).

Each stage has two tracks: **Build** (features) and **Ship & grow** (distribution,
docs, examples, marketing). A release isn't done until both are done.

Legend: ✅ proven in PoC · ⮕ simple version first, complex variant deferred

---

## Licensing & naming (decide once, up front)

- **License: `Apache-2.0`** — explicit patent grant, enterprise-friendly, allows
  free embedding (incl. commercial). Add `LICENSE` (Apache 2.0 text) + a `NOTICE`
  file (your attribution) + SPDX headers.
- **Name clearance:** confirm `nexum` is free on **crates.io, PyPI, npm, GitHub
  org, pkg.go.dev**, and do a basic trademark sanity check. Reserve the names early
  (publish a placeholder `0.0.0` crate to hold it).
- **Contribution model:** use **DCO** (`Signed-off-by`), not a CLA — lower friction
  for an OSS infra project.
- **Crypto/export note:** revisit when encryption-at-rest lands (v0.4).

---

## Phase 0 — Foundations (before v0.1 ships, one-time)

**Repo & hygiene**
- `git init`, public GitHub repo, `.gitignore` (ignore `target/`, build artifacts)
- `LICENSE` (Apache-2.0) + `NOTICE`, `README.md` (done), `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `SECURITY.md` (disclosure policy — we're a security tool),
  issue/PR templates
- `CHANGELOG.md` (Keep-a-Changelog) + a written semver policy (note 0.x caveats)

**CI/CD & quality gates**
- GitHub Actions: `fmt` + `clippy -D warnings` + `test` + `build` on push/PR
- `cargo-deny` (license + advisory check) and `cargo-audit` in CI
- Branch protection on `main`; release tag → build workflow

**Docs scaffolding**
- `docs/` structure; ADRs (started); a one-page "architecture & security model"

## v0.1 — MVP (SSH-first vertical slice)

**Build** *(simple option everywhere — no second mechanism/SDK)*
- ✅ Persistent PTY sessions · ✅ structured `ExecResult` · ✅ always-on ANSI strip
- ✅ Sentinel command boundary ⮕ (OSC 133/7 → v0.3) + long-running detect + interrupt-resync
- Bounded/backpressured output (byte cap) · SSH transport (`russh`)
- Least-privilege transport defaults (load-bearing control)
- Simple advisory policy ⮕ allowlist + dangerous-pattern denylist (no DSL)
- Secret redaction · plain append-only JSONL audit log ⮕ (hash-chain → v0.4)
- MCP server mode (stdio) — the only interface in v0.1

**Ship & grow**
- 📦 Publish core crate to **crates.io** (`cargo publish`); **docs.rs** builds automatically
- 🏷️ Tag `v0.1.0` + GitHub Release with notes; start `CHANGELOG`
- 📚 **Quickstart** + **"Add nexum to Claude Code / Cursor / Gemini CLI" MCP guide** + rustdoc on the public API
- 🧪 3 runnable **examples**: local exec, persistent SSH session, MCP server config (with a demo GIF/asciinema)
- 📣 **Launch:** problem-first blog post ("agents are running shell on prod with no guardrails — here's the gap"), Show HN, r/rust + r/LocalLLaMA, submit to **awesome-mcp / MCP registry**

## v0.2 — Recover & reach

**Build**
- 🔑 Git-backed **workspace checkpoints (linear)** ⮕ snapshot → restore-last; gated, diff-and-warn *(branches → v0.4; side effects NOT reverted)*
- Local + Docker exec transports · output budget controls (head/tail/grep + cap) · **Python SDK** (PyO3)

**Ship & grow**
- 📦 Publish **Python SDK to PyPI** (maturin; manylinux + macOS wheels) · republish crate
- 📚 Docs: **recovery/checkpoint guide** (with the honest "what undo does and doesn't cover"), Docker transport guide, Python SDK reference
- 🧪 Examples: checkpoint/restore, Docker session, Python quickstart
- 📣 Blog: "undo for agent actions — speculative execution on real servers"; seed `good-first-issue`s for contributors
- 📊 Publish first **benchmarks** (latency, concurrent sessions)

## v0.3 — Streaming & interactivity

**Build**
- Streaming `ExecResult` (events) · ✅ interactive stdin (REPLs/prompts)
- **OSC 133/7** boundary detection (upgrade over sentinel) · **Node SDK** (napi-rs)

**Ship & grow**
- 📦 Publish **Node SDK to npm** (napi prebuilt binaries per OS/arch) · republish crate + PyPI
- 📚 Docs: streaming guide, interactive-process guide, **OSC 133 shell-integration setup**
- 🧪 Examples: live build-watching, driving a REPL, Node quickstart, **a LangChain/CrewAI integration**
- 📣 Tutorial-style articles (integration walkthroughs) — content that ranks for "agent + ssh/terminal" searches

## v0.4 — Containment, history & scale  *(decide details when we build it)*

**Build**
- 🔒 Sandbox transport as a **mode** (integrate a proven runtime) · 🔑 git checkpoints: **branches / history tree / prune**
- 🔒 Self-healing reconnect w/ host-key re-verify · hash-chained tamper-evident audit
- K8s exec · quotas/TTL · OpenTelemetry · **Go SDK**

**Ship & grow**
- 🔐 **External/community security audit** *before* promoting production use; add crypto/export notice
- 📦 Publish **Go module** (pkg.go.dev); republish all SDKs
- 📚 Docs: **security model deep-dive**, sandbox setup, audit/compliance guide, K8s + OTel guides
- 📣 Thought-leadership blog: "safe autonomy — the security model for agents on real infra"

## v1.0 — Production stable

**Build**
- Windows ConPTY · stable semver API (internal schema frozen) · MCP Streamable-HTTP

**Ship & grow**
- 🏷️ **1.0 announcement** + retrospective blog; semver/stability guarantee documented
- 📚 Full integration guides (LangChain, CrewAI, OpenHands, AutoGen) · migration guide · **benchmark report**
- 🌐 Simple **landing page / docs site**; demo video
- 📣 Bigger push: conference talk / podcast / newsletter outreach; submit to relevant "awesome" lists
- 🤝 Lightweight **governance doc** (maintainers, release process) as contributors arrive

---

## Recurring every release (the checklist)

- Bump version · update `CHANGELOG` · tag · GitHub Release with notes
- `cargo publish` (+ PyPI/npm/Go as they exist) · verify docs.rs renders
- Run `cargo-deny` / `cargo-audit`; fix advisories
- Update README badges, examples, and any drifted docs
- Triage issues/PRs; update `good-first-issue`s
- One piece of **problem-first content** per release (indirect need-creation, not a sales pitch)

## Marketing principle (so it doesn't feel like spam)

Lead with the **pain**, not the product: articles about agents nuking servers,
context-window blowup from huge logs, and the absent audit trail for autonomous
actions. Each naturally arrives at "…which is the gap nexum fills." Dev tools win
on **docs + a 30-second working demo**, not announcements.

## Deferred — decide if/when a user asks

Semantic output compression · semantic event detection · transparent self-healing ·
federated sessions · multi-agent fork/handoff · WinRM/serial · public schema spec.

## API surface (stable target — richness lives in the result, not the verbs)

```text
session.create(transport, options)   -> SessionId
session.exec(id, command, budget?)   -> ExecResult            (structured)
session.stream(id, command, budget?) -> AsyncIterator<Event>  (v0.3)
session.write(id, input)             -> ()                    (interactive, v0.3)
session.state(id)                    -> ShellState
session.checkpoint(id) / restore(c)  -> CheckpointId          (v0.2, gated)
session.destroy(id)                  -> ()
```
