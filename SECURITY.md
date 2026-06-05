# Security Policy

## Reporting a vulnerability

**Please do not open public issues for security vulnerabilities.**

Report privately via GitHub's **"Report a vulnerability"** button on the repo's
**Security** tab (Security Advisories). If that's unavailable, contact the
maintainers and we'll coordinate a private channel.

Please include: affected version/commit, a description, reproduction steps, and
the impact you observed. We aim to acknowledge within **3 business days** and to
ship a fix or mitigation for confirmed issues as quickly as is practical, then
disclose coordinated with you.

## Supported versions

execkit is pre-1.0. Security fixes target the **latest `0.x` release**; older
versions are not maintained.

## Threat model — the agent is the adversary

This is the most important thing to understand about execkit's security posture.

execkit executes shell commands on behalf of an AI agent. **That agent can be
prompt-injected** by any untrusted data it reads (a file, a web page, a CI log).
So execkit treats **its own caller as untrusted** and its job is to *contain* that
caller. Tool/command inputs are adversarial by assumption.

**In scope** (we want reports on these):
- Bypasses of the command policy that lead to execution the operator did not allow.
- Secret leakage: credentials or key material reaching the model, logs, or error
  messages.
- SSH host-key verification bypass / MITM acceptance outside the documented
  insecure opt-in.
- Path-traversal / arbitrary-read/-write via tool arguments (e.g. key paths, audit
  paths) in the MCP server.
- Memory/resource exhaustion (unbounded output, session/thread leaks) reachable
  from untrusted input.
- Sentinel-forgery or framing corruption from command output.
- Deadlocks/hangs reachable from untrusted input.

**Out of scope / known by design:**
- The command policy is **advisory**, not a sandbox (string-matching is bypassable
  by construction). The load-bearing control is a least-privilege *environment*;
  a real sandbox transport is roadmap (v0.4). Policy bypasses are still worth
  reporting, but "regex policy can be evaded" alone is expected.
- `HostKeyVerification::AcceptAny` and `EXECKIT_MCP_INSECURE_ACCEPT_ANY_HOSTKEY`
  disable MITM protection **on purpose** for testing — using them is not a vuln.
- Anything requiring an already-privileged local attacker on the operator's host.

## Operator hardening checklist

- Run the agent and any SSH user with **least privilege** (not root).
- Use the command `allow`/`deny` lists and an **audit log** (`EXECKIT_MCP_AUDIT`).
- Keep SSH host-key verification on (the default); pin a `fingerprint` for hosts
  you care about. Never set the insecure-accept-any opt-in in production.
- Constrain SSH key access with `EXECKIT_MCP_KEY_DIR`.
- Prefer ephemeral/sandboxed targets for autonomous runs.

## Known advisories in dependencies

- **RUSTSEC-2023-0071** (Marvin timing side-channel in `rsa`) is pulled
  transitively via `russh → ssh-key → rsa`. There is no fixed upstream release
  yet; it is acknowledged and tracked (CI ignores this specific advisory while
  still gating on all others). We will drop the exception when `russh` updates.
