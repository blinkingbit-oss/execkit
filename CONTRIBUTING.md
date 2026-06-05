# Contributing to execkit

Thanks for your interest! execkit is a young project and contributions are welcome.

## Ground rules

- Be kind; see [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).
- Security issues go through [`SECURITY.md`](./SECURITY.md), **not** public issues.
- Discuss large changes in an issue first.

## Development setup

You need a recent stable Rust (MSRV is **1.85**). Docker is needed only for the
SSH end-to-end test.

```bash
git clone https://github.com/execkit/execkit && cd execkit
cargo build --workspace
```

## Before you push — the same checks CI runs

```bash
cargo fmt --all                                   # format
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy -p execkit --no-default-features --all-targets -- -D warnings   # lean build
cargo test --workspace                            # unit + local PTY + MCP e2e (no network)
```

### Running the SSH end-to-end test (optional, needs Docker)

```bash
docker run -d --name sshd -p 127.0.0.1:2222:22 alpine sh -c \
  "apk add --no-cache openssh && ssh-keygen -A && echo root:testpw | chpasswd && \
   sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && /usr/sbin/sshd -D -e"
EXECKIT_TEST_SSH="root:testpw@127.0.0.1:2222" cargo test -p execkit --test ssh_smoke -- --nocapture
docker rm -f sshd
```

Examples:

```bash
cargo run --example local
EXECKIT_SSH="user:pass@host:22" cargo run --example ssh
```

## Coding conventions

- `cargo fmt` and clippy-clean (`-D warnings`) are required.
- Tests verify **real behavior** (we drive real PTYs, a real sshd, and the real
  MCP binary), not mocks. New behavior needs a test.
- Keep the security posture in mind: tool/command inputs are **untrusted**
  (the agent may be prompt-injected). Don't add a tool argument that lets the
  caller pick arbitrary host paths, credentials, or hosts — make dangerous config
  operator-controlled (startup env). See the MCP server's threat-model comment.
- Match the surrounding style; small, focused PRs are easier to review.

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/).
Sign off each commit:

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by:` line certifying you wrote the change (or have the
right to submit it) under the project's license.

## License of contributions

By contributing, you agree your work is licensed under **Apache-2.0**, the
project license.
