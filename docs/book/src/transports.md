# Transports

`session_create` takes a `transport`: `"local"`, `"ssh"`, or `"docker"`. Any other
value is an error.

Every transport needs a POSIX shell and `base64` on the target: execkit sends each
command base64-encoded and decodes it there.

## Local

A shell on the machine running the server.

```jsonc
// session_create {"transport":"local"}  -> {"session_id":"a3f9-1_local"}
```

The agent reaches whatever the server's user can. Run that user with least
privilege.

## SSH

```jsonc
// session_create {
//   "transport":"ssh", "host":"web-01", "user":"deploy",
//   "key_path":"deploy_ed25519"            // or "password":"..."
// }
```

Required: `host`, plus a `user` and a way to authenticate, unless your ssh config
supplies them (below). Optional: `port` (default 22) and `fingerprint` to pin an
exact host key.

### Host aliases from your ssh config

`host` can be a `Host` alias from the operator's ssh config, read from
`<key dir>/config` (so `~/.ssh/config` by default). For an entry like this:

```text
Host web
    HostName web-01.internal
    User deploy
    Port 2222
    IdentityFile ~/.ssh/deploy_ed25519
```

the agent only needs `{"transport":"ssh","host":"web"}`. `HostName`, `User`,
`Port` and `IdentityFile` fill in whatever the call leaves out; arguments the
agent passes take precedence. Only exact `Host` names match: wildcard patterns,
`Match` blocks and `Include` are ignored.

### Authentication

execkit uses the first of these that applies:

1. `password`, if given.
2. `key_path`, if given.
3. The alias's `IdentityFile` entries, in order, then `id_ed25519`, `id_ecdsa` and
   `id_rsa` in the key directory. The first file that exists inside the key
   directory is used.

Every key must live inside the key directory (`~/.ssh` by default, or
`EXECKIT_MCP_KEY_DIR`). Out-of-bounds or traversal paths are rejected with a
generic error that does not leak whether the path exists. An `IdentityFile` that
points outside the key directory is skipped.

### Host keys

Host-key handling is safe by default:

- **Verified against execkit's own `known_hosts` (TOFU).** The file is
  `~/.execkit/known_hosts` unless `EXECKIT_MCP_KNOWN_HOSTS` overrides it. The
  first connection to a host records its key; a changed key is rejected as a
  likely man-in-the-middle. Entries are keyed `host` on port 22 and
  `[host]:port` otherwise, so two ports on one host are verified separately.
- **Not your OpenSSH `~/.ssh/known_hosts`.** Before v0.9 execkit wrote its pins
  to `~/.ssh/known_hosts`. It now keeps its own file and does not read the old
  pins, so after upgrading, the first connection to each host records its key
  again. To carry your pins over instead, copy execkit's lines (`host SHA256:...`)
  across:

  ```sh
  mkdir -p -m 700 ~/.execkit
  grep -E '^[^ ]+ SHA256:' ~/.ssh/known_hosts >> ~/.execkit/known_hosts
  ```

  If `EXECKIT_MCP_KNOWN_HOSTS` points at an OpenSSH-format file, connecting to a
  new host fails with an error saying so, instead of writing to that file. See
  [Upgrading to 0.9](./upgrading.md) for the other changes.
- **Pin a key** by passing `fingerprint` (`"SHA256:..."`) for an exact match.

### Connect timeout

Connecting, the SSH handshake and authentication share one 15 second budget. An
unreachable host or a server that stalls during auth fails `session_create` with
a timeout error instead of hanging.

The home directory behind `~/.ssh` and `~/.execkit` resolves by priority
(`$HOME`, then the system passwd database), so defaults are correct even when
`$HOME` is unset, as in a service-launched server.

For throwaway or test hosts only, `EXECKIT_MCP_INSECURE_ACCEPT_ANY_HOSTKEY=1`
disables host-key verification. Never use it in production.

## Docker

```jsonc
// session_create {"transport":"docker","container":"app-web-1"}
```

Runs `docker exec` against any container the daemon can see, so the agent reaches
whatever your Docker context exposes. If the container does not exist or is not
running, `session_create` fails with an error that names it. The container needs
a POSIX `/bin/sh`. Grant the server Docker access only when you
want that, and scope the daemon or context accordingly.

## Remote workspace undo

SSH and Docker sessions support [Checkpoints](./checkpoints.md): a git-backed
snapshot of the workspace you can restore on demand.
