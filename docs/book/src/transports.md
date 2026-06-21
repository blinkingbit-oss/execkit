# Transports

`session_create` takes a `transport`: `"local"`, `"ssh"`, or `"docker"`.

## Local

A shell on the machine running the server.

```jsonc
// session_create {"transport":"local"}  -> {"session_id":"1_local"}
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

Required: `host`, `user`, and one of `password` or `key_path`. Optional: `port`
(default 22) and `fingerprint` to pin an exact host key.

Host-key handling is safe by default:

- **Verified against `known_hosts` (TOFU).** A changed key is rejected as a likely
  man-in-the-middle. The file is `~/.ssh/known_hosts` unless
  `EXECKIT_MCP_KNOWN_HOSTS` overrides it, and the first connection records the key.
- **Pin a key** by passing `fingerprint` for an exact match.
- **`key_path` is sandboxed.** It must canonicalize to inside the key directory
  (`~/.ssh` by default, or `EXECKIT_MCP_KEY_DIR`). Out-of-bounds or traversal
  paths are rejected with a generic error that does not leak whether the path
  exists.

The home directory behind `~/.ssh` resolves by priority (`$HOME`, then the
system passwd database), so defaults are correct even when `$HOME` is unset, as
in a service-launched server.

For throwaway or test hosts only, `EXECKIT_MCP_INSECURE_ACCEPT_ANY_HOSTKEY=1`
disables host-key verification. Never use it in production.

## Docker

```jsonc
// session_create {"transport":"docker","container":"app-web-1"}
```

Runs `docker exec` against any container the daemon can see, so the agent reaches
whatever your Docker context exposes. Grant the server Docker access only when you
want that, and scope the daemon or context accordingly.

## Remote workspace undo

SSH and Docker sessions support [Checkpoints](./checkpoints.md): a git-backed
snapshot of the workspace you can restore on demand.
