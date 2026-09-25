# Upgrading to 0.9

0.9 changes some defaults and a few library types. Check this list before you
upgrade a server or bump the crate.

## Behaviour

- **SSH host keys live in `~/.execkit/known_hosts`.** Before 0.9 execkit pinned
  keys in `~/.ssh/known_hosts`. Those pins are not read any more. By default, the
  first connection to each host after upgrading records its key again (trust on
  first use), so connect once from a network you trust. To keep your old pins,
  copy execkit's lines (they look like `host SHA256:...`, unlike OpenSSH's own
  entries) into the new file:

  ```sh
  mkdir -p ~/.execkit && chmod 700 ~/.execkit
  grep -E '^[^ ]+ SHA256:' ~/.ssh/known_hosts >> ~/.execkit/known_hosts
  ```

  Old pins were keyed by bare host whatever the port. A line for a host you
  reached on a port other than 22 must be rewritten as `[host]:port` after
  copying (for example `example.com SHA256:...` becomes
  `[example.com]:2222 SHA256:...`); left as is, it is read as the port-22 pin,
  so a later port-22 connection to that host fails as a key mismatch.

  If you set `EXECKIT_MCP_KNOWN_HOSTS`, that file is still used. See
  [Transports](./transports.md#host-keys).
- **stdin is closed.** Every command runs with stdin set to `/dev/null`. Prompts,
  REPLs and `read` get end-of-file instead of waiting. Pagers are set to `cat`
  for the session (see [Sessions](./sessions.md#what-a-command-can-contain)).
- **The target needs `base64`.** Commands are sent base64-encoded. GNU coreutils,
  busybox and macOS `base64` all work. A shell without it fails at
  `session_create` with a clear error.
- **Timeouts return a result.** A command that runs past its timeout is
  interrupted with Ctrl-C and returned normally, with `exit_code` 124 and
  `timed_out: true`. The session stays usable. In 0.8 a timeout was an error
  (`command still running`) and closed the session. Only a command that ignores
  Ctrl-C still closes it.
- **Session ids changed format.** They are now `<run>-<n>_<transport>...`, for
  example `a3f9-1_local` or `a3f9-2_ssh_deploy@web1`, instead of `1_local`. Tools
  that parse ids or match audit file names need updating. See
  [Sessions](./sessions.md#session-ids-are-self-identifying).

## Rust library

- **`ExecResult` has a new public field, `timed_out: bool`.** Code that builds an
  `ExecResult` with a struct literal must set it. Code that only reads results is
  unaffected.
- **`SshConfig` has a new public field, `connect_timeout: Duration`** (default 15
  seconds). Build it with `SshConfig::new(...)` and then set fields, rather than a
  struct literal.
- **`Error::StillRunning` now means the timeout could not be interrupted**, and
  the session is closed. An ordinary timeout is `Ok` with `timed_out` set.

The Python `ExecResult` gains a `timed_out` attribute. Nothing was removed.
