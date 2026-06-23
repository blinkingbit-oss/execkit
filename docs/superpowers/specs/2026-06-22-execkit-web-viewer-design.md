# execkit-mcp live web viewer - design

## Overview

A read-only, real-time shell-transcript screen that appears in the user's
browser with no manual step, plus a standalone command to browser-view any
audit log. It is a thin new layer over the existing `watch` stack: the same
audit events and the same `render_event` rendering, delivered over
Server-Sent Events (SSE) to a self-contained HTML page styled like a terminal.

This is the third delivery surface for watching an agent's shell activity,
alongside the existing TUI (`watch`), plain follow stream (`watch --follow`),
and the MCP log/progress notifications. It exists because the other surfaces
all require a manual step: pressing Ctrl+O to expand agent output, or opening a
second terminal to run `watch`. The browser tab is a clear, separate, view-only
screen the MCP server can put in front of the user on its own.

## Goals

- A live, view-only shell transcript on a clear, direct screen with no manual
  step when enabled.
- Reuse the existing event parsing, rendering, and session model; keep the new
  surface small.
- Keep the existing TUI and follow paths unchanged.

## Non-goals

- Not a sandbox or an access-control boundary. Advisory, localhost dev tooling.
- No interactivity that touches the agent: the viewer cannot send commands,
  edit, or mutate anything. It only reads the audit stream.
- No remote access. Bind to loopback only; never expose beyond the local host.
- No authentication beyond a single URL token (it is local-only tooling).

## Decisions (settled during brainstorming)

1. **Surface: a localhost browser tab.** The only direct, separate screen the
   MCP server can drive without the user's terminal, and universally available.
   Not a native GUI window (heavy, platform packaging) and not an editor-tailed
   file (weaker for a growing stream).
2. **Off by default, opt-in.** A server that silently binds a port and opens
   browser tabs would be a surprise-and-trust problem.
3. **Auto-open the browser** on the auto-start path (no click), and also emit
   the URL via an MCP log notification as a fallback.
4. **Layout: session sidebar + transcript pane**, mirroring the TUI model.
5. **Delivery: both** an MCP-server auto-start path and a standalone
   `watch --serve` subcommand.
6. **Event source for auto-start: tail the audit file** (reuse `Tailer` /
   `Source`). If the web viewer is enabled with no audit path configured, the
   server auto-creates a default audit file in the execkit state dir so there is
   something to tail.
7. **One new dependency: `getrandom`** (small, audited) for the URL token.

## Architecture

```
                    +-------------------+
 audit events  -->  | Source / Tailer   |  (existing)
 (file on disk)     +-------------------+
                              |
                              v
                    +-------------------+
                    | render_event      |  (existing) -> Vec<RenderedLine{kind,text}>
                    +-------------------+
                              |
                              v
                    +-------------------+        SSE (text/event-stream)
                    | web server        |  ----------------------------->  browser page
                    | (tokio TCP,       |        JSON line events           (sidebar + panes,
                    |  hand-rolled HTTP) |  <-----------------------------    terminal-styled,
                    +-------------------+        GET / , GET /events?t=       read-only)
```

The data path is identical to the TUI up to `render_event`. The new layer
serializes each rendered line (with its session id and `LineKind`) to JSON and
pushes it to connected browsers over SSE. The browser holds the same per-session
model the TUI's `AppState` holds, routing lines into per-session buffers and
rendering the selected one.

No heavyweight HTTP framework. SSE is a `Content-Type: text/event-stream`
response whose body is a sequence of `data: <json>\n\n` chunks. This is
hand-rolled on a `tokio` `TcpListener` (tokio is already a dependency).

## Components

### `watch/web.rs` (new)
The HTTP/SSE server.

- `serve(source, bind, token, open) -> anyhow::Result<ServerHandle>`:
  binds `127.0.0.1:0` (ephemeral port), spawns the accept loop on the tokio
  runtime, returns the chosen `SocketAddr` and token so the caller can build the
  URL. Holds a broadcast of rendered lines plus the full backlog for replay.
- Accept loop: per connection, parse the request line + path. Route:
  - `GET /?t=<token>`: serve the HTML page; the token is required here too. The
    page reads the token from its own URL (`window.location.search`) and reuses
    it for the `/events` fetch, so the token lives only in the URL.
  - `GET /events?t=<token>`: SSE stream. On connect, replay the current backlog
    (all rendered lines so far), then stream new lines live until the client
    disconnects.
  - Any other path, or a missing/incorrect token: `403`/`404` as appropriate.
- A poller task drives the `Source`: poll for new `AuditEvent`s, run
  `render_event`, append to the backlog, broadcast to subscribers.
- `open_browser(url)`: platform command selection - `xdg-open` (Linux),
  `open` (macOS), `cmd /c start` (Windows). Spawned detached; failure is
  non-fatal (the URL was also surfaced via notification).

### `watch/viewer.html` (new, embedded via `include_str!`)
A single self-contained page: inline CSS + JS, no external assets. Opens an
`EventSource` to `/events?t=<token>`, maintains per-session line buffers,
renders the sidebar (`> id (cmd-count)`, dim when closed) and the selected
session's transcript with TUI-matching colors (cyan bold prompt, red
stderr/`x exit`, green `ok exit`, dim markers). Auto-scrolls to the bottom
unless the user has scrolled up. Read-only.

### `main.rs` wiring
- Arg parsing: extend the existing `watch` subcommand to recognize `--serve`
  and `--open`. `watch --serve [--open] <file>` runs the web server against the
  given audit file (or `EXECKIT_MCP_AUDIT` / `EXECKIT_MCP_AUDIT_DIR`), tailing
  it via `Source`, and blocks until Ctrl+C.
- Auto-start hook in `run_server`: when `EXECKIT_MCP_WATCH_WEB` is set, after
  resolving the audit path (defaulting one in the state dir if unset), spawn the
  web server, open the browser, and emit the URL via
  `notify_logging_message` (info level).

## Data flow

1. The MCP server executes a command; the existing `AuditWriter` appends an
   `AuditEvent` (Open / Exec / Close / Blocked) to the audit file.
2. The web server's poller `Source::poll()` reads new events, calls
   `render_event` to produce `RenderedLine { kind, text }` values, tags each
   with the event's session id, appends to the in-memory backlog, and
   broadcasts to SSE subscribers.
3. Each connected browser receives the lines as JSON SSE messages, routes them
   into per-session buffers, and updates the DOM.
4. A browser connecting mid-session first receives the full backlog (replay),
   so the panes are populated immediately, then live updates.

## Endpoints

- `GET /` (token required): the HTML page.
- `GET /events?t=<token>`: SSE stream. `text/event-stream`; body is
  `data: {"session":"1_local","kind":"prompt","text":"/tmp $ ls"}\n\n` lines.
  Replay-then-live.
- All responses include `Cache-Control: no-store`. Missing/incorrect token -> `403`.

The SSE message payload is one rendered line:

```json
{ "session": "1_local", "kind": "stderr", "text": "ls: cannot access ..." }
```

`kind` is the serialized `LineKind` (prompt | stdout | stderr | exit_ok |
exit_err | marker), so the browser colors without re-deriving meaning.

## Security model

- **Loopback only.** Bind `127.0.0.1`. Never `0.0.0.0`.
- **Ephemeral port**, one per server process, so concurrent agents do not
  collide.
- **URL token.** A 128-bit random token (`getrandom`) generated at startup,
  required on `/` and `/events`. Requests without it get `403`. This blocks
  other local processes and CSRF from a random visited web page from reading
  the transcript.
- **Read-only by construction.** No endpoint mutates state; the server only
  reads the audit stream and serves a static page.
- **Secrets already redacted.** execkit redacts secrets before they reach the
  audit stream. The audit may still be sensitive, so loopback + token is the
  boundary. This is advisory tooling, documented as such.

## Configuration

- `EXECKIT_MCP_WATCH_WEB` (set/unset): enable the auto-start web viewer. When
  set, the server serves + auto-opens the browser + emits the URL notification.
- Audit path resolution for the viewer: `EXECKIT_MCP_AUDIT` if set, else
  `EXECKIT_MCP_AUDIT_DIR`, else a default file in the execkit state dir created
  for the session.
- CLI: `execkit-mcp watch --serve [--open] <audit-file-or-dir>`. Without an
  explicit path it falls back to `EXECKIT_MCP_AUDIT_DIR` / `EXECKIT_MCP_AUDIT`,
  matching the existing `watch` path resolution.

## Testing

- **Unit (web.rs):**
  - Token check: a request to `/` or `/events` without the token returns `403`.
  - `GET /` returns the HTML page (status 200, `text/html`).
  - `GET /events?t=<token>` returns `text/event-stream` and replays existing
    backlog lines. Bind an ephemeral port, connect with a raw tokio TCP client,
    assert the response head and the first replayed `data:` line.
  - `open_browser` command selection per OS returns the expected argv; do not
    actually spawn in tests.
- **Integration (new `web_viewer.rs`, mirroring `policy_file.rs`):** drive the
  built server with `EXECKIT_MCP_WATCH_WEB` + `EXECKIT_MCP_AUDIT` set, assert the
  startup log notification carries a `http://127.0.0.1:<port>/?t=<token>` URL,
  connect to `/events`, run a `session_exec`, and assert the exec lines arrive
  over SSE.
- **Reused:** the existing `render_event` and `Tailer` tests cover rendering and
  tailing; this feature does not re-test them.

## File structure

- New: `crates/execkit-mcp/src/watch/web.rs`
- New: `crates/execkit-mcp/src/watch/viewer.html` (embedded via `include_str!`)
- New: `crates/execkit-mcp/tests/web_viewer.rs`
- Modified: `crates/execkit-mcp/src/watch/mod.rs` (declare `web`), `main.rs`
  (arg + auto-start wiring), `Cargo.toml` (add `getrandom`)
- Reused unchanged: `watch/render.rs`, `watch/source.rs`, `watch/tail.rs`,
  `watch/dirtail.rs`, `audit.rs`, `paths.rs`

## Dependencies

- New: `getrandom` (token randomness). Small, audited; cargo-deny/cargo-audit
  in CI will see it.
- No new HTTP framework: SSE is hand-rolled over `tokio::net`.

## Constraints

- ASCII only in code, docs, and help text (no em-dash or non-ASCII typography).
- Keep the existing TUI (`watch`) and follow (`watch --follow`) paths working
  unchanged.
- No `unwrap`/`expect` on network input or operator-controlled values.

## Out of scope (future, if a user asks)

- WebSocket upgrade (SSE is sufficient for one-way streaming).
- An in-memory event tee that removes the audit-file dependency for auto-start.
- Authentication beyond the URL token.
- Filtering/search in the page.
