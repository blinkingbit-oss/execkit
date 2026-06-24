# execkit-mcp web viewer - UX iteration design

## Overview

A major UX iteration on the read-only web viewer (shipped in the prior branch).
It redesigns the sidebar (transport-grouped accordion with friendly session
labels, active highlight, resize, branding), adds per-session actions (rename,
pin, keep, export, screenshot) via a 3-dots overflow menu, and adds history
(browse past sessions from the audit directory). It introduces the viewer's
first write surface - a narrow, display-only metadata store - so renames, pins,
and keeps persist server-side and are shared across browsers.

Most layout/label work is a `viewer.html` (frontend) change deriving from data
the page already has. The new server work is four endpoints in `watch/web.rs`
plus a small metadata store module.

## Goals

- Sidebar grouped by transport with exact per-group counts; expandable groups;
  friendly labels (ssh `user@host`, docker `container`, local); active session
  highlighted.
- Per-session 3-dots menu: rename, pin to top, keep, export, screenshot.
- Resizable sidebar (drag), with width persisted.
- Browse the last N past sessions and view their logs; pinned and kept sessions
  are surfaced/retained.
- Branding: "execkit" shown at the top in a larger mono font.
- Export a session to `.txt`, `.log`, `.md`, `.json`; screenshot a session to
  `.png`.

## Non-goals

- No external JS/CSS libraries. The page stays a single self-contained
  `viewer.html` embedded via `include_str!`.
- The write surface is NOT a general file or session API. It writes exactly one
  fixed metadata file and can never affect sessions, execution, or the audit log.
- No auth beyond the existing URL token. Loopback only.
- No real-time collaboration / multi-user concerns beyond a shared local file.

## Decisions (settled during brainstorming)

1. **State model: server-side.** Renames/pins/keeps persist in a server-written
   metadata file so they are durable and shared across browsers. This relaxes
   the prior "read-only by construction" invariant to "read audit + write one
   display-only metadata file" (see Security model).
2. **History source: server enumerates a session-log directory.** New read
   endpoints list and serve past session files from `EXECKIT_MCP_AUDIT_DIR`.
   Requires dir-mode auditing; with single-file `EXECKIT_MCP_AUDIT`, history
   degrades to the current file's contents (documented limitation).
3. **Screenshot: canvas to PNG.** The transcript is monospace, so the page draws
   it to a `<canvas>` and downloads a `.png`. No external libs.
4. **Export formats: `.txt`, `.log`, `.md`, `.json`.** Client-side Blob
   download. (`.html`/asciinema `.cast` are out as YAGNI.)
5. **Labels/grouping parse the session id**, which already encodes
   `{num}_{transport}_{detail}` (e.g. `1_local`, `2_ssh_etlrobot@web-01`,
   `3_docker_myapp`). No server change for grouping/labels.

## Endpoints

All require `?t=<token>`; a missing/wrong token returns 403; all responses send
`Cache-Control: no-store`. Bind 127.0.0.1 only.

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | the page (existing) |
| `/events` | GET | live SSE stream of the tailed audit source (existing) |
| `/sessions` | GET | JSON list of past sessions from the audit dir: `[{id, label, transport, started_ms, size}]` |
| `/session/<id>` | GET | one past session's rendered transcript as a JSON array of line objects `[{session, kind, text}]` (a plain GET, not SSE - history is static) |
| `/state` | GET | the current viewer metadata JSON |
| `/state` | POST | replace the viewer metadata JSON (validated, size-capped) |

## Security model

The new write surface is intentionally minimal and non-dangerous:

- **One fixed file.** POST `/state` replaces `~/.execkit/viewer-state.json`
  (mode 0600) wholesale. There is no caller-supplied path or filename; the agent
  or page can never write anywhere else.
- **Validated, size-capped payload.** The body must parse as the expected shape
  `{ "<session-id>": { "alias"?: string, "pinned"?: bool, "keep"?: bool }, "ui"?: { "sidebarWidth"?: number } }`
  and be under a hard byte cap (e.g. 256 KiB). Reject otherwise with 400.
  Aliases are length-capped and stored verbatim (rendered via textContent, never
  HTML).
- **Display-only.** This metadata affects only how the page labels/orders
  sessions. It never touches a real session id, the audit log, execution, or any
  command. A rename is a display alias.
- **CSRF-safe.** The token lives only in the URL (never a cookie), so a
  cross-origin page cannot read it; an untokened POST returns 403. The page
  sends the token as a query param on its own fetch, same as the read routes.
- **Path-safe history.** `/session/<id>` validates `<id>` against
  `^[0-9]+_[A-Za-z0-9@.:_-]+$` and resolves only the matching file within the
  configured audit dir; no `..`, no absolute paths, no escape.
- **Loopback + token preserved** on every endpoint, exactly as today.

## Frontend (viewer.html)

A single self-contained page; vanilla HTML/CSS/JS; ASCII only.

### Branding header
"execkit" at the top in a larger monospace font, with the existing "live -
read-only" descriptor beneath (now "read + local notes").

### Sidebar
- **Accordion grouped by transport.** Groups: local, ssh, docker (and any future
  transport, derived from the id/transport). Each group header shows an exact
  count and expands/collapses. Group membership and the friendly label are
  parsed from the session id: `{num}_{transport}_{detail}` ->
  group=`transport`, label=`detail` (`user@host`, `container`, or `local`).
- **Active highlight.** The selected session is visually highlighted; closed
  sessions are dimmed (existing behavior preserved).
- **Pin to top.** Pinned sessions float to the top of their group with a pin
  marker; persisted via `/state`.
- **Keep.** Kept sessions are retained when history is trimmed to the last N;
  persisted via `/state`.
- **3-dots overflow menu** per session row: Rename, Pin/Unpin, Keep/Unkeep,
  Export (submenu: txt/log/md/json), Screenshot (png).
- **Rename.** Inline edit or prompt; stored as a display alias in `/state`. The
  real id is shown on hover/title. Alias rendered via textContent.
- **Resizable.** A drag handle on the sidebar's right edge resizes its width;
  the width persists to `/state` (`ui.sidebarWidth`) and restores on load.

### History panel
- A "History (last N)" section lists past sessions from `/sessions`, newest
  first, showing the friendly label and a relative time. Clicking one loads its
  transcript via `/session/<id>` into the transcript pane (read-only).
- Kept sessions are always shown; pinned sessions surface to the top.
- N is a small constant (e.g. 20) with kept sessions exempt from the cap.

### Export and screenshot (client-side)
- **Export** formats the currently loaded transcript (live or fetched-old) into
  a Blob and triggers a download:
  - `.txt` / `.log`: the plain shell-transcript lines.
  - `.md`: a header (session label + time) plus the transcript in a fenced code
    block.
  - `.json`: the raw audit events / rendered line objects.
- **Screenshot**: render the visible transcript to a `<canvas>` (fixed monospace
  metrics, per-kind colors) and download `session-<id>.png`.

## Data flow

1. Live: unchanged - the page tails `/events` and renders into per-session
   buffers; grouping/labels derive from the id.
2. Metadata: on load the page GETs `/state`; on any rename/pin/keep/resize it
   POSTs the updated state. The server validates and persists to the fixed file.
3. History: the page GETs `/sessions` to populate the history panel; selecting a
   past session GETs `/session/<id>` and renders it read-only.

## Module structure

- `crates/execkit-mcp/src/watch/web.rs` - add the `/sessions`, `/session/<id>`,
  `/state` (GET/POST) routes to the existing router; keep `serve`, token gate,
  and SSE unchanged.
- `crates/execkit-mcp/src/watch/state.rs` (new) - the viewer-metadata store:
  load/validate/save `~/.execkit/viewer-state.json`, the payload shape + caps,
  and the id-validation + dir-resolution for `/session/<id>`.
- `crates/execkit-mcp/src/watch/viewer.html` - the redesigned page.
- `crates/execkit-mcp/src/paths.rs` - add `default_viewer_state_path()`.
- Reused unchanged: `render_event`, `Source`/`Tailer`/`DirTailer`, `AuditEvent`,
  `gen_token`, the SSE plumbing.

## Build order (phased tasks within this one spec)

1. **Sidebar foundation** (frontend only, no new endpoints): accordion grouping
   + friendly labels (parse id), active highlight, resizable sidebar (local for
   now; wired to `/state` in phase 2), branding header. De-risks the layout and
   ships value immediately.
2. **State endpoints + rename/pin/keep**: `/state` GET/POST, the `state.rs`
   store (validated, capped, 0600, display-only), and the 3-dots menu wiring for
   rename/pin/keep + persisting sidebar width. The security-sensitive phase.
3. **History**: `/sessions` + `/session/<id>` (with id validation + dir
   resolution) and the history-panel UI.
4. **Export + screenshot**: client-side export (txt/log/md/json) and canvas->PNG
   screenshot, via the 3-dots menu.

## Constraints

- Bind 127.0.0.1 only; never 0.0.0.0.
- Token required on every endpoint (including the new ones); missing/wrong -> 403;
  all responses `Cache-Control: no-store`.
- The write surface writes exactly one fixed metadata file; validated + size-capped;
  display-only; never affects sessions/execution/audit.
- `/session/<id>` validates the id (`^[0-9]+_[A-Za-z0-9@.:_-]+$`) and resolves
  only within the audit dir; no traversal.
- No external JS/CSS libraries; single self-contained `viewer.html` via
  `include_str!`.
- ASCII only in code, docs, and the page source (no em-dash/non-ASCII). UI
  affordances (accordion arrows, the 3-dots menu glyph, pin marker, active dot)
  are CSS-drawn (borders/pseudo-elements) or plain ASCII - never emoji or
  box-drawing glyphs in the HTML source.
- No `unwrap`/`expect` that can panic on network input or operator values.
- Keep the existing TUI / follow / `watch --serve` / auto-start paths and the
  live SSE behavior working unchanged.

## Testing

- Unit (`web.rs`/`state.rs`): `/state` GET returns the stored JSON; POST with a
  valid payload persists and round-trips; POST with an oversized or malformed
  payload -> 400; the file is created 0600. `/sessions` lists the dir's session
  files with parsed fields. `/session/<id>` rejects a traversal/invalid id with
  400/404 and serves a valid id's transcript. Token gate -> 403 on every new
  route. All via a raw tokio TCP client on an ephemeral port (mirrors the
  existing `serves_page` test).
- Frontend: real-browser verification (Playwright) per phase - grouping +
  active + resize (phase 1); rename/pin/keep persist across reload via `/state`
  (phase 2); history list + open a past session (phase 3); export downloads +
  screenshot PNG (phase 4).
- Integration: extend the e2e to set `EXECKIT_MCP_AUDIT_DIR`, drive a couple of
  sessions, and assert `/sessions` lists them and `/session/<id>` serves one.

## Out of scope (future, if asked)

- `.html` / asciinema `.cast` export.
- Multi-user or cross-host shared state (the file is local).
- Search/filter within the transcript.
- Server-side render of export formats (export stays client-side).
