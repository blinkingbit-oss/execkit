# execkit-mcp Web Viewer UX Iteration - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the web viewer with a transport-grouped sidebar, per-session actions (rename/pin/keep/export/screenshot), server-persisted display metadata, and browsable session history.

**Architecture:** Mostly a `viewer.html` rewrite deriving from data the page already has (session ids encode transport + label). New backend: a small validated metadata store (`watch/meta.rs`) plus four routes added to the existing `watch/web.rs` server (`GET/POST /state`, `GET /sessions`, `GET /session/<id>`). The viewer gains exactly one narrow, validated, display-only write surface; everything stays loopback + token-gated.

**Tech Stack:** Rust, tokio (existing runtime), serde_json, the existing hand-rolled HTTP/SSE server. Frontend: vanilla HTML/CSS/JS (no external libraries), single self-contained `viewer.html` via `include_str!`.

## Global Constraints

- Bind `127.0.0.1` only; never `0.0.0.0`.
- Token required on EVERY endpoint including the new ones; missing/wrong token -> `403`. All responses send `Cache-Control: no-store`.
- The write surface (`POST /state`) writes exactly ONE fixed file (`~/.execkit/viewer-state.json`, mode 0600), with a validated shape and a hard size cap (262144 bytes); reject malformed/oversized with `400`. It is display-only and can never affect a session, execution, or the audit log.
- CSRF-safe: the token lives only in the URL/query (never a cookie); the page sends it as the `t=` query param on every fetch.
- `GET /session/<id>` validates the id against `^[0-9]+_[A-Za-z0-9@.:_-]+$` and resolves only a file within the configured audit dir; no `..`, no absolute paths.
- No external JS/CSS libraries; one self-contained `viewer.html` via `include_str!`.
- ASCII only in code, docs, and the page SOURCE (no em-dash/non-ASCII). UI affordances (accordion arrows, 3-dots, pin marker, active dot) are CSS-drawn or plain ASCII; never emoji/box-drawing glyphs in the HTML source. Verify with `grep -nP '[^\x00-\x7F]'` before each commit.
- No `unwrap`/`expect` that can panic on network input or operator values; `unwrap_or`/`unwrap_or_else`/`nth`/`find_map` are fine; mutex via `.lock().unwrap_or_else(|e| e.into_inner())`.
- Keep the existing TUI (`watch`), follow (`watch --follow`), `watch --serve`, auto-start, and live-SSE paths working unchanged.
- No Co-Authored-By trailers.
- Frontend+backend build, not pure TDD: backend uses unit tests via a raw tokio TCP client on an ephemeral port (mirror `serves_page` in `web.rs` and the harness in `tests/web_viewer.rs`); frontend uses real-browser (Playwright MCP) verification per phase.

---

## File Structure

- **Modify** `crates/execkit-mcp/src/watch/viewer.html` - the redesigned page (Phases 1, 2, 3, 4).
- **Create** `crates/execkit-mcp/src/watch/meta.rs` - the viewer-metadata store: shape, load/validate/save of `~/.execkit/viewer-state.json` (Phase 2). NOTE: do NOT name it `state.rs` - that module exists (the TUI `AppState`).
- **Modify** `crates/execkit-mcp/src/watch/mod.rs` - add `pub mod meta;` (Phase 2).
- **Modify** `crates/execkit-mcp/src/watch/web.rs` - method+body parsing, a small `Ctx`, and the new routes (Phases 2, 3).
- **Modify** `crates/execkit-mcp/src/paths.rs` - add `default_viewer_state_path()` (Phase 2).
- **Reused unchanged:** `watch/render.rs` (`render_event(&AuditEvent) -> Vec<StyledLine>`, `StyledLine { text: String, kind: LineKind }`), `watch/source.rs`/`tail.rs`/`dirtail.rs`, `audit.rs` (`AuditEvent`, `AuditEvent::session()`), `gen_token`, the SSE plumbing.

Backend interfaces introduced (referenced across tasks):
- `paths::default_viewer_state_path() -> PathBuf`
- `meta::ViewerState` (serde type), `meta::load(&Path) -> ViewerState`, `meta::save(&Path, &ViewerState) -> anyhow::Result<()>`, `meta::parse_validated(&[u8]) -> Result<ViewerState, String>`, `meta::MAX_STATE_BYTES: usize = 262144`
- In `web.rs`: `struct Ctx { backlog: Arc<Mutex<Vec<String>>>, tx: broadcast::Sender<String>, token: Arc<String>, audit: PathBuf, state_path: PathBuf }`; `handle_conn(sock, ctx: Arc<Ctx>)`.

---

## Phase 1 - Sidebar foundation (frontend only, no new endpoints)

### Task 1: Redesigned sidebar - grouping, labels, active highlight, resize, branding

**Files:**
- Modify: `crates/execkit-mcp/src/watch/viewer.html` (replace the page)

**Interfaces:**
- Consumes: the existing `/events` SSE stream (`{session, kind, text}` messages) and the existing `GET /?t=` page route - unchanged.
- Produces: no backend interface. A `parseId(id)` JS helper other tasks reuse: returns `{num, transport, label}` where for `1_local`->`{num:1,transport:"local",label:"local"}`, `2_ssh_etlrobot@web-01`->`{num:2,transport:"ssh",label:"etlrobot@web-01"}`, `3_docker_myapp`->`{num:3,transport:"docker",label:"myapp"}`.

- [ ] **Step 1: Write the id-parser and a DOM-free assertion harness inside the page is not practical; instead, implement then verify in a real browser.** Replace `crates/execkit-mcp/src/watch/viewer.html` with the redesigned page below. It keeps the live SSE wiring and read-only behavior, adds the branding header, the transport-grouped accordion sidebar with parsed labels, active highlight, and a resize handle.

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>execkit - live</title>
<style>
  :root { color-scheme: dark; --sidebar: 260px; }
  * { box-sizing: border-box; }
  body { margin: 0; height: 100vh; display: flex; flex-direction: column;
         font: 13px ui-monospace, Menlo, Consolas, monospace; background: #11141a; color: #c8ccd4; }
  header { padding: 8px 12px; background: #0b0d11; border-bottom: 1px solid #222; display: flex; align-items: baseline; gap: 10px; }
  header .brand { font-size: 20px; font-weight: 700; letter-spacing: 0.5px; color: #e6e9ef; }
  header .tag { color: #8a93a3; font-size: 12px; }
  .main { flex: 1; display: flex; min-height: 0; }
  #sidebar { width: var(--sidebar); min-width: 140px; max-width: 70vw; border-right: 1px solid #222; overflow-y: auto; flex-shrink: 0; }
  #resizer { width: 5px; cursor: col-resize; background: transparent; flex-shrink: 0; }
  #resizer:hover { background: #243044; }
  .pane { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  #title { padding: 6px 12px; border-bottom: 1px solid #222; color: #8a93a3; }
  #transcript { flex: 1; overflow-y: auto; padding: 8px 12px; white-space: pre-wrap; word-break: break-word; }
  .grp { user-select: none; }
  .grp > .ghdr { padding: 5px 10px; cursor: pointer; color: #8a93a3; display: flex; align-items: center; gap: 6px; }
  .grp > .ghdr:hover { background: #1a1f29; }
  .arrow { display: inline-block; width: 0; height: 0; border-left: 4px solid #8a93a3; border-top: 3px solid transparent; border-bottom: 3px solid transparent; transition: transform .1s; }
  .grp.open > .ghdr .arrow { transform: rotate(90deg); }
  .grp:not(.open) > .glist { display: none; }
  .srow { padding: 4px 10px 4px 22px; cursor: pointer; display: flex; align-items: center; gap: 6px; white-space: nowrap; }
  .srow:hover { background: #1a1f29; }
  .srow.sel { background: #243044; color: #fff; }
  .srow.closed { color: #6b7280; }
  .srow .lbl { overflow: hidden; text-overflow: ellipsis; flex: 1; }
  .srow .dot { width: 7px; height: 7px; border-radius: 50%; background: #98c379; flex-shrink: 0; visibility: hidden; }
  .srow.sel .dot { visibility: visible; }
  .ln { display: block; }
  .prompt { color: #56b6c2; font-weight: 600; }
  .stdout { color: #c8ccd4; }
  .stderr, .exit_err { color: #e06c75; }
  .exit_ok { color: #98c379; }
  .marker { color: #6b7280; }
</style>
</head>
<body>
<header><span class="brand">execkit</span><span class="tag">live - read-only shell transcript</span></header>
<div class="main">
  <div id="sidebar"></div>
  <div id="resizer"></div>
  <div class="pane">
    <div id="title">(no sessions yet)</div>
    <div id="transcript" aria-live="polite"></div>
  </div>
</div>
<script>
  const token = new URLSearchParams(location.search).get("t") || "";
  const sidebarEl = document.getElementById("sidebar");
  const titleEl = document.getElementById("title");
  const transcriptEl = document.getElementById("transcript");

  // session id -> { lines:[{kind,text}], closed:bool, transport, label }
  const sessions = new Map();
  const openGroups = new Set(["local","ssh","docker"]); // groups expanded by default
  let selected = null;

  function parseId(id) {
    // {num}_{transport}_{detail} ; local has no detail
    const m = String(id).match(/^(\d+)_([a-z]+)(?:_(.*))?$/);
    if (!m) return { num: 0, transport: "other", label: id };
    const transport = m[2];
    const label = transport === "local" ? "local" : (m[3] || transport);
    return { num: parseInt(m[1], 10), transport, label };
  }

  function setTitle() {
    const s = selected && sessions.get(selected);
    titleEl.textContent = selected ? (sessions.get(selected).label + (s.closed ? "  (closed)" : "  (active)")) : "(no sessions yet)";
  }

  function renderSidebar() {
    // group sessions by transport, preserving insertion order within a group
    const groups = new Map();
    for (const [id, s] of sessions) {
      if (!groups.has(s.transport)) groups.set(s.transport, []);
      groups.get(s.transport).push(id);
    }
    sidebarEl.textContent = "";
    for (const [transport, ids] of groups) {
      const grp = document.createElement("div");
      grp.className = "grp" + (openGroups.has(transport) ? " open" : "");
      const hdr = document.createElement("div");
      hdr.className = "ghdr";
      const arrow = document.createElement("span"); arrow.className = "arrow";
      const name = document.createElement("span"); name.textContent = transport + " (" + ids.length + ")";
      hdr.appendChild(arrow); hdr.appendChild(name);
      hdr.onclick = () => { if (openGroups.has(transport)) openGroups.delete(transport); else openGroups.add(transport); renderSidebar(); };
      grp.appendChild(hdr);
      const list = document.createElement("div"); list.className = "glist";
      for (const id of ids) {
        const s = sessions.get(id);
        const row = document.createElement("div");
        row.className = "srow" + (id === selected ? " sel" : "") + (s.closed ? " closed" : "");
        row.title = id;
        const dot = document.createElement("span"); dot.className = "dot";
        const lbl = document.createElement("span"); lbl.className = "lbl"; lbl.textContent = s.label + " (" + s.lines.length + ")";
        row.appendChild(dot); row.appendChild(lbl);
        row.onclick = () => { selected = id; renderAll(); };
        list.appendChild(row);
      }
      grp.appendChild(list);
      sidebarEl.appendChild(grp);
    }
  }

  function atBottom() { return transcriptEl.scrollHeight - transcriptEl.scrollTop - transcriptEl.clientHeight < 24; }

  function renderTranscript() {
    const s = selected && sessions.get(selected);
    setTitle();
    transcriptEl.textContent = "";
    if (!s) return;
    for (const l of s.lines) {
      const span = document.createElement("span"); span.className = "ln " + l.kind; span.textContent = l.text;
      transcriptEl.appendChild(span);
    }
  }

  function renderAll() { renderSidebar(); renderTranscript(); }

  function ingest(m) {
    let s = sessions.get(m.session);
    if (!s) { const p = parseId(m.session); s = { lines: [], closed: false, transport: p.transport, label: p.label }; sessions.set(m.session, s); if (!selected) selected = m.session; }
    if (m.kind === "marker" && m.text.startsWith("-- closed")) s.closed = true;
    if (m.kind === "marker" && m.text.startsWith("-- opened")) s.closed = false;
    s.lines.push({ kind: m.kind, text: m.text });
    if (m.session === selected) {
      setTitle();
      const stick = atBottom();
      const span = document.createElement("span"); span.className = "ln " + m.kind; span.textContent = m.text;
      transcriptEl.appendChild(span);
      if (stick) transcriptEl.scrollTop = transcriptEl.scrollHeight;
    }
    renderSidebar();
  }

  // Resizable sidebar (ephemeral in phase 1; persisted via /state in phase 2).
  (function () {
    const rz = document.getElementById("resizer");
    let dragging = false;
    rz.addEventListener("mousedown", () => { dragging = true; document.body.style.userSelect = "none"; });
    window.addEventListener("mousemove", (e) => { if (!dragging) return; const w = Math.max(140, Math.min(e.clientX, window.innerWidth * 0.7)); document.documentElement.style.setProperty("--sidebar", w + "px"); });
    window.addEventListener("mouseup", () => { dragging = false; document.body.style.userSelect = ""; });
  })();

  const es = new EventSource("/events?t=" + encodeURIComponent(token));
  es.onopen = () => { sessions.clear(); selected = null; transcriptEl.textContent = ""; sidebarEl.textContent = ""; setTitle(); };
  es.onmessage = (e) => { try { ingest(JSON.parse(e.data)); } catch (_) {} };
  es.onerror = () => { if (!titleEl.textContent.includes("[disconnected]")) titleEl.textContent += "  [disconnected]"; };
</script>
</body>
</html>
```

- [ ] **Step 2: Build and confirm the server test still passes**

Run: `cargo test -p execkit-mcp --lib watch::web::tests::serves_page`
Expected: PASS (the page is still served as `text/html` and contains `/events?t=`).

- [ ] **Step 3: Typography check**

Run: `grep -nP '[^\x00-\x7F]' crates/execkit-mcp/src/watch/viewer.html`
Expected: NO output. (If the `rз`/`rез` artifact remains, fix it.)

- [ ] **Step 4: Real-browser verification (Playwright)**

Seed a multi-transport audit log and serve it, then drive the page in a real browser:
- Write `/tmp/ek-ux-audit.jsonl` with Open+Exec events for three sessions: `1_local`, `2_ssh_etlrobot@web-01`, `3_docker_myapp` (each an `open` then an `exec` with some stdout and an exit).
- Start: `cargo run -q -p execkit-mcp -- watch --serve /tmp/ek-ux-audit.jsonl &`; read the printed `http://127.0.0.1:PORT/?t=TOKEN` from stderr.
- With the Playwright MCP tools (`browser_navigate`, `browser_snapshot`, `browser_click`): confirm the header shows a large "execkit"; the sidebar has three accordion groups `local (1)`, `ssh (1)`, `docker (1)`; the ssh row shows label `etlrobot@web-01`, the docker row `myapp`, local `local`; clicking a group header collapses/expands it; clicking a session selects it (active dot + highlight) and shows its transcript; dragging `#resizer` widens the sidebar.
- Stop the server, remove the temp file and any `.playwright-mcp/` artifacts. Record the snapshot outcome in the task report.

- [ ] **Step 5: Commit**

```bash
git add crates/execkit-mcp/src/watch/viewer.html
git commit -m "feat(mcp): viewer sidebar redesign - transport groups, labels, active, resize, branding"
```

---

## Phase 2 - Server metadata store + rename/pin/keep

### Task 2: `default_viewer_state_path` + the `meta` store (validated, capped, 0600)

**Files:**
- Modify: `crates/execkit-mcp/src/paths.rs` (add the path helper + test)
- Create: `crates/execkit-mcp/src/watch/meta.rs`
- Modify: `crates/execkit-mcp/src/watch/mod.rs` (add `pub mod meta;` after `pub mod web;`)

**Interfaces:**
- Produces: `paths::default_viewer_state_path() -> PathBuf`; `meta::ViewerState`; `meta::MAX_STATE_BYTES`; `meta::parse_validated(&[u8]) -> Result<ViewerState, String>`; `meta::load(&Path) -> ViewerState`; `meta::save(&Path, &ViewerState) -> anyhow::Result<()>`.

- [ ] **Step 1: Add the path helper + test**

In `crates/execkit-mcp/src/paths.rs`, add:

```rust
/// Viewer display-metadata file (aliases/pins/keeps/ui), written by POST /state.
pub fn default_viewer_state_path() -> PathBuf {
    home_dir().join(".execkit").join("viewer-state.json")
}
```

Add to its `tests` module:

```rust
    #[test]
    fn default_viewer_state_path_is_under_home() {
        let p = default_viewer_state_path();
        assert!(p.is_absolute());
        assert_eq!(p, home_dir().join(".execkit").join("viewer-state.json"));
    }
```

Run: `cargo test -p execkit-mcp --lib paths` -> pass.

- [ ] **Step 2: Write the failing meta tests**

Create `crates/execkit-mcp/src/watch/meta.rs` with only the tests first (so they fail to compile), then implement in Step 3. Final file (tests + impl):

```rust
// SPDX-License-Identifier: Apache-2.0
//! The viewer's display-only metadata store: aliases, pins, keeps, and UI prefs
//! the page persists via POST /state. This is the ONLY thing the viewer writes.
//! It never affects a session, execution, or the audit log. One fixed file.
use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Hard cap on an accepted /state body. Rejects oversized writes.
pub const MAX_STATE_BYTES: usize = 262144;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pinned: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keep: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UiPrefs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidebar_width: Option<u32>,
}

// NOTE: do NOT use `#[serde(flatten)]` for `sessions` - flatten is incompatible
// with `deny_unknown_fields`. Keep `sessions` an explicit field. The JSON shape
// is `{ "sessions": { "<id>": {...} }, "ui": {...} }`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewerState {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sessions: BTreeMap<String, SessionMeta>,
    #[serde(default, skip_serializing_if = "is_default_ui")]
    pub ui: UiPrefs,
}

fn is_default_ui(u: &UiPrefs) -> bool {
    *u == UiPrefs::default()
}

/// Parse + validate an incoming /state body. Enforces the size cap, JSON shape,
/// and per-field caps. Returns the validated state or a short error string.
pub fn parse_validated(body: &[u8]) -> Result<ViewerState, String> {
    if body.len() > MAX_STATE_BYTES {
        return Err(format!("state too large ({} > {})", body.len(), MAX_STATE_BYTES));
    }
    let mut st: ViewerState =
        serde_json::from_slice(body).map_err(|e| format!("invalid state json: {e}"))?;
    // Cap alias length; drop empty aliases. Session ids are arbitrary strings
    // (display keys only) but bounded by the overall size cap.
    for m in st.sessions.values_mut() {
        if let Some(a) = &m.alias {
            if a.is_empty() {
                m.alias = None;
            } else if a.len() > 200 {
                return Err("alias too long".into());
            }
        }
    }
    if let Some(w) = st.ui.sidebar_width {
        if !(120..=2000).contains(&w) {
            return Err("sidebar_width out of range".into());
        }
    }
    Ok(st)
}

/// Read the state file, returning a default (empty) state if it is missing or
/// unreadable - the viewer must still work without prior metadata.
pub fn load(path: &Path) -> ViewerState {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
        Err(_) => ViewerState::default(),
    }
}

/// Write the state file atomically-ish, mode 0600 on unix (created restricted
/// from the first byte). The parent dir is created if absent.
pub fn save(path: &Path, st: &ViewerState) -> anyhow::Result<()> {
    let body = serde_json::to_vec_pretty(st).context("serializing viewer state")?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("writing {}", path.display()))?;
        f.write_all(&body)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &body).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trips_a_valid_state() {
        let body = br#"{"sessions":{"1_local":{"alias":"build","pinned":true}},"ui":{"sidebar_width":320}}"#;
        let st = parse_validated(body).unwrap();
        assert_eq!(st.sessions["1_local"].alias.as_deref(), Some("build"));
        assert!(st.sessions["1_local"].pinned);
        assert_eq!(st.ui.sidebar_width, Some(320));
    }

    #[test]
    fn rejects_oversized_body() {
        let big = vec![b'x'; MAX_STATE_BYTES + 1];
        assert!(parse_validated(&big).is_err());
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(parse_validated(b"{ not json").is_err());
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        // deny_unknown_fields guards against typo'd / injected keys at the top.
        assert!(parse_validated(br#"{"sessions":{},"evil":1}"#).is_err());
    }

    #[test]
    fn rejects_out_of_range_width() {
        assert!(parse_validated(br#"{"ui":{"sidebar_width":99999}}"#).is_err());
    }

    #[test]
    fn save_then_load_round_trips_and_is_0600() {
        let p = std::env::temp_dir().join(format!("ek_meta_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let mut st = ViewerState::default();
        st.sessions.insert("2_ssh_u@h".into(), SessionMeta { alias: Some("db".into()), pinned: false, keep: true });
        save(&p, &st).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "state file must be 0600");
        }
        let back = load(&p);
        assert_eq!(back, st);
        let _ = std::fs::remove_file(&p);
    }
}
```

(The page's JSON shape is `{ "sessions": { "<id>": {alias?,pinned?,keep?} }, "ui": { "sidebar_width"? } }`; Task 4's fetch payloads use this shape.)

- [ ] **Step 3: Declare the module + run the tests**

Add `pub mod meta;` to `crates/execkit-mcp/src/watch/mod.rs` after `pub mod web;`.
Run: `cargo test -p execkit-mcp --lib watch::meta` -> all pass.
Run: `cargo clippy -p execkit-mcp --all-targets -- -D warnings` -> clean.
Run: `grep -nP '[^\x00-\x7F]' crates/execkit-mcp/src/watch/meta.rs crates/execkit-mcp/src/paths.rs` -> empty.

- [ ] **Step 4: Commit**

```bash
git add crates/execkit-mcp/src/watch/meta.rs crates/execkit-mcp/src/watch/mod.rs crates/execkit-mcp/src/paths.rs
git commit -m "feat(mcp): viewer metadata store (validated, capped, 0600 display-only state)"
```

### Task 3: `GET/POST /state` routes (method+body parsing, Ctx, token, no-store)

**Files:**
- Modify: `crates/execkit-mcp/src/watch/web.rs`

**Interfaces:**
- Consumes: `meta::{ViewerState, parse_validated, load, save, MAX_STATE_BYTES}`, `paths::default_viewer_state_path`.
- Produces: a `Ctx` struct + a method-aware `handle_conn`; later tasks add routes to the same `match`.

- [ ] **Step 1: Introduce `Ctx`, parse method+body, thread the audit + state paths**

In `web.rs`, add imports: `use crate::watch::meta;`. Define the context and change `serve` to build it and clone the audit `path` into it:

```rust
struct Ctx {
    backlog: Arc<Mutex<Vec<String>>>,
    tx: broadcast::Sender<String>,
    token: Arc<String>,
    audit: PathBuf,
    state_path: PathBuf,
}
```

In `serve`, after computing `backlog`/`tx`/`token` and BEFORE the accept loop, build:

```rust
    let ctx = Arc::new(Ctx {
        backlog: backlog.clone(),
        tx: tx.clone(),
        token: token.clone(),
        audit: path_for_routes,   // a clone of `path` taken before it is moved into the poller
        state_path: crate::paths::default_viewer_state_path(),
    });
```

To get `path_for_routes`, clone `path` before it is moved into the poller closure (`let path_for_routes = path.clone();` right after `serve` binds, and move the original into the poller as today). Change the accept loop to spawn `handle_conn(sock, ctx.clone())`.

Rewrite `handle_conn` to parse the method and (for POST) the body, then route. Replace its signature and body with:

```rust
async fn handle_conn(mut sock: TcpStream, ctx: Arc<Ctx>) -> std::io::Result<()> {
    // Read the request head; capture how many header bytes precede the body.
    let mut buf = vec![0u8; 8192];
    let mut n = 0;
    let mut head_end = None;
    loop {
        let r = sock.read(&mut buf[n..]).await?;
        if r == 0 { return Ok(()); }
        n += r;
        if let Some(p) = find_subslice(&buf[..n], b"\r\n\r\n") { head_end = Some(p + 4); break; }
        if n == buf.len() { break; }
    }
    let head = String::from_utf8_lossy(&buf[..head_end.unwrap_or(n)]).to_string();
    let first = head.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let supplied = query.split('&').find_map(|kv| kv.strip_prefix("t=")).unwrap_or("");
    if supplied != ctx.token.as_str() {
        return write_simple(&mut sock, "403 Forbidden", "text/plain", b"403 forbidden\n").await;
    }

    match (method, path) {
        ("GET", "/") => write_simple(&mut sock, "200 OK", "text/html; charset=utf-8", PAGE.as_bytes()).await,
        ("GET", "/events") => stream_events(sock, ctx.backlog.clone(), ctx.tx.clone()).await,
        ("GET", "/state") => {
            let body = serde_json::to_vec(&meta::load(&ctx.state_path)).unwrap_or_else(|_| b"{}".to_vec());
            write_simple(&mut sock, "200 OK", "application/json", &body).await
        }
        ("POST", "/state") => handle_post_state(&mut sock, &ctx, &head, &buf[..n], head_end).await,
        _ => write_simple(&mut sock, "404 Not Found", "text/plain", b"404 not found\n").await,
    }
}

/// Find the start index of `needle` in `hay`.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
```

Add the POST handler (reads Content-Length bytes, validates, saves; 400 on bad body, 413-ish via 400 on oversize):

```rust
async fn handle_post_state(
    sock: &mut TcpStream,
    ctx: &Ctx,
    head: &str,
    already: &[u8],
    head_end: Option<usize>,
) -> std::io::Result<()> {
    let len: usize = head
        .lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string()))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if len > meta::MAX_STATE_BYTES {
        return write_simple(sock, "400 Bad Request", "text/plain", b"state too large\n").await;
    }
    let mut body = Vec::with_capacity(len);
    if let Some(he) = head_end {
        body.extend_from_slice(&already[he..]); // bytes already read past the header
    }
    while body.len() < len {
        let mut chunk = [0u8; 4096];
        let r = sock.read(&mut chunk).await?;
        if r == 0 { break; }
        body.extend_from_slice(&chunk[..r]);
        if body.len() > meta::MAX_STATE_BYTES { break; }
    }
    match meta::parse_validated(&body) {
        Ok(st) => match meta::save(&ctx.state_path, &st) {
            Ok(()) => write_simple(sock, "200 OK", "application/json", b"{\"ok\":true}").await,
            Err(_) => write_simple(sock, "500 Internal Server Error", "text/plain", b"save failed\n").await,
        },
        Err(e) => write_simple(sock, "400 Bad Request", "text/plain", format!("{e}\n").as_bytes()).await,
    }
}
```

Update the existing `serves_page` test call sites if needed (they use `serve(path, token, 0)` - unchanged). The `_ => 404` arm and the old `match path` are replaced by the `match (method, path)`.

- [ ] **Step 2: Write the `/state` round-trip + reject tests**

Add to `web.rs` `tests` (reuse the `http_get`/`seed_audit` helpers; add an `http_post`):

```rust
    async fn http_post(addr: std::net::SocketAddr, target: &str, body: &str) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!("POST {target} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        s.write_all(req.as_bytes()).await.unwrap();
        let mut b = vec![0u8; 4096];
        let n = tokio::time::timeout(std::time::Duration::from_millis(500), s.read(&mut b)).await.map(|r| r.unwrap_or(0)).unwrap_or(0);
        String::from_utf8_lossy(&b[..n]).to_string()
    }

    #[tokio::test]
    async fn state_get_post_round_trip_and_token_and_validation() {
        // Isolate the state file by pointing HOME at a temp dir.
        let home = std::env::temp_dir().join(format!("ek_uxhome_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&home);
        std::env::set_var("HOME", &home);
        let path = seed_audit();
        let token = "tok".to_string();
        let (addr, _h) = serve(path.clone(), token.clone(), 0).await.unwrap();

        // no token -> 403 on both methods
        assert!(http_get(addr, "/state", 300).await.starts_with("HTTP/1.1 403"));
        assert!(http_post(addr, "/state", "{}").await.starts_with("HTTP/1.1 403"));

        // valid POST persists; GET returns it
        let ok = http_post(addr, &format!("/state?t={token}"), r#"{"sessions":{"1_local":{"alias":"build"}}}"#).await;
        assert!(ok.starts_with("HTTP/1.1 200"), "post: {ok}");
        let got = http_get(addr, &format!("/state?t={token}"), 300).await;
        assert!(got.contains("\"alias\":\"build\""), "get: {got}");

        // malformed -> 400
        let bad = http_post(addr, &format!("/state?t={token}"), "{ not json").await;
        assert!(bad.starts_with("HTTP/1.1 400"), "bad: {bad}");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&home);
    }
```

- [ ] **Step 3: Run + lint + typography**

Run: `cargo test -p execkit-mcp --lib watch::web` -> all pass (existing + new).
Run: `cargo clippy -p execkit-mcp --all-targets -- -D warnings` -> clean.
Run: `grep -nP '[^\x00-\x7F]' crates/execkit-mcp/src/watch/web.rs` -> empty.
Run: `cargo test -p execkit-mcp --test web_viewer` -> the auto-start e2e still passes (serve signature unchanged).

- [ ] **Step 4: Commit**

```bash
git add crates/execkit-mcp/src/watch/web.rs
git commit -m "feat(mcp): GET/POST /state route - token-gated, validated, no-store"
```

### Task 4: 3-dots menu + rename/pin/keep + persisted width (viewer.html + /state)

**Files:**
- Modify: `crates/execkit-mcp/src/watch/viewer.html`

**Interfaces:**
- Consumes: `GET /state` (load on start), `POST /state` (on change). Payload shape `{ "sessions": { "<id>": {alias?,pinned?,keep?} }, "ui": { "sidebar_width"? } }`.

- [ ] **Step 1: Add the metadata layer + overflow menu**

Extend `viewer.html`:
- Add a module-level `let meta = { sessions: {}, ui: {} };` and `async function loadMeta() { try { const r = await fetch("/state?t=" + encodeURIComponent(token)); meta = await r.json(); } catch (_) {} }` and `function saveMeta() { fetch("/state?t=" + encodeURIComponent(token), { method: "POST", body: JSON.stringify(meta) }).catch(() => {}); }`.
- Call `await loadMeta()` before opening the EventSource; apply `meta.ui.sidebar_width` to `--sidebar` on load; in the resizer `mouseup`, set `meta.ui = {sidebar_width: <w>}` and `saveMeta()`.
- In `renderSidebar`, for each session compute `const md = (meta.sessions||{})[id] || {}`; the displayed label uses `md.alias || s.label`; pinned sessions (`md.pinned`) sort to the top of their group; add a kept marker if `md.keep`.
- Add a 3-dots button (CSS-drawn, e.g. a `.dots` span styled as three stacked ASCII dots via text `...` rotated, or three `<i>` dots) to each `.srow`; clicking it opens a small absolutely-positioned menu with: Rename, Pin/Unpin, Keep/Unkeep (Export/Screenshot are added in Phase 4). Each action mutates `meta.sessions[id]` and calls `saveMeta()` then `renderSidebar()`. Rename uses `prompt("New name", md.alias || s.label)`; empty input clears the alias.
- Ensure aliases render via `textContent` only (never innerHTML).

Keep all affordances ASCII/CSS-drawn (no glyphs in source).

- [ ] **Step 2: Server test still green + typography**

Run: `cargo test -p execkit-mcp --lib watch::web::tests::serves_page` -> PASS.
Run: `grep -nP '[^\x00-\x7F]' crates/execkit-mcp/src/watch/viewer.html` -> empty.

- [ ] **Step 3: Real-browser verification (Playwright)**

Serve the seeded multi-transport log (as Task 1). In the browser: open the 3-dots menu on the `ssh` session; Rename it to "db-primary" - confirm the sidebar label updates; reload the page (`browser_navigate` to the same URL) and confirm the alias PERSISTS (proves `/state` round-trip). Pin the `local` session - confirm it moves to the top of its group and persists on reload. Resize the sidebar, reload, confirm the width persists. Record the outcome. Clean up temp files + `.playwright-mcp/`.

- [ ] **Step 4: Commit**

```bash
git add crates/execkit-mcp/src/watch/viewer.html
git commit -m "feat(mcp): viewer 3-dots menu - rename/pin/keep + persisted sidebar width"
```

---

## Phase 3 - History (past sessions)

### Task 5: `GET /sessions` + `GET /session/<id>` (enumerate dir, id-validate, no traversal)

**Files:**
- Modify: `crates/execkit-mcp/src/watch/web.rs`

**Interfaces:**
- Consumes: `ctx.audit` (the audit path; dir mode required for history), `render_event`, `AuditEvent`.
- Produces: `GET /sessions` -> `[{id,label,transport,started_ms,size}]`; `GET /session/<id>` -> `[{session,kind,text}]`.

- [ ] **Step 1: Implement the routes**

Add to the `match (method, path)` in `handle_conn`:

```rust
        ("GET", "/sessions") => {
            let body = serde_json::to_vec(&list_sessions(&ctx.audit)).unwrap_or_else(|_| b"[]".to_vec());
            write_simple(&mut sock, "200 OK", "application/json", &body).await
        }
        ("GET", p) if p.starts_with("/session/") => {
            let id = &p["/session/".len()..];
            match session_transcript(&ctx.audit, id) {
                Some(body) => write_simple(&mut sock, "200 OK", "application/json", &body).await,
                None => write_simple(&mut sock, "404 Not Found", "text/plain", b"no such session\n").await,
            }
        }
```

Add the helpers. Session files are named `<id>-<open_ms>.jsonl` (see `AuditSink::PerSession`):

```rust
use serde::Serialize as _;

fn id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_alphanumeric() || matches!(b, b'@' | b'.' | b':' | b'_' | b'-')
                || (b == b'_') || (i > 0 && b.is_ascii_digit())
        })
        && id.as_bytes()[0].is_ascii_digit()
}

#[derive(serde::Serialize)]
struct SessionInfo { id: String, label: String, transport: String, started_ms: u64, size: u64 }

/// List past session files in the audit dir (dir mode). Empty if `audit` is not
/// a directory (single-file mode has no per-session history).
fn list_sessions(audit: &Path) -> Vec<SessionInfo> {
    let mut out = Vec::new();
    if !audit.is_dir() { return out; }
    let rd = match std::fs::read_dir(audit) { Ok(r) => r, Err(_) => return out };
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().to_string();
        // <id>-<open_ms>.jsonl
        let stem = match name.strip_suffix(".jsonl") { Some(s) => s, None => continue };
        let (id, ts) = match stem.rsplit_once('-') { Some(x) => x, None => continue };
        if !id_ok(id) { continue; }
        let started_ms = ts.parse().unwrap_or(0);
        let size = ent.metadata().map(|m| m.len()).unwrap_or(0);
        let (transport, label) = split_label(id);
        out.push(SessionInfo { id: id.to_string(), label, transport, started_ms, size });
    }
    out.sort_by(|a, b| b.started_ms.cmp(&a.started_ms)); // newest first
    out
}

/// Parse transport + friendly label out of an id like `2_ssh_u@h` / `1_local`.
fn split_label(id: &str) -> (String, String) {
    let rest = id.splitn(2, '_').nth(1).unwrap_or(""); // after the number
    let mut it = rest.splitn(2, '_');
    let transport = it.next().unwrap_or("other").to_string();
    let label = if transport == "local" { "local".to_string() } else { it.next().unwrap_or(&transport).to_string() };
    (transport, label)
}

/// Render one past session's transcript. Id is validated and resolved ONLY
/// within `audit`; no traversal. None if missing/invalid.
fn session_transcript(audit: &Path, id: &str) -> Option<Vec<u8>> {
    if !audit.is_dir() || !id_ok(id) { return None; }
    // find the file `<id>-<ts>.jsonl` in the dir (do not build a path from the id)
    let rd = std::fs::read_dir(audit).ok()?;
    let mut found: Option<std::path::PathBuf> = None;
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().to_string();
        if name.strip_suffix(".jsonl").and_then(|s| s.rsplit_once('-')).map(|(i, _)| i) == Some(id) {
            found = Some(ent.path());
            break;
        }
    }
    let file = found?;
    let text = std::fs::read_to_string(&file).ok()?;
    let mut lines = Vec::new();
    for l in text.lines() {
        if let Ok(ev) = serde_json::from_str::<crate::audit::AuditEvent>(l) {
            let session = ev.session().to_string();
            for sl in render_event(&ev) {
                // reuse the same wire shape as live
                lines.push(serde_json::json!({"session": session, "kind": kind_str(sl.kind), "text": sl.text}));
            }
        }
    }
    serde_json::to_vec(&lines).ok()
}
```

(Note: `id_ok` rejects `..`, `/`, and absolute paths by character allowlist; resolution scans the dir rather than joining the id, so traversal is impossible.)

- [ ] **Step 2: Tests - listing, transcript, and traversal rejection**

Add to `web.rs` `tests`:

```rust
    #[tokio::test]
    async fn sessions_list_and_transcript_and_reject_traversal() {
        // dir-mode audit with two per-session files
        let dir = std::env::temp_dir().join(format!("ek_uxdir_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("1_local-100.jsonl"),
            "{\"event\":\"open\",\"ts\":100,\"session\":\"1_local\",\"transport\":\"local\"}\n{\"event\":\"exec\",\"ts\":101,\"session\":\"1_local\",\"transport\":\"local\",\"command\":\"echo hi\",\"stdout\":\"hi\",\"stderr\":\"\",\"exit_code\":0,\"duration_ms\":3,\"cwd\":\"/tmp\",\"truncated\":false}\n").unwrap();
        std::fs::write(dir.join("2_ssh_u@h-200.jsonl"),
            "{\"event\":\"open\",\"ts\":200,\"session\":\"2_ssh_u@h\",\"transport\":\"ssh\"}\n").unwrap();
        let token = "tok".to_string();
        let (addr, _h) = serve(dir.clone(), token.clone(), 0).await.unwrap();

        let list = http_get(addr, &format!("/sessions?t={token}"), 400).await;
        assert!(list.contains("\"id\":\"2_ssh_u@h\"") && list.contains("\"transport\":\"ssh\""), "list: {list}");
        assert!(list.contains("\"label\":\"u@h\""), "label: {list}");

        let tr = http_get(addr, &format!("/session/1_local?t={token}"), 400).await;
        assert!(tr.contains("/tmp $ echo hi"), "transcript: {tr}");

        // traversal / bad id -> 404 (id_ok rejects it; nothing served)
        let trav = http_get(addr, &format!("/session/../../etc/passwd?t={token}"), 400).await;
        assert!(trav.contains("404"), "traversal must 404: {trav}");

        let _ = std::fs::remove_dir_all(&dir);
    }
```

- [ ] **Step 3: Run + lint + typography**

Run: `cargo test -p execkit-mcp --lib watch::web` -> all pass.
Run: `cargo clippy -p execkit-mcp --all-targets -- -D warnings` -> clean.
Run: `grep -nP '[^\x00-\x7F]' crates/execkit-mcp/src/watch/web.rs` -> empty.

- [ ] **Step 4: Commit**

```bash
git add crates/execkit-mcp/src/watch/web.rs
git commit -m "feat(mcp): GET /sessions + /session/<id> - dir history, id-validated, no traversal"
```

### Task 6: History panel (viewer.html)

**Files:**
- Modify: `crates/execkit-mcp/src/watch/viewer.html`

- [ ] **Step 1: Add the history section**

Extend `viewer.html`:
- After the live groups, render a "History" section. On load, `fetch("/sessions?t=...")`; show the newest `N = 20` entries (kept ones - `meta.sessions[id].keep` - are always shown even past N; pinned surface to the top). Each entry shows `md.alias || label` and a relative time from `started_ms`.
- Clicking a history entry calls `fetch("/session/<id>?t=...")`, loads the returned `[{session,kind,text}]` into a read-only transcript view (set `selected` to a synthetic "history:<id>" view or render directly into the transcript pane with the title showing the label + "(history)"). Live sessions remain selectable separately.
- The history list does not auto-update; add a small "refresh" affordance (re-fetch `/sessions`).

- [ ] **Step 2: Server test green + typography**, then **Step 3: Playwright** (serve a DIR-mode audit: set `EXECKIT_MCP_AUDIT_DIR` to a temp dir with two `<id>-<ts>.jsonl` files, run `watch --serve <dir>`; confirm the History section lists both, clicking one shows its transcript read-only), then **Step 4: Commit**.

```bash
git add crates/execkit-mcp/src/watch/viewer.html
git commit -m "feat(mcp): viewer history panel - browse past sessions from the audit dir"
```

---

## Phase 4 - Export + screenshot (frontend only)

### Task 7: Export a session (.txt/.log/.md/.json)

**Files:**
- Modify: `crates/execkit-mcp/src/watch/viewer.html`

- [ ] **Step 1: Add export actions to the 3-dots menu**

Add an "Export" submenu (txt, log, md, json) to the per-session menu. Build the content from the selected session's `lines` (live) or the loaded history transcript:
- `txt`/`log`: join `lines.map(l => l.text)` with `\n`.
- `md`: a header line `# <label> - <id>` plus a fenced block:
  ```
  function toMd(label, id, lines) { return "# " + label + " - " + id + "\n\n```text\n" + lines.map(l => l.text).join("\n") + "\n```\n"; }
  ```
- `json`: `JSON.stringify(lines, null, 2)`.
Trigger a download via a Blob + a temporary `<a download>`:
```js
function download(name, mime, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: mime }));
  a.download = name; a.click(); URL.revokeObjectURL(a.href);
}
```
File name: `<id>.<ext>`.

- [ ] **Step 2: typography + serves_page green**, **Step 3: Playwright** (click Export > md; confirm a download is triggered - assert via `browser_evaluate` that clicking creates an object URL / or that a download event fires; at minimum confirm the menu wiring and that `toMd` output contains the fenced block), **Step 4: Commit**.

```bash
git add crates/execkit-mcp/src/watch/viewer.html
git commit -m "feat(mcp): viewer session export - txt/log/md/json"
```

### Task 8: Screenshot a session (canvas -> PNG)

**Files:**
- Modify: `crates/execkit-mcp/src/watch/viewer.html`

- [ ] **Step 1: Add a Screenshot action**

Add "Screenshot" to the per-session menu. Render the selected session's transcript to a `<canvas>` and download a PNG:
```js
function screenshot(id, label, lines) {
  const pad = 12, lh = 18, cw = 7.8, font = "13px ui-monospace, Menlo, Consolas, monospace";
  const colors = { prompt: "#56b6c2", stdout: "#c8ccd4", stderr: "#e06c75", exit_ok: "#98c379", exit_err: "#e06c75", marker: "#6b7280" };
  const maxLen = lines.reduce((m, l) => Math.max(m, l.text.length), label.length + 4);
  const cv = document.createElement("canvas");
  cv.width = Math.ceil(pad * 2 + maxLen * cw);
  cv.height = pad * 2 + lh * (lines.length + 1);
  const x = cv.getContext("2d");
  x.fillStyle = "#11141a"; x.fillRect(0, 0, cv.width, cv.height);
  x.font = font; x.textBaseline = "top";
  x.fillStyle = "#e6e9ef"; x.fillText(label + "  (" + id + ")", pad, pad);
  lines.forEach((l, i) => { x.fillStyle = colors[l.kind] || "#c8ccd4"; x.fillText(l.text, pad, pad + lh * (i + 1)); });
  cv.toBlob((b) => { const a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = id + ".png"; a.click(); URL.revokeObjectURL(a.href); });
}
```

- [ ] **Step 2: typography + serves_page green**, **Step 3: Playwright** (click Screenshot; via `browser_evaluate` confirm a canvas is produced with non-zero dimensions and `toBlob` yields a PNG; verify no exceptions), **Step 4: Commit**.

```bash
git add crates/execkit-mcp/src/watch/viewer.html
git commit -m "feat(mcp): viewer session screenshot - canvas to PNG"
```

---

## Final integration

- [ ] Update `crates/execkit-mcp/README.md`: note that the viewer now persists display metadata to `~/.execkit/viewer-state.json` (0600, display-only) and that history requires `EXECKIT_MCP_AUDIT_DIR`. ASCII only. Commit.
- [ ] Full gate: `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test -p execkit-mcp`; `grep -nP '[^\x00-\x7F]'` over all changed files. All green.

---

## Self-Review Notes (for the executor)

- **Spec coverage:** Phase 1 (sidebar group/label/active/resize/branding) = Task 1. Server state + security (validated/capped/0600/display-only) = Tasks 2-3. Rename/pin/keep + persisted width = Task 4. History endpoints (id-validated, no traversal) = Task 5; history UI = Task 6. Export = Task 7; screenshot = Task 8. README + final gate = Final integration.
- **Naming:** the new module is `watch/meta.rs` (NOT `state.rs`, which already holds the TUI `AppState`).
- **State JSON shape:** `{ "sessions": { "<id>": {alias?,pinned?,keep?} }, "ui": { "sidebar_width"? } }` - consistent between `meta.rs`, the `/state` tests, and the page (Task 4 fetch payloads). `flatten` is NOT used (incompatible with `deny_unknown_fields`).
- **Security invariants in code:** loopback bind unchanged; token checked before routing for every method/path; `/state` POST validated + size-capped + 0600 + fixed path; `/session/<id>` resolves by scanning the dir (never joins the id into a path) and rejects non-allowlisted ids; all responses carry `Cache-Control: no-store` via `write_simple` and the SSE header.
- **No-panic:** request/method/body parsing uses `unwrap_or`/`find_map`/`position`; mutex via the existing `lock()` helper; meta load tolerates missing/corrupt files.
- **ASCII:** one deliberate trap is called out in Task 1 (the `rез` artifact) - the implementer must fix it; every task ends with the ASCII grep.
