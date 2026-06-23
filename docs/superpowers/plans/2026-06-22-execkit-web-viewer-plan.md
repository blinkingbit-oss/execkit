# execkit-mcp Live Web Viewer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A read-only, real-time web viewer for execkit-mcp's shell transcript that the MCP server can auto-open in the user's browser, plus a `watch --serve` subcommand to browser-view any audit log.

**Architecture:** A thin new layer over the existing `watch` stack. A hand-rolled HTTP/SSE server (on the tokio runtime already in the tree) tails the audit file through the existing `Source`/`Tailer`, renders each event with the existing `render_event`, and streams the rendered lines as JSON over Server-Sent Events to a self-contained HTML page. New code is `watch/web.rs` + `watch/viewer.html` + wiring; everything else is reused.

**Tech Stack:** Rust, tokio (`net`, `sync::broadcast`, `time`), `serde_json`, `getrandom` (new, token), `include_str!` for the page. No HTTP framework. Frontend is vanilla HTML/CSS/JS using `EventSource`.

## Global Constraints

- ASCII only in code, docs, and help text. No em-dash or non-ASCII typography (ASCII hyphen only). Verify with `grep -nP '[^\x00-\x7F]'` over changed files before each commit.
- Bind `127.0.0.1` only. Never `0.0.0.0`.
- Read-only by construction: no endpoint mutates any state; the server only reads the audit stream and serves a static page.
- No `unwrap`/`expect` that can panic on network input or operator-controlled values. `unwrap_or`/`unwrap_or_else`/`unwrap_or_default` (non-panicking) are fine. Recover poisoned mutexes with `.lock().unwrap_or_else(|e| e.into_inner())`.
- Keep the existing TUI (`watch`) and follow (`watch --follow`) paths working unchanged.
- The token is required on both `/` and `/events`; a missing or wrong token returns `403`. All responses send `Cache-Control: no-store`.
- No Co-Authored-By trailers in commits.
- This is a frontend+backend build, not pure TDD: tests are real verification (cargo build, `cargo clippy -- -D warnings`, cargo test, a raw tokio TCP client against an ephemeral-port server, per-OS open-command argv assertions, and an end-to-end integration test mirroring `tests/policy_file.rs`).

---

## File Structure

- **Create** `crates/execkit-mcp/src/watch/web.rs` - the HTTP/SSE server: token, wire JSON, `serve()`, connection handling, SSE streaming, browser-open helper.
- **Create** `crates/execkit-mcp/src/watch/viewer.html` - the self-contained page (sidebar + transcript panes), embedded via `include_str!`.
- **Create** `crates/execkit-mcp/tests/web_viewer.rs` - end-to-end: drive the built server with `EXECKIT_MCP_WATCH_WEB` + audit, assert the URL notification, connect to `/events`, assert an exec arrives over SSE.
- **Modify** `crates/execkit-mcp/src/watch/mod.rs` - add `pub mod web;`.
- **Modify** `crates/execkit-mcp/src/main.rs` - extend the `watch` subcommand with `--serve`/`--open`; add the auto-start hook in `run_server`.
- **Modify** `crates/execkit-mcp/Cargo.toml` - add `getrandom = "0.4"`.
- **Modify** `crates/execkit-mcp/README.md` - document the env var and the subcommand.
- **Reused unchanged:** `watch/render.rs` (`render_event` -> `Vec<StyledLine>`, `StyledLine { text: String, kind: LineKind }`, `LineKind::{Prompt,Stdout,Stderr,ExitOk,ExitErr,Marker}`), `watch/source.rs` (`Source::new(PathBuf)`, `Source::poll() -> Vec<AuditEvent>`), `watch/tail.rs`, `audit.rs` (`AuditEvent`, `AuditEvent::session() -> &str`), `paths.rs` (`home_dir() -> PathBuf`).

---

## Task 1: web.rs scaffolding - token and SSE wire JSON

**Files:**
- Create: `crates/execkit-mcp/src/watch/web.rs`
- Modify: `crates/execkit-mcp/src/watch/mod.rs` (add `pub mod web;` after `pub mod tui;`)
- Modify: `crates/execkit-mcp/Cargo.toml` (`[dependencies]`: add `getrandom = "0.4"`)

**Interfaces:**
- Consumes: `crate::watch::render::{StyledLine, LineKind}`.
- Produces:
  - `pub fn gen_token() -> anyhow::Result<String>` - 32 lowercase hex chars (16 random bytes).
  - `fn kind_str(k: LineKind) -> &'static str` - maps to `"prompt"|"stdout"|"stderr"|"exit_ok"|"exit_err"|"marker"`.
  - `fn wire_json(session: &str, line: &StyledLine) -> String` - one SSE payload: `{"session":..,"kind":..,"text":..}`.

- [ ] **Step 1: Add the dependency**

In `crates/execkit-mcp/Cargo.toml`, under `[dependencies]`, add after the `regex = "1"` line:

```toml
getrandom = "0.4"
```

- [ ] **Step 2: Create web.rs with token + wire helpers and their tests**

Create `crates/execkit-mcp/src/watch/web.rs`:

```rust
// SPDX-License-Identifier: Apache-2.0
//! A live, read-only web viewer for the audit log. A hand-rolled HTTP/SSE
//! server (loopback only, token-gated) tails the same Source the TUI uses,
//! renders events with render_event, and streams the rendered lines as JSON to
//! a self-contained page. Read-only: no endpoint mutates anything.
use crate::watch::render::{LineKind, StyledLine};

/// 16 random bytes as 32 lowercase hex chars. Used as a URL token so other
/// local processes (or a CSRF from a visited page) cannot read the transcript.
pub fn gen_token() -> anyhow::Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("system RNG: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Stable wire name for a line kind, so the browser colors without re-deriving.
fn kind_str(k: LineKind) -> &'static str {
    match k {
        LineKind::Prompt => "prompt",
        LineKind::Stdout => "stdout",
        LineKind::Stderr => "stderr",
        LineKind::ExitOk => "exit_ok",
        LineKind::ExitErr => "exit_err",
        LineKind::Marker => "marker",
    }
}

/// One SSE message: a rendered line tagged with its session id.
fn wire_json(session: &str, line: &StyledLine) -> String {
    serde_json::json!({
        "session": session,
        "kind": kind_str(line.kind),
        "text": line.text,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_32_hex_chars_and_varies() {
        let a = gen_token().unwrap();
        let b = gen_token().unwrap();
        assert_eq!(a.len(), 32, "16 bytes -> 32 hex chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two tokens should differ");
    }

    #[test]
    fn kind_str_covers_every_variant() {
        assert_eq!(kind_str(LineKind::Prompt), "prompt");
        assert_eq!(kind_str(LineKind::Stdout), "stdout");
        assert_eq!(kind_str(LineKind::Stderr), "stderr");
        assert_eq!(kind_str(LineKind::ExitOk), "exit_ok");
        assert_eq!(kind_str(LineKind::ExitErr), "exit_err");
        assert_eq!(kind_str(LineKind::Marker), "marker");
    }

    #[test]
    fn wire_json_shape() {
        let line = StyledLine { text: "/tmp $ ls".into(), kind: LineKind::Prompt };
        let v: serde_json::Value = serde_json::from_str(&wire_json("1_local", &line)).unwrap();
        assert_eq!(v["session"], "1_local");
        assert_eq!(v["kind"], "prompt");
        assert_eq!(v["text"], "/tmp $ ls");
    }
}
```

(Test-only `.unwrap()` on our own `Result`/`Value` is fine - the no-panic rule is about network/operator input in production paths.)

- [ ] **Step 3: Declare the module**

In `crates/execkit-mcp/src/watch/mod.rs`, add after `pub mod tui;`:

```rust
pub mod web;
```

- [ ] **Step 4: Build and run the tests**

Run: `cargo test -p execkit-mcp --lib watch::web`
Expected: 3 tests pass (`token_is_32_hex_chars_and_varies`, `kind_str_covers_every_variant`, `wire_json_shape`).

- [ ] **Step 5: Lint + typography**

Run: `cargo clippy -p execkit-mcp --all-targets -- -D warnings`
Expected: clean.
Run: `grep -nP '[^\x00-\x7F]' crates/execkit-mcp/src/watch/web.rs crates/execkit-mcp/Cargo.toml`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add crates/execkit-mcp/src/watch/web.rs crates/execkit-mcp/src/watch/mod.rs crates/execkit-mcp/Cargo.toml
git commit -m "feat(mcp): web viewer scaffolding - URL token + SSE wire JSON"
```

---

## Task 2: The HTTP/SSE server core + a minimal page

**Files:**
- Modify: `crates/execkit-mcp/src/watch/web.rs` (add `serve`, connection handling, SSE)
- Create: `crates/execkit-mcp/src/watch/viewer.html` (minimal page; Task 3 fills in the real UI)

**Interfaces:**
- Consumes: `crate::watch::render::render_event`, `crate::watch::source::Source`, `crate::audit::AuditEvent` (via `Source::poll`), `AuditEvent::session()`.
- Produces:
  - `pub async fn serve(path: std::path::PathBuf, token: String) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)>` - binds `127.0.0.1:0`, spawns the audit poller and the accept loop, returns the bound address and the accept-loop handle.

- [ ] **Step 1: Create the minimal page so `include_str!` compiles**

Create `crates/execkit-mcp/src/watch/viewer.html` (Task 3 replaces the body with the sidebar+panes UI; this minimal version proves the stream end to end):

```html
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>execkit - live</title></head>
<body>
<pre id="log" aria-live="polite"></pre>
<script>
  const t = new URLSearchParams(location.search).get("t") || "";
  const log = document.getElementById("log");
  const es = new EventSource("/events?t=" + encodeURIComponent(t));
  es.onmessage = (e) => {
    const m = JSON.parse(e.data);
    log.textContent += "[" + m.session + "] " + m.text + "\n";
    window.scrollTo(0, document.body.scrollHeight);
  };
</script>
</body>
</html>
```

- [ ] **Step 2: Write the failing server test**

Add to the `tests` module in `crates/execkit-mcp/src/watch/web.rs`:

```rust
    use std::io::Write as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Write a tiny audit log, serve it, return (addr, token, tempfile path).
    fn seed_audit() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ek_web_{}.jsonl", std::process::id()));
        let mut f = std::fs::File::create(&p).unwrap();
        // one Open + one Exec for session 1_local
        writeln!(f, r#"{{"event":"open","ts":1,"session":"1_local","transport":"local"}}"#).unwrap();
        writeln!(f, r#"{{"event":"exec","ts":2,"session":"1_local","transport":"local","command":"echo hi","stdout":"hi","stderr":"","exit_code":0,"duration_ms":3,"cwd":"/tmp","truncated":false}}"#).unwrap();
        p
    }

    // Minimal HTTP GET; returns the full response text (headers + body so far).
    async fn http_get(addr: std::net::SocketAddr, target: &str, read_ms: u64) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        // Read briefly; SSE never closes, so bound the read by time.
        let n = tokio::time::timeout(std::time::Duration::from_millis(read_ms), s.read(&mut buf))
            .await
            .map(|r| r.unwrap_or(0))
            .unwrap_or(0);
        String::from_utf8_lossy(&buf[..n]).to_string()
    }

    #[tokio::test]
    async fn serves_page_streams_sse_and_gates_on_token() {
        let path = seed_audit();
        let token = "secrettoken".to_string();
        let (addr, _h) = serve(path.clone(), token.clone()).await.unwrap();

        // No token -> 403 on both routes.
        assert!(http_get(addr, "/", 300).await.starts_with("HTTP/1.1 403"));
        assert!(http_get(addr, "/events", 300).await.starts_with("HTTP/1.1 403"));

        // Page with token -> 200 html containing our script anchor.
        let page = http_get(addr, &format!("/?t={token}"), 300).await;
        assert!(page.starts_with("HTTP/1.1 200"), "page status: {}", &page[..page.len().min(40)]);
        assert!(page.contains("text/html"));
        assert!(page.contains("/events?t="));

        // Events with token -> text/event-stream, replays the seeded exec.
        let ev = http_get(addr, &format!("/events?t={token}"), 800).await;
        assert!(ev.contains("text/event-stream"), "sse content-type missing: {ev}");
        assert!(ev.contains("/tmp $ echo hi"), "replayed prompt missing: {ev}");
        assert!(ev.contains("\"session\":\"1_local\""), "session tag missing: {ev}");

        let _ = std::fs::remove_file(&path);
    }
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p execkit-mcp --lib watch::web::tests::serves_page`
Expected: FAIL to compile (`serve` not found).

- [ ] **Step 4: Implement the server**

In `crates/execkit-mcp/src/watch/web.rs`, add the imports at the top (below the existing `use`):

```rust
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use crate::watch::render::render_event;
use crate::watch::source::Source;

/// The page is embedded so the binary is self-contained (no asset files at run time).
const PAGE: &str = include_str!("viewer.html");

/// Lock the backlog, recovering from a poisoned mutex instead of panicking.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
```

Then add the server functions:

```rust
/// Bind 127.0.0.1 on an ephemeral port, tail `path` through Source, render each
/// event, accumulate a replay backlog, and broadcast new lines to SSE clients.
/// Returns the bound address and the accept-loop handle. Read-only throughout.
pub async fn serve(
    path: PathBuf,
    token: String,
) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;

    let backlog: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let (tx, _rx) = broadcast::channel::<String>(1024);

    // Poller: tail the audit Source, render, append to backlog, broadcast.
    {
        let backlog = backlog.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut source = Source::new(path);
            loop {
                for ev in source.poll() {
                    let session = ev.session().to_string();
                    for line in render_event(&ev) {
                        let msg = wire_json(&session, &line);
                        lock(&backlog).push(msg.clone());
                        let _ = tx.send(msg); // Err only if no subscribers; ignore.
                    }
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        });
    }

    // Accept loop: one task per connection.
    let token = Arc::new(token);
    let handle = tokio::spawn(async move {
        loop {
            let (sock, _peer) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => continue,
            };
            let backlog = backlog.clone();
            let tx = tx.clone();
            let token = token.clone();
            tokio::spawn(async move {
                let _ = handle_conn(sock, backlog, tx, token).await;
            });
        }
    });

    Ok((addr, handle))
}

async fn write_simple(
    sock: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(body).await?;
    sock.flush().await
}

async fn handle_conn(
    mut sock: TcpStream,
    backlog: Arc<Mutex<Vec<String>>>,
    tx: broadcast::Sender<String>,
    token: Arc<String>,
) -> std::io::Result<()> {
    // Read the request head (bounded; we only need the first line).
    let mut buf = vec![0u8; 8192];
    let mut n = 0;
    loop {
        let r = sock.read(&mut buf[n..]).await?;
        if r == 0 {
            return Ok(());
        }
        n += r;
        if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") || n == buf.len() {
            break;
        }
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let first = req.lines().next().unwrap_or("");
    let target = first.split_whitespace().nth(1).unwrap_or("");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let supplied = query.split('&').find_map(|kv| kv.strip_prefix("t=")).unwrap_or("");

    if supplied != token.as_str() {
        return write_simple(&mut sock, "403 Forbidden", "text/plain", b"403 forbidden\n").await;
    }
    match path {
        "/" => write_simple(&mut sock, "200 OK", "text/html; charset=utf-8", PAGE.as_bytes()).await,
        "/events" => stream_events(sock, backlog, tx).await,
        _ => write_simple(&mut sock, "404 Not Found", "text/plain", b"404 not found\n").await,
    }
}

/// SSE: send the replay backlog, then forward live lines until the client drops.
async fn stream_events(
    mut sock: TcpStream,
    backlog: Arc<Mutex<Vec<String>>>,
    tx: broadcast::Sender<String>,
) -> std::io::Result<()> {
    sock.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
          Cache-Control: no-store\r\nConnection: close\r\n\r\n",
    )
    .await?;

    // Snapshot + subscribe atomically w.r.t. the poller (it locks before send).
    let (snapshot, mut rx) = {
        let g = lock(&backlog);
        (g.clone(), tx.subscribe())
    };
    for msg in snapshot {
        sock.write_all(format!("data: {msg}\n\n").as_bytes()).await?;
    }
    sock.flush().await?;

    loop {
        match rx.recv().await {
            Ok(msg) => {
                sock.write_all(format!("data: {msg}\n\n").as_bytes()).await?;
                sock.flush().await?;
            }
            // Lagged: drop missed messages, keep streaming.
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p execkit-mcp --lib watch::web::tests::serves_page`
Expected: PASS.

- [ ] **Step 6: Full lint, typography, and the existing watch tests**

Run: `cargo clippy -p execkit-mcp --all-targets -- -D warnings`
Expected: clean.
Run: `grep -nP '[^\x00-\x7F]' crates/execkit-mcp/src/watch/web.rs crates/execkit-mcp/src/watch/viewer.html`
Expected: no output.
Run: `cargo test -p execkit-mcp --lib watch`
Expected: all watch tests pass (render, tail, tui, web).

- [ ] **Step 7: Commit**

```bash
git add crates/execkit-mcp/src/watch/web.rs crates/execkit-mcp/src/watch/viewer.html
git commit -m "feat(mcp): web viewer HTTP/SSE core - token-gated, loopback, replay+live"
```

---

## Task 3: The real page - session sidebar + transcript panes

**Files:**
- Modify: `crates/execkit-mcp/src/watch/viewer.html` (replace the minimal body with the two-pane UI)

**Interfaces:**
- Consumes: the `/events?t=` SSE stream, each message `{"session","kind","text"}` (from Task 2).
- Produces: no Rust interface; this is the frontend. The served bytes change; the Task 2 server test still passes because it only asserts the page contains `/events?t=` and is `text/html`.

- [ ] **Step 1: Replace viewer.html with the full UI**

Overwrite `crates/execkit-mcp/src/watch/viewer.html`:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>execkit - live (read-only)</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; height: 100vh; display: flex; flex-direction: column;
         font: 13px ui-monospace, Menlo, Consolas, monospace; background: #11141a; color: #c8ccd4; }
  header { padding: 6px 10px; background: #0b0d11; border-bottom: 1px solid #222; color: #8a93a3; }
  header b { color: #c8ccd4; }
  .main { flex: 1; display: flex; min-height: 0; }
  #sessions { width: 220px; border-right: 1px solid #222; overflow-y: auto; }
  #sessions .s { padding: 4px 10px; cursor: pointer; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  #sessions .s:hover { background: #1a1f29; }
  #sessions .s.sel { background: #243044; color: #fff; }
  #sessions .s.closed { color: #6b7280; }
  #transcript { flex: 1; overflow-y: auto; padding: 8px 12px; white-space: pre-wrap; word-break: break-word; }
  #title { padding: 6px 12px; border-bottom: 1px solid #222; color: #8a93a3; }
  .pane { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  .ln { display: block; }
  .prompt { color: #56b6c2; font-weight: 600; }
  .stdout { color: #c8ccd4; }
  .stderr { color: #e06c75; }
  .exit_ok { color: #98c379; }
  .exit_err { color: #e06c75; }
  .marker { color: #6b7280; }
</style>
</head>
<body>
<header>execkit <b>live</b> - read-only shell transcript</header>
<div class="main">
  <div id="sessions" role="listbox" aria-label="sessions"></div>
  <div class="pane">
    <div id="title">(no sessions yet)</div>
    <div id="transcript" aria-live="polite"></div>
  </div>
</div>
<script>
  const token = new URLSearchParams(location.search).get("t") || "";
  const sessionsEl = document.getElementById("sessions");
  const titleEl = document.getElementById("title");
  const transcriptEl = document.getElementById("transcript");

  // session id -> { lines: [{kind,text}], closed: bool }
  const sessions = new Map();
  let selected = null;

  function order() { return [...sessions.keys()]; }

  function renderSidebar() {
    sessionsEl.textContent = "";
    for (const id of order()) {
      const s = sessions.get(id);
      const div = document.createElement("div");
      div.className = "s" + (id === selected ? " sel" : "") + (s.closed ? " closed" : "");
      div.textContent = (id === selected ? "> " : "  ") + id + " (" + s.lines.length + ")";
      div.onclick = () => { selected = id; renderAll(); };
      sessionsEl.appendChild(div);
    }
  }

  function atBottom() {
    return transcriptEl.scrollHeight - transcriptEl.scrollTop - transcriptEl.clientHeight < 24;
  }

  function renderTranscript() {
    const s = selected && sessions.get(selected);
    titleEl.textContent = selected ? (selected + (s.closed ? "  (closed)" : "  (active)")) : "(no sessions yet)";
    transcriptEl.textContent = "";
    if (!s) return;
    for (const l of s.lines) {
      const span = document.createElement("span");
      span.className = "ln " + l.kind;
      span.textContent = l.text;
      transcriptEl.appendChild(span);
    }
  }

  function renderAll() { renderSidebar(); renderTranscript(); }

  function ingest(m) {
    let s = sessions.get(m.session);
    if (!s) { s = { lines: [], closed: false }; sessions.set(m.session, s); if (!selected) selected = m.session; }
    if (m.kind === "marker" && m.text.startsWith("-- closed")) s.closed = true;
    if (m.kind === "marker" && m.text.startsWith("-- opened")) s.closed = false;
    s.lines.push({ kind: m.kind, text: m.text });

    const stick = (m.session === selected) && atBottom();
    if (m.session === selected) {
      const span = document.createElement("span");
      span.className = "ln " + m.kind;
      span.textContent = m.text;
      transcriptEl.appendChild(span);
      if (stick) transcriptEl.scrollTop = transcriptEl.scrollHeight;
    }
    renderSidebar();
  }

  const es = new EventSource("/events?t=" + encodeURIComponent(token));
  es.onmessage = (e) => { try { ingest(JSON.parse(e.data)); } catch (_) {} };
  es.onerror = () => { titleEl.textContent += "  [disconnected]"; };
</script>
</body>
</html>
```

- [ ] **Step 2: Verify it still compiles and the server test still passes**

Run: `cargo test -p execkit-mcp --lib watch::web::tests::serves_page`
Expected: PASS (the page still contains `/events?t=` and is served as `text/html`).

- [ ] **Step 3: Real verification - load the page against a live server with Playwright**

Start a server bound to an ephemeral port against a seeded audit log, then drive the page in a real browser. Use this throwaway script (do not commit it):

Create `/tmp/ek-web-verify.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
A=/tmp/ek-verify-audit.jsonl
printf '%s\n' \
  '{"event":"open","ts":1,"session":"1_local","transport":"local"}' \
  '{"event":"exec","ts":2,"session":"1_local","transport":"local","command":"echo hi","stdout":"hi","stderr":"","exit_code":0,"duration_ms":3,"cwd":"/tmp","truncated":false}' \
  '{"event":"exec","ts":3,"session":"1_local","transport":"local","command":"ls /nope","stdout":"","stderr":"ls: cannot access","exit_code":2,"duration_ms":5,"cwd":"/tmp","truncated":false}' \
  '{"event":"open","ts":4,"session":"2_local","transport":"local"}' \
  '{"event":"exec","ts":5,"session":"2_local","transport":"local","command":"uname -s","stdout":"Linux","stderr":"","exit_code":0,"duration_ms":2,"cwd":"/home","truncated":false}' > "$A"
cargo run -q -p execkit-mcp -- watch --serve "$A"
```

Run the server: `bash /tmp/ek-web-verify.sh &` then read its stderr for the URL (printed by Task 5's `--serve`). Open that URL with the Playwright MCP tools (`browser_navigate`, then `browser_snapshot`) and confirm:
- the sidebar lists `1_local` and `2_local`,
- the right pane shows `/tmp $ echo hi`, `hi`, `ok exit 0`, and the red `x exit 2`,
- clicking `2_local` switches the pane to `uname -s` / `Linux`.

Then stop the server (`kill %1`) and remove the temp files. This is a manual verification step; record the snapshot result in the task report. (If Playwright is unavailable in the environment, fall back to `curl -sN "$URL/events?t=$TOKEN" | head` and confirm the SSE lines, and visually confirm the HTML structure.)

- [ ] **Step 4: Typography check**

Run: `grep -nP '[^\x00-\x7F]' crates/execkit-mcp/src/watch/viewer.html`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add crates/execkit-mcp/src/watch/viewer.html
git commit -m "feat(mcp): web viewer page - session sidebar + transcript panes"
```

---

## Task 4: Browser-open helper

**Files:**
- Modify: `crates/execkit-mcp/src/watch/web.rs` (add `open_browser`)

**Interfaces:**
- Produces:
  - `pub fn open_browser(url: &str)` - spawn the platform opener detached; failures are ignored (the URL is also surfaced via notification).
  - `fn open_command(url: &str) -> (&'static str, Vec<String>)` - the program + argv for the current OS (separated out so it is unit-testable without spawning).

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/execkit-mcp/src/watch/web.rs`:

```rust
    #[test]
    fn open_command_per_os() {
        let (prog, args) = open_command("http://127.0.0.1:9/?t=x");
        #[cfg(target_os = "linux")]
        {
            assert_eq!(prog, "xdg-open");
            assert_eq!(args, vec!["http://127.0.0.1:9/?t=x".to_string()]);
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(prog, "open");
            assert_eq!(args, vec!["http://127.0.0.1:9/?t=x".to_string()]);
        }
        #[cfg(target_os = "windows")]
        {
            assert_eq!(prog, "cmd");
            assert_eq!(args, vec!["/C".to_string(), "start".to_string(), "".to_string(), "http://127.0.0.1:9/?t=x".to_string()]);
        }
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p execkit-mcp --lib watch::web::tests::open_command_per_os`
Expected: FAIL to compile (`open_command` not found).

- [ ] **Step 3: Implement**

Add to `crates/execkit-mcp/src/watch/web.rs`:

```rust
/// Program + argv that opens `url` in the default browser on this OS. Separated
/// from spawning so it is unit-testable without launching anything.
fn open_command(url: &str) -> (&'static str, Vec<String>) {
    #[cfg(target_os = "linux")]
    {
        ("xdg-open", vec![url.to_string()])
    }
    #[cfg(target_os = "macos")]
    {
        ("open", vec![url.to_string()])
    }
    #[cfg(target_os = "windows")]
    {
        // `start` is a cmd builtin; its first quoted arg is the window title.
        ("cmd", vec!["/C".into(), "start".into(), String::new(), url.to_string()])
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        ("xdg-open", vec![url.to_string()])
    }
}

/// Best-effort: open `url` in the default browser. A failure is non-fatal - the
/// URL is also surfaced via an MCP log notification.
pub fn open_browser(url: &str) {
    let (prog, args) = open_command(url);
    let _ = std::process::Command::new(prog)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p execkit-mcp --lib watch::web::tests::open_command_per_os`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

Run: `cargo clippy -p execkit-mcp --all-targets -- -D warnings`
Expected: clean.

```bash
git add crates/execkit-mcp/src/watch/web.rs
git commit -m "feat(mcp): web viewer browser-open helper (per-OS, best-effort)"
```

---

## Task 5: `watch --serve [--open]` subcommand

**Files:**
- Modify: `crates/execkit-mcp/src/main.rs` (the `Some("watch")` arm, around lines 955-978)
- Modify: `crates/execkit-mcp/README.md` (document the subcommand)
- Test: `crates/execkit-mcp/tests/cli.rs` (assert `--serve` usage error path)

**Interfaces:**
- Consumes: `execkit_mcp::watch::web::{serve, gen_token, open_browser}`.
- Produces: the CLI behavior `execkit-mcp watch --serve [--open] <file>` - prints the URL to stderr, serves until Ctrl+C.

- [ ] **Step 1: Read the current watch arm**

Read `crates/execkit-mcp/src/main.rs` lines 955-983 to see the existing `--follow` parsing and path resolution. The new `--serve` reuses the same `path` resolution.

- [ ] **Step 2: Add `--serve`/`--open` parsing**

In the `Some("watch")` arm, after the existing `let follow = ...` line, add:

```rust
            let do_serve = rest.iter().any(|a| a == "--serve");
            let do_open = rest.iter().any(|a| a == "--open");
```

Then in the `match path { Some(p) => { ... } }` block, replace the existing `return if follow { watch::follow(p) } else { watch::run(p) }` with:

```rust
                Some(p) => {
                    if do_serve {
                        return tokio::runtime::Runtime::new()?.block_on(async move {
                            let token = watch::web::gen_token()?;
                            let (addr, handle) = watch::web::serve(p, token.clone()).await?;
                            let url = format!("http://{addr}/?t={token}");
                            eprintln!("execkit-mcp: live viewer at {url} (read-only; Ctrl+C to stop)");
                            if do_open {
                                watch::web::open_browser(&url);
                            }
                            handle.await.ok();
                            Ok(())
                        });
                    }
                    return if follow {
                        watch::follow(p)
                    } else {
                        watch::run(p)
                    };
                }
```

(The accept-loop `handle` never returns on its own, so `handle.await` blocks until the process is interrupted - the desired "serve until Ctrl+C" behavior.)

- [ ] **Step 3: Update the usage line**

In the same arm's `None =>` branch, update the usage string to mention `--serve`:

```rust
                    eprintln!("usage: execkit-mcp watch [--follow|--serve] [--open] <audit-file-or-dir>   (or set EXECKIT_MCP_AUDIT / EXECKIT_MCP_AUDIT_DIR)");
```

- [ ] **Step 4: Build**

Run: `cargo build -p execkit-mcp`
Expected: builds clean.

- [ ] **Step 5: Add a CLI test for the usage path**

Add to `crates/execkit-mcp/tests/cli.rs`:

```rust
#[test]
fn watch_serve_without_path_shows_usage() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_execkit-mcp"))
        .args(["watch", "--serve"])
        .env_remove("EXECKIT_MCP_AUDIT")
        .env_remove("EXECKIT_MCP_AUDIT_DIR")
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "missing path should exit non-zero");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--serve"), "usage should mention --serve, got {err:?}");
}
```

- [ ] **Step 6: Manual serve smoke test**

Run: `printf '%s\n' '{"event":"open","ts":1,"session":"1_local","transport":"local"}' > /tmp/ek-smoke.jsonl`
Run (background): `cargo run -q -p execkit-mcp -- watch --serve /tmp/ek-smoke.jsonl &` - note the printed `http://127.0.0.1:PORT/?t=TOKEN`.
Run: `curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:PORT/?t=TOKEN"` -> `200`; without `?t=` -> `403`.
Stop: `kill %1`; `rm /tmp/ek-smoke.jsonl`.
Record the codes in the task report.

- [ ] **Step 7: Document in the README**

In `crates/execkit-mcp/README.md`, find the section that describes `watch` (the live read-only viewer) and add a short paragraph after it (ASCII only):

```markdown
### Live viewer in your browser

`execkit-mcp watch --serve [--open] <audit-file>` serves the same read-only
transcript as a local web page (127.0.0.1 only, single-use URL token). Add
`--open` to launch your browser at it. This is the same view as the terminal
`watch`, in a browser tab instead of a TTY.
```

- [ ] **Step 8: Run the CLI tests + lint + typography**

Run: `cargo test -p execkit-mcp --test cli`
Expected: all pass, including `watch_serve_without_path_shows_usage`.
Run: `cargo clippy -p execkit-mcp --all-targets -- -D warnings`
Expected: clean.
Run: `grep -nP '[^\x00-\x7F]' crates/execkit-mcp/src/main.rs crates/execkit-mcp/README.md crates/execkit-mcp/tests/cli.rs`
Expected: no output.

- [ ] **Step 9: Commit**

```bash
git add crates/execkit-mcp/src/main.rs crates/execkit-mcp/README.md crates/execkit-mcp/tests/cli.rs
git commit -m "feat(mcp): watch --serve [--open] - browser-view any audit log"
```

---

## Task 6: Auto-start on `EXECKIT_MCP_WATCH_WEB` + end-to-end test

**Files:**
- Modify: `crates/execkit-mcp/src/main.rs` (`run_server`, around lines 988-1024)
- Create: `crates/execkit-mcp/tests/web_viewer.rs`
- Modify: `crates/execkit-mcp/README.md` (env var table + a note)

**Interfaces:**
- Consumes: `execkit_mcp::watch::web::{serve, gen_token, open_browser}`, `paths::home_dir`, the `RunningService::peer()` from rmcp (`service.peer()` returns `&Peer<RoleServer>`), `notify_logging_message`.
- Produces: when `EXECKIT_MCP_WATCH_WEB` is set, the server serves the viewer, opens the browser, and emits the URL via an info log notification.

- [ ] **Step 1: Add a default-audit-path helper**

In `crates/execkit-mcp/src/paths.rs`, add (with the others):

```rust
/// Default audit file used when the web viewer is enabled but no audit path is
/// configured. Lives under the user's home so it survives across runs.
pub fn default_web_audit_path() -> PathBuf {
    home_dir().join(".execkit").join("watch.jsonl")
}
```

Add a test in `paths.rs`'s `tests` module:

```rust
    #[test]
    fn default_web_audit_path_is_under_home() {
        let p = default_web_audit_path();
        assert!(p.is_absolute());
        assert!(p.ends_with("watch.jsonl"));
        assert!(p.starts_with(home_dir()));
    }
```

Run: `cargo test -p execkit-mcp --lib paths`
Expected: pass.

- [ ] **Step 2: Wire the auto-start into run_server**

In `crates/execkit-mcp/src/main.rs`, change `let config = Config::from_env();` near the top of `run_server` to `let mut config = Config::from_env();`. Then, immediately before the `let service = ExeckitServer::new(...)` line, insert:

```rust
    // Live web viewer (opt-in). It tails the audit file, so if auditing is off
    // we default an audit path and turn it on so there is something to tail.
    let web_enabled = std::env::var_os("EXECKIT_MCP_WATCH_WEB").is_some();
    let web_audit_path = if web_enabled {
        let p = config
            .audit_dir
            .clone()
            .or_else(|| config.audit_path.clone())
            .unwrap_or_else(|| {
                let def = execkit_mcp::paths::default_web_audit_path();
                if let Some(parent) = def.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                config.audit_path = Some(def.clone());
                def
            });
        Some(p)
    } else {
        None
    };
```

Then change the server construction + serve to capture the service and start the viewer after the peer exists:

```rust
    let service = ExeckitServer::new(config, operator_policy)
        .serve(rmcp::transport::stdio())
        .await?;

    if let Some(path) = web_audit_path {
        match watch::web::gen_token() {
            Ok(token) => match watch::web::serve(path, token.clone()).await {
                Ok((addr, _handle)) => {
                    let url = format!("http://{addr}/?t={token}");
                    watch::web::open_browser(&url);
                    let _ = service
                        .peer()
                        .notify_logging_message(LoggingMessageNotificationParam {
                            level: LoggingLevel::Info,
                            logger: Some("execkit/web".into()),
                            data: serde_json::json!({
                                "summary": format!("live viewer at {url}"),
                                "url": url,
                            }),
                        })
                        .await;
                    eprintln!("execkit-mcp: live viewer at {url} (read-only)");
                }
                Err(e) => eprintln!("execkit-mcp: web viewer failed to start: {e:#}"),
            },
            Err(e) => eprintln!("execkit-mcp: web viewer token error: {e:#}"),
        }
    }

    service.waiting().await?;
    Ok(())
```

Confirm `watch` is imported at the top of main.rs (it is: `use execkit_mcp::watch;`) and that `LoggingMessageNotificationParam`, `LoggingLevel` are already imported (they are, from the `notify_activity` code).

- [ ] **Step 3: Build**

Run: `cargo build -p execkit-mcp`
Expected: clean. (If `service.peer()` does not resolve, confirm the method on rmcp 1.7 `RunningService` - it is `pub fn peer(&self) -> &Peer<R>`.)

- [ ] **Step 4: Write the end-to-end test**

Create `crates/execkit-mcp/tests/web_viewer.rs`. Mirror `tests/policy_file.rs`'s harness (drive the built binary over stdio), but assert the web URL notification and SSE. Full file:

```rust
// SPDX-License-Identifier: Apache-2.0
//! End-to-end: with EXECKIT_MCP_WATCH_WEB + EXECKIT_MCP_AUDIT set, the server
//! starts the web viewer, emits its URL via a log notification, and streams a
//! command's transcript over SSE. Drives the built server over stdio.
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

struct Server {
    child: Child,
    stdin: ChildStdin,
    out: BufReader<ChildStdout>,
}

impl Server {
    fn start(audit: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_execkit-mcp"))
            .env("EXECKIT_MCP_WATCH_WEB", "1")
            .env("EXECKIT_MCP_AUDIT", audit)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn server");
        let stdin = child.stdin.take().unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        Self { child, stdin, out }
    }
    fn send(&mut self, v: Value) {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
    }
    fn next_json(&mut self) -> Value {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.out.read_line(&mut line).expect("read");
            assert!(n > 0, "server closed stdout");
            if let Ok(v) = serde_json::from_str::<Value>(line.trim()) {
                return v;
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn web_viewer_emits_url_and_streams_sse() {
    let audit = std::env::temp_dir().join(format!("ek_webe2e_{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&audit);
    let mut m = Server::start(&audit);

    m.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-06-18","capabilities":{},
        "clientInfo":{"name":"t","version":"0"}}}));
    let _init = m.next_json();
    m.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));

    // Collect notifications until we see the web URL (it is emitted right after
    // the connection is initialized).
    let mut url = String::new();
    for _ in 0..50 {
        let v = m.next_json();
        if v["method"] == json!("notifications/message") {
            if let Some(u) = v["params"]["data"]["url"].as_str() {
                url = u.to_string();
                break;
            }
        }
    }
    assert!(url.starts_with("http://127.0.0.1:"), "expected loopback url, got {url:?}");
    assert!(url.contains("/?t="), "url should carry a token: {url}");

    // Create a session and run a command; it lands in the audit file the viewer tails.
    m.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"session_create","arguments":{"transport":"local"}}}));
    // session id is deterministic: 1_local
    m.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
        "params":{"name":"session_exec","arguments":{"session_id":"1_local","command":"echo sse-demo"}}}));

    // Connect to /events and confirm the exec arrives over SSE.
    let base = url.replace("/?t=", "/events?t=");
    let (host_port, token) = base.split_once("/events?t=").map(|(h, t)| (h.trim_start_matches("http://"), t)).unwrap();
    let mut found = false;
    for _ in 0..40 {
        if let Ok(body) = sse_read(host_port, token, Duration::from_millis(500)) {
            if body.contains("echo sse-demo") {
                found = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(found, "expected the exec to stream over SSE");

    let _ = std::fs::remove_file(&audit);
}

// Minimal blocking SSE read: GET /events?t=, read for `dur`, return what arrived.
fn sse_read(host_port: &str, token: &str, dur: Duration) -> std::io::Result<String> {
    use std::io::Read;
    use std::net::TcpStream;
    let mut s = TcpStream::connect(host_port)?;
    s.set_read_timeout(Some(dur))?;
    write!(s, "GET /events?t={token} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")?;
    let mut buf = [0u8; 8192];
    let mut acc = String::new();
    let start = std::time::Instant::now();
    while start.elapsed() < dur {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => acc.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(_) => break,
        }
    }
    Ok(acc)
}
```

- [ ] **Step 5: Run the end-to-end test**

Run: `cargo test -p execkit-mcp --test web_viewer`
Expected: `web_viewer_emits_url_and_streams_sse` passes.

- [ ] **Step 6: Document the env var**

In `crates/execkit-mcp/README.md`, add a row to the environment-variable table (find the table that lists `EXECKIT_MCP_POLICY_FILE`):

```markdown
| `EXECKIT_MCP_WATCH_WEB` | Auto-start the read-only browser viewer and open it (loopback + URL token); auto-enables an audit file if none is set | off |
```

- [ ] **Step 7: Full workspace gate**

Run: `cargo fmt --all -- --check` -> clean (run `cargo fmt --all` if needed).
Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings` -> clean.
Run: `cargo test -p execkit-mcp` -> all pass (lib + cli + web_viewer + existing).
Run: `grep -nP '[^\x00-\x7F]' crates/execkit-mcp/src/main.rs crates/execkit-mcp/src/paths.rs crates/execkit-mcp/tests/web_viewer.rs crates/execkit-mcp/README.md` -> no output.

- [ ] **Step 8: Confirm the existing watch paths still work (regression)**

Run: `cargo test -p execkit-mcp --lib watch` -> render/tail/tui/web tests pass.
Run: `printf '%s\n' '{"event":"open","ts":1,"session":"s","transport":"local"}' > /tmp/ek-follow.jsonl && cargo run -q -p execkit-mcp -- watch --follow /tmp/ek-follow.jsonl` -> prints `[s] -- opened: local --` then tails; Ctrl+C to stop; `rm /tmp/ek-follow.jsonl`.

- [ ] **Step 9: Commit**

```bash
git add crates/execkit-mcp/src/main.rs crates/execkit-mcp/src/paths.rs crates/execkit-mcp/tests/web_viewer.rs crates/execkit-mcp/README.md
git commit -m "feat(mcp): EXECKIT_MCP_WATCH_WEB auto-starts the browser viewer"
```

---

## Self-Review Notes (for the executor)

- **Spec coverage:** Task 1 (token, wire JSON, getrandom). Task 2 (serve, loopback, ephemeral port, token gate -> 403, Cache-Control: no-store, `/` page, `/events` SSE replay+live). Task 3 (sidebar + panes, TUI colors, replay-then-live, auto-scroll). Task 4 (browser open, per-OS). Task 5 (`watch --serve [--open]`, README). Task 6 (auto-start env var, default audit path, URL notification, end-to-end test, README env row). Reuse of `render_event`/`Source`/`AuditEvent`/`paths` is explicit and unchanged.
- **Type consistency:** `StyledLine { text, kind }` and `LineKind` variants match `render.rs`. `serve(PathBuf, String) -> (SocketAddr, JoinHandle<()>)` is consumed identically in Tasks 5 and 6. `gen_token() -> anyhow::Result<String>` and `open_browser(&str)` match their call sites.
- **Read-only invariant:** the only endpoints are `GET /` and `GET /events`; neither writes anything. The server only reads the audit Source.
- **No-panic:** request parsing uses `unwrap_or`/`nth`/`find_map` (non-panicking); the mutex uses `unwrap_or_else(|e| e.into_inner())`; `gen_token` returns `Result`. Test-only `.unwrap()` is acceptable.
