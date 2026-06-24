// SPDX-License-Identifier: Apache-2.0
//! A live web viewer for the audit log. A hand-rolled HTTP/SSE server (loopback
//! only, token-gated) tails the same Source the TUI uses, renders events with
//! render_event, and streams the rendered lines as JSON to a self-contained page.
//! GET /state and POST /state let the page persist display-only metadata
//! (aliases, pins, keeps, ui prefs) via meta::save - the only write surface.
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use anyhow::Context;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use crate::watch::meta;
use crate::watch::render::{render_event, LineKind, StyledLine};
use crate::watch::source::Source;

/// Per-connection context: everything `handle_conn` needs, cheaply cloned.
struct Ctx {
    backlog: Arc<Mutex<Vec<String>>>,
    tx: broadcast::Sender<String>,
    token: Arc<String>,
    /// Path to the audit log (used by /sessions + /session/<id> routes).
    audit: PathBuf,
    state_path: PathBuf,
}

/// The page is embedded so the binary is self-contained (no asset files at run time).
const PAGE: &str = include_str!("viewer.html");

/// Lock the backlog, recovering from a poisoned mutex instead of panicking.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// 16 random bytes as 32 lowercase hex chars. Used as a URL token so other
/// local processes (or a CSRF from a visited page) cannot read the transcript.
pub fn gen_token() -> anyhow::Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("system RNG: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Read the persistent token, or generate + persist one (mode 0600 on unix) if
/// absent/empty. A stable token keeps the auto-start URL constant across
/// restarts so an open browser tab reconnects on its own.
pub fn load_or_create_token(path: &Path) -> anyhow::Result<String> {
    if let Ok(s) = std::fs::read_to_string(path) {
        let t = s.trim();
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }
    let token = gen_token()?;
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
            .with_context(|| format!("writing token file {}", path.display()))?;
        f.write_all(token.as_bytes())
            .with_context(|| format!("writing token file {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &token)
            .with_context(|| format!("writing token file {}", path.display()))?;
    }
    Ok(token)
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

/// Bind 127.0.0.1 on an ephemeral port, tail `path` through Source, render each
/// event, accumulate a replay backlog, and broadcast new lines to SSE clients.
/// Returns the bound address and the accept-loop handle.
pub async fn serve(
    path: PathBuf,
    token: String,
    port: u16,
) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = listener.local_addr()?;

    let backlog: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let (tx, _rx) = broadcast::channel::<String>(1024);

    // Clone the audit path before the poller takes ownership of `path`.
    let path_for_routes = path.clone();

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

    // Build the per-connection context; the accept loop clones the Arc.
    let token = Arc::new(token);
    let ctx = Arc::new(Ctx {
        backlog: backlog.clone(),
        tx: tx.clone(),
        token: token.clone(),
        audit: path_for_routes,
        state_path: crate::paths::default_viewer_state_path(),
    });

    // Accept loop: one task per connection.
    let handle = tokio::spawn(async move {
        loop {
            let (sock, _peer) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => continue,
            };
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let _ = handle_conn(sock, ctx).await;
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

async fn handle_conn(mut sock: TcpStream, ctx: Arc<Ctx>) -> std::io::Result<()> {
    // Read the request head; capture how many header bytes precede the body.
    let mut buf = vec![0u8; 8192];
    let mut n = 0;
    let mut head_end = None;
    loop {
        let r = sock.read(&mut buf[n..]).await?;
        if r == 0 {
            return Ok(());
        }
        n += r;
        if let Some(p) = find_subslice(&buf[..n], b"\r\n\r\n") {
            head_end = Some(p + 4);
            break;
        }
        if n == buf.len() {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf[..head_end.unwrap_or(n)]).to_string();
    let first = head.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let supplied = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("t="))
        .unwrap_or("");
    if supplied != ctx.token.as_str() {
        return write_simple(&mut sock, "403 Forbidden", "text/plain", b"403 forbidden\n").await;
    }

    match (method, path) {
        ("GET", "/") => {
            write_simple(
                &mut sock,
                "200 OK",
                "text/html; charset=utf-8",
                PAGE.as_bytes(),
            )
            .await
        }
        ("GET", "/events") => stream_events(sock, ctx.backlog.clone(), ctx.tx.clone()).await,
        ("GET", "/state") => {
            let body =
                serde_json::to_vec(&meta::load(&ctx.state_path)).unwrap_or_else(|_| b"{}".to_vec());
            write_simple(&mut sock, "200 OK", "application/json", &body).await
        }
        ("POST", "/state") => handle_post_state(&mut sock, &ctx, &head, &buf[..n], head_end).await,
        ("GET", "/sessions") => {
            let body =
                serde_json::to_vec(&list_sessions(&ctx.audit)).unwrap_or_else(|_| b"[]".to_vec());
            write_simple(&mut sock, "200 OK", "application/json", &body).await
        }
        ("GET", p) if p.starts_with("/session/") => {
            let key = &p["/session/".len()..];
            match session_transcript(&ctx.audit, key) {
                Some(body) => write_simple(&mut sock, "200 OK", "application/json", &body).await,
                None => {
                    write_simple(
                        &mut sock,
                        "404 Not Found",
                        "text/plain",
                        b"no such session\n",
                    )
                    .await
                }
            }
        }
        _ => write_simple(&mut sock, "404 Not Found", "text/plain", b"404 not found\n").await,
    }
}

fn id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'@' | b'.' | b':' | b'_' | b'-')
                || (b == b'_')
                || (i > 0 && b.is_ascii_digit())
        })
        && id.as_bytes()[0].is_ascii_digit()
}

#[derive(serde::Serialize)]
struct SessionInfo {
    /// Unique handle for this past session = the file stem `<id>-<open_ms>`.
    /// Session ids reset per server run, so the id alone is NOT unique across
    /// runs; the key is what /session/<key> resolves.
    key: String,
    id: String,
    label: String,
    transport: String,
    started_ms: u64,
    /// Last activity = the file's modification time in epoch millis (falls back
    /// to `started_ms` if the mtime is unavailable). Drives the relative time
    /// and the absolute "last activity" tooltip in the history panel.
    last_ms: u64,
    size: u64,
}

/// List past session files in the audit dir (dir mode). Empty if `audit` is not
/// a directory (single-file mode has no per-session history).
fn list_sessions(audit: &Path) -> Vec<SessionInfo> {
    let mut out = Vec::new();
    if !audit.is_dir() {
        return out;
    }
    let rd = match std::fs::read_dir(audit) {
        Ok(r) => r,
        Err(_) => return out,
    };
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().to_string();
        // <id>-<open_ms>.jsonl
        let stem = match name.strip_suffix(".jsonl") {
            Some(s) => s,
            None => continue,
        };
        let (id, ts) = match stem.rsplit_once('-') {
            Some(x) => x,
            None => continue,
        };
        if !id_ok(id) {
            continue;
        }
        let started_ms = ts.parse().unwrap_or(0);
        let meta = ent.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let last_ms = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .filter(|&ms| ms > 0)
            .unwrap_or(started_ms);
        let (transport, label) = split_label(id);
        out.push(SessionInfo {
            key: stem.to_string(),
            id: id.to_string(),
            label,
            transport,
            started_ms,
            last_ms,
            size,
        });
    }
    out.sort_by_key(|s| std::cmp::Reverse(s.started_ms)); // newest first
    out
}

/// Parse transport + friendly label out of an id like `2_ssh_u@h` / `1_local`.
fn split_label(id: &str) -> (String, String) {
    let rest = id.split_once('_').map(|x| x.1).unwrap_or(""); // after the number
    let (transport, tail) = rest.split_once('_').unwrap_or((rest, ""));
    let label = if transport == "local" || tail.is_empty() {
        transport.to_string()
    } else {
        tail.to_string()
    };
    (transport.to_string(), label)
}

/// Render one past session's transcript. Id is validated and resolved ONLY
/// within `audit`; no traversal. None if missing/invalid.
fn session_transcript(audit: &Path, key: &str) -> Option<Vec<u8>> {
    if !audit.is_dir() || !id_ok(key) {
        return None;
    }
    // `key` is the unique file stem `<id>-<open_ms>`. Resolve by scanning the
    // dir for an exact stem match (never build a path from the key), so two
    // same-id sessions from different runs stay distinguishable.
    let rd = std::fs::read_dir(audit).ok()?;
    let mut found: Option<std::path::PathBuf> = None;
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().to_string();
        if name.strip_suffix(".jsonl") == Some(key) {
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

/// Find the start index of `needle` in `hay`.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// POST /state: read Content-Length bytes, validate, save; 400 on bad/oversized.
async fn handle_post_state(
    sock: &mut TcpStream,
    ctx: &Ctx,
    head: &str,
    already: &[u8],
    head_end: Option<usize>,
) -> std::io::Result<()> {
    let len: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().to_string())
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if len > meta::MAX_STATE_BYTES {
        return write_simple(sock, "400 Bad Request", "text/plain", b"state too large\n").await;
    }
    // len is already checked <= MAX_STATE_BYTES above.
    let mut body = Vec::with_capacity(len);
    if let Some(he) = head_end {
        let pre = &already[he..];
        body.extend_from_slice(&pre[..pre.len().min(len)]); // never exceed Content-Length
    }
    while body.len() < len {
        let mut chunk = [0u8; 4096];
        let r = sock.read(&mut chunk).await?;
        if r == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..r]);
        if body.len() > meta::MAX_STATE_BYTES {
            break;
        }
    }
    match meta::parse_validated(&body) {
        Ok(st) => match meta::save(&ctx.state_path, &st) {
            Ok(()) => write_simple(sock, "200 OK", "application/json", b"{\"ok\":true}").await,
            Err(_) => {
                write_simple(
                    sock,
                    "500 Internal Server Error",
                    "text/plain",
                    b"save failed\n",
                )
                .await
            }
        },
        Err(e) => {
            write_simple(
                sock,
                "400 Bad Request",
                "text/plain",
                format!("{e}\n").as_bytes(),
            )
            .await
        }
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
        sock.write_all(format!("data: {msg}\n\n").as_bytes())
            .await?;
    }
    sock.flush().await?;

    loop {
        match rx.recv().await {
            Ok(msg) => {
                sock.write_all(format!("data: {msg}\n\n").as_bytes())
                    .await?;
                sock.flush().await?;
            }
            // Lagged: drop missed messages, keep streaming.
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

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
        (
            "cmd",
            vec!["/C".into(), "start".into(), String::new(), url.to_string()],
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Write a tiny audit log, serve it, return (addr, token, tempfile path).
    fn seed_audit() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ek_web_{}.jsonl", std::process::id()));
        let mut f = std::fs::File::create(&p).unwrap();
        // one Open + one Exec for session 1_local
        writeln!(
            f,
            r#"{{"event":"open","ts":1,"session":"1_local","transport":"local"}}"#
        )
        .unwrap();
        writeln!(f, r#"{{"event":"exec","ts":2,"session":"1_local","transport":"local","command":"echo hi","stdout":"hi","stderr":"","exit_code":0,"duration_ms":3,"cwd":"/tmp","truncated":false}}"#).unwrap();
        p
    }

    // Minimal HTTP POST; returns the full response text.
    async fn http_post(addr: std::net::SocketAddr, target: &str, body: &str) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "POST {target} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut b = vec![0u8; 4096];
        let n = tokio::time::timeout(std::time::Duration::from_millis(500), s.read(&mut b))
            .await
            .map(|r| r.unwrap_or(0))
            .unwrap_or(0);
        String::from_utf8_lossy(&b[..n]).to_string()
    }

    // Minimal HTTP GET; returns the full response text (headers + body so far).
    async fn http_get(addr: std::net::SocketAddr, target: &str, read_ms: u64) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = vec![0u8; 8192];
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
        let (addr, _h) = serve(path.clone(), token.clone(), 0).await.unwrap();

        // No token -> 403 on both routes.
        assert!(http_get(addr, "/", 300).await.starts_with("HTTP/1.1 403"));
        assert!(http_get(addr, "/events", 300)
            .await
            .starts_with("HTTP/1.1 403"));

        // Page with token -> 200 html containing our script anchor.
        let page = http_get(addr, &format!("/?t={token}"), 300).await;
        assert!(
            page.starts_with("HTTP/1.1 200"),
            "page status: {}",
            &page[..page.len().min(40)]
        );
        assert!(page.contains("text/html"));
        assert!(page.contains("/events?t="));

        // Events with token -> text/event-stream, replays the seeded exec.
        let ev = http_get(addr, &format!("/events?t={token}"), 800).await;
        assert!(
            ev.contains("text/event-stream"),
            "sse content-type missing: {ev}"
        );
        assert!(
            ev.contains("/tmp $ echo hi"),
            "replayed prompt missing: {ev}"
        );
        assert!(
            ev.contains("\"session\":\"1_local\""),
            "session tag missing: {ev}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_or_create_token_persists_and_reuses() {
        let p = std::env::temp_dir().join(format!("ek_tok_{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let a = load_or_create_token(&p).unwrap();
        assert_eq!(a.len(), 32, "32 hex chars");
        let b = load_or_create_token(&p).unwrap();
        assert_eq!(a, b, "second call reuses the persisted token");
        let _ = std::fs::remove_file(&p);
    }

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
        let line = StyledLine {
            text: "/tmp $ ls".into(),
            kind: LineKind::Prompt,
        };
        let v: serde_json::Value = serde_json::from_str(&wire_json("1_local", &line)).unwrap();
        assert_eq!(v["session"], "1_local");
        assert_eq!(v["kind"], "prompt");
        assert_eq!(v["text"], "/tmp $ ls");
    }

    #[tokio::test]
    async fn state_get_post_round_trip_and_token_and_validation() {
        // Isolate the state file by pointing HOME at a temp dir.
        let home = std::env::temp_dir().join(format!("ek_uxhome_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&home);
        let prior_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);
        let path = seed_audit();
        let token = "tok".to_string();
        let (addr, _h) = serve(path.clone(), token.clone(), 0).await.unwrap();

        // no token -> 403 on both methods
        assert!(http_get(addr, "/state", 300)
            .await
            .starts_with("HTTP/1.1 403"));
        assert!(http_post(addr, "/state", "{}")
            .await
            .starts_with("HTTP/1.1 403"));

        // valid POST persists; GET returns it
        let ok = http_post(
            addr,
            &format!("/state?t={token}"),
            r#"{"sessions":{"1_local":{"alias":"build"}}}"#,
        )
        .await;
        assert!(ok.starts_with("HTTP/1.1 200"), "post: {ok}");
        let got = http_get(addr, &format!("/state?t={token}"), 300).await;
        assert!(got.contains("\"alias\":\"build\""), "get: {got}");

        // malformed -> 400
        let bad = http_post(addr, &format!("/state?t={token}"), "{ not json").await;
        assert!(bad.starts_with("HTTP/1.1 400"), "bad: {bad}");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&home);
        match prior_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
    }

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
            assert_eq!(
                args,
                vec![
                    "/C".to_string(),
                    "start".to_string(),
                    "".to_string(),
                    "http://127.0.0.1:9/?t=x".to_string()
                ]
            );
        }
    }

    #[tokio::test]
    async fn sessions_list_and_transcript_and_reject_traversal() {
        // dir-mode audit with two per-session files
        let dir = std::env::temp_dir().join(format!("ek_uxdir_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("1_local-100.jsonl"),
            "{\"event\":\"open\",\"ts\":100,\"session\":\"1_local\",\"transport\":\"local\"}\n{\"event\":\"exec\",\"ts\":101,\"session\":\"1_local\",\"transport\":\"local\",\"command\":\"echo hi\",\"stdout\":\"hi\",\"stderr\":\"\",\"exit_code\":0,\"duration_ms\":3,\"cwd\":\"/tmp\",\"truncated\":false}\n").unwrap();
        std::fs::write(
            dir.join("2_ssh_u@h-200.jsonl"),
            "{\"event\":\"open\",\"ts\":200,\"session\":\"2_ssh_u@h\",\"transport\":\"ssh\"}\n",
        )
        .unwrap();
        let token = "tok".to_string();
        let (addr, _h) = serve(dir.clone(), token.clone(), 0).await.unwrap();

        let list = http_get(addr, &format!("/sessions?t={token}"), 400).await;
        assert!(
            list.contains("\"id\":\"2_ssh_u@h\"") && list.contains("\"transport\":\"ssh\""),
            "list: {list}"
        );
        assert!(list.contains("\"label\":\"u@h\""), "label: {list}");
        // each entry carries its unique file-stem key (so same-id sessions across
        // runs stay distinguishable).
        assert!(list.contains("\"key\":\"1_local-100\""), "key: {list}");

        // resolve by the unique key (stem), not the bare id
        let tr = http_get(addr, &format!("/session/1_local-100?t={token}"), 400).await;
        assert!(tr.contains("/tmp $ echo hi"), "transcript: {tr}");

        // the bare id (no timestamp) no longer resolves a file -> 404
        let bare = http_get(addr, &format!("/session/1_local?t={token}"), 400).await;
        assert!(bare.contains("404"), "bare id must 404: {bare}");

        // traversal / bad id -> 404 (id_ok rejects it; nothing served)
        let trav = http_get(addr, &format!("/session/../../etc/passwd?t={token}"), 400).await;
        assert!(trav.contains("404"), "traversal must 404: {trav}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
