// SPDX-License-Identifier: Apache-2.0
//! A live, read-only web viewer for the audit log. A hand-rolled HTTP/SSE
//! server (loopback only, token-gated) tails the same Source the TUI uses,
//! renders events with render_event, and streams the rendered lines as JSON to
//! a self-contained page. Read-only: no endpoint mutates anything.
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use crate::watch::render::{render_event, LineKind, StyledLine};
use crate::watch::source::Source;

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
    let supplied = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("t="))
        .unwrap_or("");

    if supplied != token.as_str() {
        return write_simple(&mut sock, "403 Forbidden", "text/plain", b"403 forbidden\n").await;
    }
    match path {
        "/" => {
            write_simple(
                &mut sock,
                "200 OK",
                "text/html; charset=utf-8",
                PAGE.as_bytes(),
            )
            .await
        }
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
        let (addr, _h) = serve(path.clone(), token.clone()).await.unwrap();

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
}
