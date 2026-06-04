// SPDX-License-Identifier: Apache-2.0
//! nexum-mcp — an MCP (stdio) server exposing nexum shell sessions to any
//! MCP-capable agent (Claude Code, Cursor, Gemini CLI, ...).
//!
//! Tools: `session_create`, `session_exec`, `session_destroy`. Sessions are
//! stateful and outlive a single tool call; `session_exec` returns the
//! structured `ExecResult` as JSON (split stdout/stderr, exit code, cwd, ...),
//! already policy-checked, secret-redacted, and bounded.
//!
//! ## Threat model
//!
//! The agent driving these tools can be prompt-injected, so tool arguments are
//! treated as untrusted. Anything that affects the host or filesystem in a
//! dangerous way is configured by the **operator at startup** (env vars), not by
//! per-call agent arguments:
//!   - `NEXUM_MCP_AUDIT`       — append a JSONL audit log here (all sessions).
//!   - `NEXUM_MCP_KEY_DIR`     — dir SSH private keys must live under (default ~/.ssh).
//!   - `NEXUM_MCP_KNOWN_HOSTS` — SSH known_hosts file (default ~/.ssh/known_hosts).
//!   - `NEXUM_MCP_INSECURE_ACCEPT_ANY_HOSTKEY=1` — DANGEROUS: disable host-key
//!     verification. Never in production.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::Deserialize;

use nexum::{AuditLog, HostKeyVerification, Policy, Session, SshAuth, SshConfig};

/// A session guarded by its own mutex (nexum::Session is Send but not Sync;
/// blocking `exec` runs on a blocking thread holding only this lock).
type SessionRef = Arc<Mutex<Session>>;
type Sessions = Arc<Mutex<HashMap<String, SessionRef>>>;

/// Operator-controlled configuration (from env), NOT settable per tool call.
struct Config {
    audit_path: Option<PathBuf>,
    key_dir: PathBuf,
    known_hosts: PathBuf,
    insecure_accept_any: bool,
    /// Soft cap on concurrent live sessions (bounds thread/connection growth
    /// from untrusted create calls).
    max_sessions: usize,
}

impl Config {
    fn from_env() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        let ssh = Path::new(&home).join(".ssh");
        Config {
            audit_path: std::env::var_os("NEXUM_MCP_AUDIT").map(PathBuf::from),
            key_dir: std::env::var_os("NEXUM_MCP_KEY_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| ssh.clone()),
            known_hosts: std::env::var_os("NEXUM_MCP_KNOWN_HOSTS")
                .map(PathBuf::from)
                .unwrap_or_else(|| ssh.join("known_hosts")),
            insecure_accept_any: std::env::var_os("NEXUM_MCP_INSECURE_ACCEPT_ANY_HOSTKEY")
                .is_some(),
            max_sessions: std::env::var("NEXUM_MCP_MAX_SESSIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(64),
        }
    }
}

/// Lock a std Mutex, recovering the guard if a prior holder panicked — a
/// poisoned lock must not brick the session (inner) or the whole server (outer).
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone)]
struct NexumServer {
    // Read by the code the #[tool_handler] macro generates; Rust's dead-code
    // analysis can't see through the macro, hence the allow.
    #[allow(dead_code)]
    tool_router: ToolRouter<NexumServer>,
    sessions: Sessions,
    config: Arc<Config>,
}

#[derive(Deserialize, JsonSchema)]
struct CreateParams {
    /// Transport: "local" (a local shell) or "ssh".
    transport: String,
    /// SSH host (required for ssh).
    #[serde(default)]
    host: Option<String>,
    /// SSH port (default 22).
    #[serde(default)]
    port: Option<u16>,
    /// SSH user (required for ssh).
    #[serde(default)]
    user: Option<String>,
    /// SSH password auth.
    #[serde(default)]
    password: Option<String>,
    /// SSH private-key path (must live under the operator's key dir).
    #[serde(default)]
    key_path: Option<String>,
    /// Optional pinned host-key fingerprint ("SHA256:..."). If set, the server
    /// requires the host key to match exactly. Otherwise the operator's
    /// known_hosts file is used.
    #[serde(default)]
    fingerprint: Option<String>,
    /// Optional command allowlist (program names). If set, only these run.
    #[serde(default)]
    allow: Vec<String>,
    /// Optional command denylist (program names).
    #[serde(default)]
    deny: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
struct ExecParams {
    /// Session id from session_create.
    session_id: String,
    /// The shell command to run.
    command: String,
}

#[derive(Deserialize, JsonSchema)]
struct SessionIdParams {
    /// Session id from session_create.
    session_id: String,
}

#[tool_router]
impl NexumServer {
    fn new(config: Config) -> Self {
        Self {
            tool_router: Self::tool_router(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(config),
        }
    }

    #[tool(
        description = "Open a stateful shell session. transport is \"local\" or \"ssh\" \
                       (ssh needs host, user, and password or key_path). Optional fingerprint \
                       (pin host key), allow/deny command lists. Returns a session_id."
    )]
    async fn session_create(
        &self,
        Parameters(p): Parameters<CreateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // Soft cap before doing the (potentially expensive) connect.
        if lock(&self.sessions).len() >= self.config.max_sessions {
            return Ok(tool_error(format!(
                "session limit reached ({}); destroy unused sessions",
                self.config.max_sessions
            )));
        }
        let config = self.config.clone();
        let built = tokio::task::spawn_blocking(move || build_session(p, &config))
            .await
            .map_err(internal)?;
        match built {
            Ok(session) => {
                let id = next_id();
                lock(&self.sessions).insert(id.clone(), Arc::new(Mutex::new(session)));
                Ok(text(format!("{{\"session_id\":\"{id}\"}}")))
            }
            Err(e) => Ok(tool_error(format!("session_create failed: {e}"))),
        }
    }

    #[tool(description = "Run a command in a session; returns a structured ExecResult JSON \
                          (stdout, stderr, exit_code, duration_ms, cwd, truncated).")]
    async fn session_exec(
        &self,
        Parameters(p): Parameters<ExecParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = self.get(&p.session_id)?;
        let command = p.command;
        // Concurrent execs on the SAME session serialize on this lock (the
        // outer map lock is already released). `lock` recovers from poisoning.
        let outcome = tokio::task::spawn_blocking(move || lock(&session).exec(&command))
            .await
            .map_err(internal)?;
        match outcome {
            Ok(r) => {
                let json = serde_json::to_string_pretty(&r).map_err(internal)?;
                Ok(text(json))
            }
            Err(e) => Ok(tool_error(e.to_string())),
        }
    }

    #[tool(description = "Destroy a session and free its resources.")]
    async fn session_destroy(
        &self,
        Parameters(p): Parameters<SessionIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let removed = lock(&self.sessions).remove(&p.session_id).is_some();
        Ok(text(format!("{{\"destroyed\":{removed}}}")))
    }
}

impl NexumServer {
    fn get(&self, id: &str) -> Result<SessionRef, ErrorData> {
        lock(&self.sessions)
            .get(id)
            .cloned()
            .ok_or_else(|| ErrorData::invalid_params(format!("unknown session_id: {id}"), None))
    }
}

#[tool_handler]
impl ServerHandler for NexumServer {
    fn get_info(&self) -> ServerInfo {
        // ServerInfo is #[non_exhaustive] — start from default and assign.
        let mut info = ServerInfo::default();
        info.instructions = Some(
            "Stateful, structured, safe shell sessions for agents. Call session_create \
             (local or ssh) to get a session_id, session_exec to run commands (structured \
             results), and session_destroy when done. State (cwd, env) persists across execs."
                .into(),
        );
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }
}

fn build_session(p: CreateParams, config: &Config) -> Result<Session, nexum::Error> {
    let mut session = match p.transport.as_str() {
        "ssh" => {
            let host = p
                .host
                .ok_or_else(|| nexum::Error::Transport("ssh: 'host' required".into()))?;
            let user = p
                .user
                .ok_or_else(|| nexum::Error::Transport("ssh: 'user' required".into()))?;
            let auth = if let Some(pw) = p.password {
                SshAuth::Password(pw)
            } else if let Some(key) = p.key_path {
                // Constrain to the operator's key dir; generic error so the path's
                // existence/parseability never leaks to the (untrusted) caller.
                let path = validated_key_path(&key, &config.key_dir)?;
                SshAuth::Key { path, passphrase: None }
            } else {
                return Err(nexum::Error::Transport(
                    "ssh: 'password' or 'key_path' required".into(),
                ));
            };
            // Host-key policy: pin if a fingerprint is supplied (safe — no file
            // I/O on a caller path); otherwise verify against the operator's
            // known_hosts; AcceptAny ONLY via explicit insecure opt-in.
            let host_key = if let Some(fp) = p.fingerprint {
                HostKeyVerification::Pinned(fp)
            } else if config.insecure_accept_any {
                HostKeyVerification::AcceptAny
            } else {
                HostKeyVerification::KnownHosts(config.known_hosts.clone())
            };
            let mut cfg = SshConfig::new(host, user, auth, host_key);
            if let Some(port) = p.port {
                cfg.port = port;
            }
            Session::ssh(cfg)?
        }
        _ => Session::local()?,
    };
    if !p.allow.is_empty() || !p.deny.is_empty() {
        session = session.with_policy(Policy { allow: p.allow, deny: p.deny });
    }
    // Audit destination is operator-controlled (startup), never a tool arg.
    if let Some(path) = &config.audit_path {
        session = session.with_audit(AuditLog::new(path));
    }
    Ok(session)
}

/// Resolve a caller-supplied key path and require it to live under `key_dir`.
/// Uses canonicalization (resolves `..` and symlinks) and returns a single
/// generic error so a not-found vs. out-of-bounds path is indistinguishable.
fn validated_key_path(raw: &str, key_dir: &Path) -> Result<PathBuf, nexum::Error> {
    let deny = || nexum::Error::Transport("ssh: key_path not permitted".into());
    let dir = std::fs::canonicalize(key_dir).map_err(|_| deny())?;
    let path = std::fs::canonicalize(raw).map_err(|_| deny())?;
    if path.starts_with(&dir) {
        Ok(path)
    } else {
        Err(deny())
    }
}

fn text(s: String) -> CallToolResult {
    CallToolResult::success(vec![Content::text(s)])
}

fn tool_error(s: String) -> CallToolResult {
    CallToolResult::error(vec![Content::text(s)])
}

fn next_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    format!("sess_{}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn internal<E: std::fmt::Display>(e: E) -> ErrorData {
    ErrorData::internal_error(e.to_string(), None)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // stdout is the MCP channel — all diagnostics go to stderr.
    let config = Config::from_env();
    eprintln!("nexum-mcp: starting MCP server on stdio");
    if std::env::var_os("HOME").is_none() {
        eprintln!(
            "nexum-mcp: NOTE HOME is unset — SSH key dir / known_hosts default under \
             /root/.ssh; set NEXUM_MCP_KEY_DIR / NEXUM_MCP_KNOWN_HOSTS explicitly."
        );
    }
    if config.insecure_accept_any {
        eprintln!(
            "nexum-mcp: WARNING NEXUM_MCP_INSECURE_ACCEPT_ANY_HOSTKEY is set — \
             SSH host-key verification is DISABLED (MITM possible). Do not use in production."
        );
    }
    let service = NexumServer::new(config).serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
