// SPDX-License-Identifier: Apache-2.0
//! execkit-mcp - an MCP (stdio) server exposing execkit shell sessions to any
//! MCP-capable agent (Claude Code, Cursor, Gemini CLI, ...).
//!
//! Tools: `session_create`, `session_exec`, `session_destroy`, and (remote only)
//! `session_checkpoint`, `session_checkpoints`, `session_restore`. Sessions are
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
//!   - `EXECKIT_MCP_AUDIT`       - append a JSONL audit log here (all sessions).
//!   - `EXECKIT_MCP_KEY_DIR`     - dir SSH private keys must live under (default ~/.ssh).
//!   - `EXECKIT_MCP_KNOWN_HOSTS` - SSH known_hosts file (default ~/.ssh/known_hosts).
//!   - `EXECKIT_MCP_INSECURE_ACCEPT_ANY_HOSTKEY=1` - DANGEROUS: disable host-key
//!     verification. Never in production.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::Deserialize;

use execkit::{Budget, Grep, HostKeyVerification, Keep, Policy, Session, SshAuth, SshConfig};
use execkit_mcp::audit::AuditWriter;

/// A live session plus the last time a handler touched it (for idle reaping).
/// `last_used` is a separate inner mutex so bumping the timestamp never waits on
/// a long-running `exec` that holds `session`.
struct SessionEntry {
    session: Mutex<Session>,
    last_used: Mutex<Instant>,
    transport: String,
}
type SessionRef = Arc<SessionEntry>;
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
    /// None disables idle reaping; Some(d) reaps sessions idle longer than d.
    session_ttl: Option<Duration>,
}

impl Config {
    fn from_env() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        let ssh = Path::new(&home).join(".ssh");
        Config {
            audit_path: std::env::var_os("EXECKIT_MCP_AUDIT").map(PathBuf::from),
            key_dir: std::env::var_os("EXECKIT_MCP_KEY_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| ssh.clone()),
            known_hosts: std::env::var_os("EXECKIT_MCP_KNOWN_HOSTS")
                .map(PathBuf::from)
                .unwrap_or_else(|| ssh.join("known_hosts")),
            insecure_accept_any: std::env::var_os("EXECKIT_MCP_INSECURE_ACCEPT_ANY_HOSTKEY")
                .is_some(),
            max_sessions: std::env::var("EXECKIT_MCP_MAX_SESSIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(64),
            session_ttl: match std::env::var("EXECKIT_MCP_SESSION_TTL")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
            {
                Some(0) => None,                         // explicitly disabled
                Some(s) => Some(Duration::from_secs(s)), // operator override
                None => Some(Duration::from_secs(1800)), // default 30 min
            },
        }
    }
}

/// Lock a std Mutex, recovering the guard if a prior holder panicked - a
/// poisoned lock must not brick the session (inner) or the whole server (outer).
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone)]
struct ExeckitServer {
    // Read by the code the #[tool_handler] macro generates; Rust's dead-code
    // analysis can't see through the macro, hence the allow.
    #[allow(dead_code)]
    tool_router: ToolRouter<ExeckitServer>,
    sessions: Sessions,
    config: Arc<Config>,
    /// Atomic admission counter: the source of truth for the live-session cap.
    /// Reserved (fetch_add) at the START of session_create BEFORE the blocking
    /// build, so the check-and-reserve is a single atomic step (no TOCTOU). The
    /// sessions map stays the lookup table; this is the gate. Released on build
    /// failure and on destroy.
    live: Arc<AtomicUsize>,
    audit: Option<std::sync::Arc<AuditWriter>>,
}

#[derive(Deserialize, JsonSchema)]
struct CreateParams {
    /// Transport: "local" (a local shell), "ssh", or "docker".
    transport: String,
    /// Docker container name or id (required for docker).
    #[serde(default)]
    container: Option<String>,
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
    /// Auto-snapshot before changing remote commands (default true, but only takes
    /// effect once `workspace` is set; remote only).
    #[serde(default = "default_true")]
    auto_snapshot: bool,
    /// Remote workspace root for checkpoints. REQUIRED to enable checkpoints; there
    /// is no default (it will not snapshot the cwd/home dir).
    #[serde(default)]
    workspace: Option<String>,
    /// Sub-paths under the root to checkpoint (optional; default: whole root).
    #[serde(default)]
    paths: Vec<String>,
    /// Extra exclude patterns (gitignore syntax) added to the snapshot, on top of
    /// the built-in defaults (.git, node_modules, caches, .ssh, ...).
    #[serde(default)]
    checkpoint_ignores: Vec<String>,
    /// Default output budget for every exec in this session (optional).
    #[serde(default)]
    output_budget: Option<BudgetParams>,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize, JsonSchema)]
struct GrepParams {
    /// Regex; keep only matching lines.
    pattern: String,
    /// Context lines kept on each side of a match (default 0).
    #[serde(default)]
    context: usize,
}

#[derive(Deserialize, JsonSchema)]
struct KeepParams {
    /// One of: "all", "tail", "head", "head_tail".
    mode: String,
    /// Line count for tail/head.
    #[serde(default)]
    n: Option<usize>,
    /// For head_tail: leading lines.
    #[serde(default)]
    head: Option<usize>,
    /// For head_tail: trailing lines.
    #[serde(default)]
    tail: Option<usize>,
}

/// Output-shaping budget: grep -> line-keep -> char cap. All fields optional.
#[derive(Deserialize, JsonSchema)]
struct BudgetParams {
    #[serde(default)]
    grep: Option<GrepParams>,
    #[serde(default)]
    keep: Option<KeepParams>,
    #[serde(default)]
    max_chars: Option<usize>,
}

impl BudgetParams {
    fn to_budget(&self) -> Result<Budget, String> {
        let keep = match &self.keep {
            None => Keep::All,
            Some(k) => match k.mode.as_str() {
                "all" => Keep::All,
                "tail" => Keep::Tail(k.n.unwrap_or(0)),
                "head" => Keep::Head(k.n.unwrap_or(0)),
                "head_tail" => Keep::HeadTail(k.head.unwrap_or(0), k.tail.unwrap_or(0)),
                other => return Err(format!("unknown keep mode: {other}")),
            },
        };
        Ok(Budget {
            grep: self.grep.as_ref().map(|g| Grep {
                pattern: g.pattern.clone(),
                context: g.context,
            }),
            keep,
            max_chars: self.max_chars,
        })
    }
}

#[derive(Deserialize, JsonSchema)]
struct ExecParams {
    /// Session id from session_create.
    session_id: String,
    /// The shell command to run.
    command: String,
    /// Shape THIS command's output (overrides the session default).
    #[serde(default)]
    budget: Option<BudgetParams>,
}

#[derive(Deserialize, JsonSchema)]
struct SessionIdParams {
    /// Session id from session_create.
    session_id: String,
}

#[derive(Deserialize, JsonSchema)]
struct CheckpointParams {
    /// Session id from session_create.
    session_id: String,
    /// Optional human label for the checkpoint.
    #[serde(default)]
    label: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct RestoreParams {
    /// Session id from session_create.
    session_id: String,
    /// Checkpoint id to restore; omit to restore the most recent.
    #[serde(default)]
    checkpoint_id: Option<String>,
}

#[tool_router]
impl ExeckitServer {
    fn new(config: Config) -> Self {
        let audit = config
            .audit_path
            .clone()
            .map(|p| std::sync::Arc::new(AuditWriter::new(p)));
        Self {
            tool_router: Self::tool_router(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(config),
            live: Arc::new(AtomicUsize::new(0)),
            audit,
        }
    }

    #[tool(
        description = "Open a stateful shell session. transport is \"local\", \"ssh\", or \
                       \"docker\". ssh needs host, user, and password or key_path; docker needs \
                       container (a running container name/id). Optional fingerprint (pin host \
                       key), allow/deny command lists. Returns a session_id. \
                       Remote sessions support workspace checkpoints - requires git on \
                       the remote AND an explicit workspace (set 'workspace'; without it \
                       checkpoints/auto_snapshot are disabled, never defaulting to the \
                       home dir). Tune with auto_snapshot, paths, checkpoint_ignores. \
                       Pass output_budget (same shape as session_exec's budget) to \
                       default-shape every command's output."
    )]
    async fn session_create(
        &self,
        Parameters(p): Parameters<CreateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // Reclaim slots from sessions abandoned past the idle TTL before
        // reserving, so a full cap of idle sessions cannot reject this create.
        self.reap_idle();
        // Atomically reserve a slot BEFORE the (potentially expensive, awaited)
        // connect. fetch_add returns the prior value; if it was already at the
        // cap, undo the reservation and reject. This is the single source of
        // truth for admission - concurrent creates can never all slip past a
        // dropped lock the way a check-then-insert on the map could.
        if self.live.fetch_add(1, Ordering::AcqRel) >= self.config.max_sessions {
            self.live.fetch_sub(1, Ordering::AcqRel);
            return Ok(tool_error(format!(
                "session limit reached ({}); destroy unused sessions",
                self.config.max_sessions
            )));
        }
        // Past this point the slot is reserved: EVERY path must either insert a
        // live session (keeping the reservation) or release it (fetch_sub).
        let transport = transport_label(&p);
        let config = self.config.clone();
        let built = match tokio::task::spawn_blocking(move || build_session(p, &config)).await {
            Ok(built) => built,
            Err(e) => {
                // Join error (panic/cancel): release the reserved slot.
                self.live.fetch_sub(1, Ordering::AcqRel);
                return Err(internal(e));
            }
        };
        match built {
            Ok(session) => {
                let id = next_id();
                lock(&self.sessions).insert(
                    id.clone(),
                    Arc::new(SessionEntry {
                        session: Mutex::new(session),
                        last_used: Mutex::new(Instant::now()),
                        transport: transport.clone(),
                    }),
                );
                if let Some(a) = &self.audit {
                    a.open(&id, &transport);
                }
                Ok(text(format!("{{\"session_id\":\"{id}\"}}")))
            }
            Err(e) => {
                // Build failed: no session was inserted, release the slot.
                self.live.fetch_sub(1, Ordering::AcqRel);
                Ok(tool_error(format!("session_create failed: {e}")))
            }
        }
    }

    #[tool(
        description = "Run a command in a session; returns a structured ExecResult JSON \
                          (stdout, stderr, exit_code, duration_ms, cwd, truncated). \
                          Optionally pass budget to shape output: {grep:{pattern,context?}, \
                          keep:{mode:\"all\"|\"tail\"|\"head\"|\"head_tail\",n?|head?+tail?}, max_chars?}. \
                          Shaping is line-based, client-side, AFTER secret redaction; it never \
                          changes the exit code or side effects. When applied, the result \
                          includes a budget report (per-stream mode + lines_total/lines_kept)."
    )]
    async fn session_exec(
        &self,
        Parameters(p): Parameters<ExecParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = self.get(&p.session_id)?;
        let session_id = p.session_id.clone();
        let transport = session.transport.clone();
        let command = p.command;
        let budget = match p.budget.as_ref().map(|b| b.to_budget()) {
            Some(Ok(b)) => Some(b),
            Some(Err(e)) => return Ok(tool_error(e)),
            None => None,
        };
        // Concurrent execs on the SAME session serialize on this lock (the
        // outer map lock is already released). `lock` recovers from poisoning.
        let outcome = tokio::task::spawn_blocking(move || match budget {
            Some(b) => lock(&session.session).exec_budgeted(&command, &b),
            None => lock(&session.session).exec(&command),
        })
        .await
        .map_err(internal)?;
        match outcome {
            Ok(r) => {
                if let Some(a) = &self.audit {
                    a.exec(&session_id, &transport, &r);
                }
                let json = serde_json::to_string_pretty(&r).map_err(internal)?;
                Ok(text(json))
            }
            Err(e) => Ok(tool_error(e.to_string())),
        }
    }

    #[tool(
        description = "Take a workspace checkpoint on a REMOTE session (snapshot of \
                       files you can restore). Requires git on the remote host. \
                       Undoes FILES only - not side effects (DB, network, installs). \
                       Returns { checkpoint_id }."
    )]
    async fn session_checkpoint(
        &self,
        Parameters(p): Parameters<CheckpointParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = self.get(&p.session_id)?;
        let label = p.label;
        let outcome = tokio::task::spawn_blocking(move || {
            lock(&session.session).checkpoint(label.as_deref())
        })
        .await
        .map_err(internal)?;
        match outcome {
            Ok(id) => Ok(text(format!("{{\"checkpoint_id\":\"{}\"}}", id.0))),
            Err(e) => Ok(tool_error(e.to_string())),
        }
    }

    #[tool(description = "List checkpoints (newest first) for a remote session.")]
    async fn session_checkpoints(
        &self,
        Parameters(p): Parameters<SessionIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = self.get(&p.session_id)?;
        let outcome = tokio::task::spawn_blocking(move || lock(&session.session).checkpoints())
            .await
            .map_err(internal)?;
        match outcome {
            Ok(list) => {
                let json = serde_json::to_string_pretty(&list).map_err(internal)?;
                Ok(text(json))
            }
            Err(e) => Ok(tool_error(e.to_string())),
        }
    }

    #[tool(
        description = "Restore a remote session's workspace FILES to a checkpoint \
                       (omit checkpoint_id to restore the most recent). Does not \
                       undo side effects."
    )]
    async fn session_restore(
        &self,
        Parameters(p): Parameters<RestoreParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = self.get(&p.session_id)?;
        let id = p.checkpoint_id;
        let outcome = tokio::task::spawn_blocking(move || {
            let mut s = lock(&session.session);
            match id {
                Some(cid) => s.restore(&execkit::CheckpointId(cid)),
                None => s.restore_last(),
            }
        })
        .await
        .map_err(internal)?;
        match outcome {
            Ok(r) => Ok(text(serde_json::to_string(&r).map_err(internal)?)),
            Err(e) => Ok(tool_error(e.to_string())),
        }
    }

    #[tool(description = "Destroy a session and free its resources.")]
    async fn session_destroy(
        &self,
        Parameters(p): Parameters<SessionIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let removed = lock(&self.sessions).remove(&p.session_id);
        // Release the admission slot only if a session was actually present, so
        // a double-destroy (or destroy of an unknown id) can't underflow the
        // counter and free a slot that was never reserved by this session.
        let destroyed = removed.is_some();
        if let Some(entry) = removed {
            self.live.fetch_sub(1, Ordering::AcqRel);
            if let Some(a) = &self.audit {
                a.close(&p.session_id, "destroyed");
            }
            // Session::drop is blocking (PTY kill / SSH teardown / docker reap);
            // do it off the async executor and not under the map lock.
            tokio::task::spawn_blocking(move || drop(entry));
        }
        Ok(text(format!("{{\"destroyed\":{destroyed}}}")))
    }
}

impl ExeckitServer {
    fn get(&self, id: &str) -> Result<SessionRef, ErrorData> {
        let entry = lock(&self.sessions)
            .get(id)
            .cloned()
            .ok_or_else(|| ErrorData::invalid_params(format!("unknown session_id: {id}"), None))?;
        *lock(&entry.last_used) = Instant::now(); // touch on every use
        Ok(entry)
    }

    /// Drop sessions idle longer than the TTL. Selects entries idle past the TTL
    /// AND not currently locked (a session a handler is mid-exec on fails
    /// try_lock and is skipped). Removes them under the map lock, decrements the
    /// cap once each, then drops the (blocking) Session off the async executor.
    /// No-op when the TTL is disabled. Returns the number reaped.
    fn reap_idle(&self) -> usize {
        let Some(ttl) = self.config.session_ttl else {
            return 0;
        };
        let now = Instant::now();
        let mut reaped: Vec<SessionRef> = Vec::new();
        {
            let mut map = lock(&self.sessions);
            let stale: Vec<String> = map
                .iter()
                .filter(|(_, e)| {
                    now.duration_since(*lock(&e.last_used)) > ttl && e.session.try_lock().is_ok()
                })
                .map(|(id, _)| id.clone())
                .collect();
            for id in stale {
                if let Some(e) = map.remove(&id) {
                    let idle = now.duration_since(*lock(&e.last_used));
                    eprintln!(
                        "execkit: reaped idle session {id} (idle {}s)",
                        idle.as_secs()
                    );
                    self.live.fetch_sub(1, Ordering::AcqRel);
                    if let Some(a) = &self.audit {
                        a.close(&id, "reaped");
                    }
                    reaped.push(e);
                }
            }
        }
        let n = reaped.len();
        if n > 0 {
            tokio::task::spawn_blocking(move || drop(reaped));
        }
        n
    }
}

#[tool_handler]
impl ServerHandler for ExeckitServer {
    fn get_info(&self) -> ServerInfo {
        // ServerInfo is #[non_exhaustive] - start from default and assign.
        let mut info = ServerInfo::default();
        info.instructions = Some(
            "Stateful, structured, safe shell sessions for agents. Call session_create \
             (local, ssh, or docker) to get a session_id, session_exec to run commands \
             (structured results), and session_destroy when done. State (cwd, env) persists \
             across execs. Remote (ssh/docker) sessions also support workspace checkpoints \
             (session_checkpoint/session_checkpoints/session_restore)."
                .into(),
        );
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        // Default pulls rmcp's own crate identity; advertise ourselves instead.
        info.server_info.name = "execkit-mcp".into();
        info.server_info.version = env!("CARGO_PKG_VERSION").into();
        info
    }
}

fn transport_label(p: &CreateParams) -> String {
    match p.transport.as_str() {
        "ssh" => match &p.host {
            Some(h) => format!("ssh:{h}"),
            None => "ssh".to_string(),
        },
        "docker" => match &p.container {
            Some(c) => format!("docker:{c}"),
            None => "docker".to_string(),
        },
        other => other.to_string(), // "local" and anything else
    }
}

fn build_session(p: CreateParams, config: &Config) -> Result<Session, execkit::Error> {
    let mut session = match p.transport.as_str() {
        "ssh" => {
            let host = p
                .host
                .ok_or_else(|| execkit::Error::Transport("ssh: 'host' required".into()))?;
            let user = p
                .user
                .ok_or_else(|| execkit::Error::Transport("ssh: 'user' required".into()))?;
            let auth = if let Some(pw) = p.password {
                SshAuth::Password(pw)
            } else if let Some(key) = p.key_path {
                // Constrain to the operator's key dir; generic error so the path's
                // existence/parseability never leaks to the (untrusted) caller.
                let path = validated_key_path(&key, &config.key_dir)?;
                SshAuth::Key {
                    path,
                    passphrase: None,
                }
            } else {
                return Err(execkit::Error::Transport(
                    "ssh: 'password' or 'key_path' required".into(),
                ));
            };
            // Host-key policy: pin if a fingerprint is supplied (safe - no file
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
        "docker" => {
            let container = p
                .container
                .ok_or_else(|| execkit::Error::Transport("docker: 'container' required".into()))?;
            Session::docker(&container)?
        }
        _ => Session::local()?,
    };
    session = session
        .with_auto_snapshot(p.auto_snapshot)
        .with_checkpoint_paths(p.paths.clone())
        .with_checkpoint_ignores(p.checkpoint_ignores.clone());
    if let Some(ws) = p.workspace.clone() {
        session = session.with_workspace(ws);
    }
    if let Some(bp) = &p.output_budget {
        let b = bp.to_budget().map_err(execkit::Error::Budget)?;
        session = session.with_output_budget(b);
    }
    if !p.allow.is_empty() || !p.deny.is_empty() {
        session = session.with_policy(Policy {
            allow: p.allow,
            deny: p.deny,
        });
    }
    Ok(session)
}

/// Resolve a caller-supplied key path and require it to live under `key_dir`.
/// Uses canonicalization (resolves `..` and symlinks) and returns a single
/// generic error so a not-found vs. out-of-bounds path is indistinguishable.
fn validated_key_path(raw: &str, key_dir: &Path) -> Result<PathBuf, execkit::Error> {
    let deny = || execkit::Error::Transport("ssh: key_path not permitted".into());
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
    // stdout is the MCP channel - all diagnostics go to stderr.
    let config = Config::from_env();
    eprintln!("execkit-mcp: starting MCP server on stdio");
    if std::env::var_os("HOME").is_none() {
        eprintln!(
            "execkit-mcp: NOTE HOME is unset - SSH key dir / known_hosts default under \
             /root/.ssh; set EXECKIT_MCP_KEY_DIR / EXECKIT_MCP_KNOWN_HOSTS explicitly."
        );
    }
    if config.insecure_accept_any {
        eprintln!(
            "execkit-mcp: WARNING EXECKIT_MCP_INSECURE_ACCEPT_ANY_HOSTKEY is set - \
             SSH host-key verification is DISABLED (MITM possible). Do not use in production."
        );
    }
    let service = ExeckitServer::new(config)
        .serve(rmcp::transport::stdio())
        .await?;
    service.waiting().await?;
    Ok(())
}
