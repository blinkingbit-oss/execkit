// SPDX-License-Identifier: Apache-2.0
//! nexum-mcp — an MCP (stdio) server exposing nexum shell sessions to any
//! MCP-capable agent (Claude Code, Cursor, Gemini CLI, ...).
//!
//! Tools: `session_create`, `session_exec`, `session_destroy`. Sessions are
//! stateful and outlive a single tool call; `session_exec` returns the
//! structured `ExecResult` as JSON (split stdout/stderr, exit code, cwd, ...),
//! already policy-checked, secret-redacted, and bounded.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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

#[derive(Clone)]
struct NexumServer {
    // Read by the code the #[tool_handler] macro generates; Rust's dead-code
    // analysis can't see through the macro, hence the allow.
    #[allow(dead_code)]
    tool_router: ToolRouter<NexumServer>,
    sessions: Sessions,
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
    /// SSH private-key path auth (alternative to password).
    #[serde(default)]
    key_path: Option<String>,
    /// Optional command allowlist (program names). If set, only these run.
    #[serde(default)]
    allow: Vec<String>,
    /// Optional command denylist (program names).
    #[serde(default)]
    deny: Vec<String>,
    /// Optional path to append a JSONL audit log of every command.
    #[serde(default)]
    audit_path: Option<String>,
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
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[tool(
        description = "Open a stateful shell session. transport is \"local\" or \"ssh\" \
                       (ssh needs host, user, and password or key_path). Optional allow/deny \
                       command lists and an audit_path. Returns a session_id."
    )]
    async fn session_create(
        &self,
        Parameters(p): Parameters<CreateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let built =
            tokio::task::spawn_blocking(move || build_session(p)).await.map_err(internal)?;
        match built {
            Ok(session) => {
                let id = next_id();
                self.sessions
                    .lock()
                    .unwrap()
                    .insert(id.clone(), Arc::new(Mutex::new(session)));
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
        let outcome = tokio::task::spawn_blocking(move || session.lock().unwrap().exec(&command))
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
        let removed = self.sessions.lock().unwrap().remove(&p.session_id).is_some();
        Ok(text(format!("{{\"destroyed\":{removed}}}")))
    }
}

impl NexumServer {
    fn get(&self, id: &str) -> Result<SessionRef, ErrorData> {
        self.sessions
            .lock()
            .unwrap()
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

fn build_session(p: CreateParams) -> Result<Session, nexum::Error> {
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
                SshAuth::Key { path: key.into(), passphrase: None }
            } else {
                return Err(nexum::Error::Transport(
                    "ssh: 'password' or 'key_path' required".into(),
                ));
            };
            // NOTE: AcceptAny is convenient but unsafe; a future revision should
            // take a known_hosts path from the caller.
            let mut cfg = SshConfig::new(host, user, auth, HostKeyVerification::AcceptAny);
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
    if let Some(path) = p.audit_path {
        session = session.with_audit(AuditLog::new(path));
    }
    Ok(session)
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
    eprintln!("nexum-mcp: starting MCP server on stdio");
    let service = NexumServer::new().serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
