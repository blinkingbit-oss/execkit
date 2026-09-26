// SPDX-License-Identifier: Apache-2.0
//! Operator-facing subcommands (`--version`, `--help`, `setup`, `doctor`).
//! These are for a human at a terminal; the default no-arg invocation is the
//! stdio MCP server an agent launches, so nothing here touches that path.
use std::path::{Path, PathBuf};
use std::process::Command;

/// `print!` for these commands: a closed stdout (`execkit-mcp setup claude |
/// head -1`) ends the process with exit 0 instead of the panic `print!`
/// raises on a broken pipe.
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::cli::write_stdout(format_args!($($arg)*))
    };
}

/// `println!` counterpart of [`out!`].
macro_rules! outln {
    () => {
        out!("\n")
    };
    ($($arg:tt)*) => {
        out!("{}\n", format_args!($($arg)*))
    };
}

/// A broken pipe means the reader has gone away and wants no more output:
/// exit 0. Any other stdout error is a real failure.
fn write_stdout(args: std::fmt::Arguments) {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    if let Err(e) = stdout.write_fmt(args).and_then(|()| stdout.flush()) {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("execkit-mcp: error writing to stdout: {e}");
        std::process::exit(1);
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO: &str = "https://github.com/blinkingbit-oss/execkit";

pub fn version() {
    outln!("execkit-mcp {VERSION}");
}

pub fn help() {
    out!(
        "execkit-mcp {VERSION}
An MCP (stdio) server exposing stateful, structured, safe shell sessions to AI agents.

USAGE:
  execkit-mcp                                    Run the MCP server on stdio (default; how an agent launches it)
  execkit-mcp setup <client>                     Print the config to wire execkit into a client
                                                 client: claude | cursor | gemini | codex | vscode | windsurf
  execkit-mcp doctor                             Check the local environment and print a report
  execkit-mcp watch [--follow|--serve [--open]] <path>
                                                 Live, read-only viewer over the audit log
                                                 --follow  plain streaming log, no TTY required
                                                 --serve   token-gated local web viewer
                                                 --open    (with --serve) open it in the default browser
                                                 execkit-mcp watch --help  for details
  execkit-mcp --version | version                Print version
  execkit-mcp --help                             Print this help

ENVIRONMENT (operator-controlled; see the README):
  EXECKIT_MCP_AUDIT                 Append a JSONL audit log of every command here
  EXECKIT_MCP_AUDIT_DIR             One JSONL file per session in this directory
  EXECKIT_MCP_AUDIT_RETENTION_DAYS  Prune per-session files older than N days (default 14)
  EXECKIT_MCP_EXEC_TIMEOUT          Default per-call exec timeout in seconds (default 120, clamped 1-3600)
  EXECKIT_MCP_KEY_DIR               Directory SSH keys must live under (default ~/.ssh)
  EXECKIT_MCP_KNOWN_HOSTS           execkit-managed SSH known_hosts file (default ~/.execkit/known_hosts)
  EXECKIT_MCP_MAX_SESSIONS          Soft cap on concurrent live sessions (default 64)
  EXECKIT_MCP_SESSION_TTL           Reap sessions idle longer than N seconds (default 1800)
  EXECKIT_MCP_POLICY_FILE           JSON allow/deny + deny_patterns the agent cannot edit (advisory)
  EXECKIT_MCP_WATCH_WEB             Start the live web viewer alongside the stdio server (any value)
  EXECKIT_MCP_WATCH_PORT            Port for the web viewer (default 7878, falls back to a random port)
  EXECKIT_MCP_WATCH_OPEN            Auto-open the web viewer in the default browser (any value)

Docs: {REPO}
"
    );
}

/// `watch --help`: just the watch section, for someone who already knows the
/// rest and wants the flags/env vars for this one subcommand.
pub fn watch_help() {
    out!(
        "execkit-mcp watch [--follow|--serve [--open]] <path>

Live, read-only viewer over the audit log (EXECKIT_MCP_AUDIT / EXECKIT_MCP_AUDIT_DIR).
<path> may be a single audit file or an audit directory (one file per session);
omit it to use whichever of those two env vars is set.

  execkit-mcp watch <path>                 Interactive TUI (needs a terminal)
  execkit-mcp watch --follow <path>        Plain streaming log to stdout (no TTY needed)
  execkit-mcp watch --serve <path>         Serve a token-gated local web viewer
  execkit-mcp watch --serve --open <path>  ...and open it in the default browser

ENVIRONMENT:
  EXECKIT_MCP_WATCH_WEB    Start the web viewer alongside the stdio server (any value)
  EXECKIT_MCP_WATCH_PORT   Port for the web viewer (default 7878, falls back to a random port)
  EXECKIT_MCP_WATCH_OPEN   Auto-open the web viewer in the default browser (any value)
"
    );
}

/// The absolute path to this binary, for pasting into a client config. Falls
/// back to the bare name if the exe path can't be resolved (e.g. it is on PATH).
fn binary_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .unwrap_or_else(|| "execkit-mcp".to_string())
}

/// Escape `\` and `"` so `s` can be dropped into a JSON or TOML basic
/// (double-quoted) string literal without breaking out of it. Order matters:
/// backslashes must be doubled first, so the quote-escaping pass doesn't
/// touch the backslashes it just introduced.
fn escape_quoted(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn config_block(bin: &str) -> String {
    let bin = escape_quoted(bin);
    format!(
        "{{
  \"mcpServers\": {{
    \"execkit\": {{ \"command\": \"{bin}\" }}
  }}
}}"
    )
}

/// TOML snippet for Codex CLI's `~/.codex/config.toml`.
fn codex_block(bin: &str) -> String {
    format!(
        "[mcp_servers.execkit]\ncommand = \"{}\"",
        escape_quoted(bin)
    )
}

/// JSON snippet for VS Code's workspace `.vscode/mcp.json`.
fn vscode_block(bin: &str) -> String {
    let bin = escape_quoted(bin);
    format!(
        "{{
  \"servers\": {{
    \"execkit\": {{ \"type\": \"stdio\", \"command\": \"{bin}\" }}
  }}
}}"
    )
}

/// `setup <client>`: print a ready-to-use MCP config for the named client, with
/// this binary's absolute path filled in. Prints (does not edit config files):
/// editing a client's live config risks corrupting it, so we hand the operator
/// an exact block and the file it goes in.
pub fn setup(client: Option<&str>) -> anyhow::Result<()> {
    let bin = binary_path();
    let block = config_block(&bin);
    match client {
        Some("claude") => {
            outln!("Wire execkit into Claude Code with one command:\n");
            outln!("  claude mcp add execkit -- {bin}");
            outln!("    (add `-s user` to enable it in every project)\n");
            outln!("Or add this to your config by hand:\n\n{block}");
        }
        Some("cursor") => {
            outln!("Add execkit to Cursor. Edit this file:\n");
            outln!("  ~/.cursor/mcp.json   (project-scoped: .cursor/mcp.json in the repo)\n");
            outln!("and merge in:\n\n{block}");
        }
        Some("gemini") => {
            outln!("Add execkit to Gemini CLI. Edit this file:\n");
            outln!("  ~/.gemini/settings.json\n");
            outln!("and merge in:\n\n{block}");
        }
        Some("codex") => {
            outln!("Add execkit to Codex CLI. Edit this file:\n");
            outln!("  ~/.codex/config.toml\n");
            outln!("and add:\n\n{}", codex_block(&bin));
        }
        Some("vscode") => {
            outln!("Add execkit to VS Code (workspace-scoped). Edit this file:\n");
            outln!("  .vscode/mcp.json\n");
            outln!("and merge in:\n\n{}", vscode_block(&bin));
        }
        Some("windsurf") => {
            outln!("Add execkit to Windsurf. Edit this file:\n");
            outln!("  ~/.codeium/windsurf/mcp_config.json\n");
            outln!("and merge in:\n\n{block}");
        }
        Some(other) => {
            eprintln!(
                "execkit-mcp setup: unknown client {other:?}. Use: claude | cursor | gemini | codex | vscode | windsurf"
            );
            std::process::exit(2);
        }
        None => {
            eprintln!(
                "execkit-mcp setup: name a client. Use: claude | cursor | gemini | codex | vscode | windsurf"
            );
            std::process::exit(2);
        }
    }
    Ok(())
}

enum Status {
    Ok,
    Warn,
    Info,
}

fn line(status: Status, label: &str, detail: &str) {
    let tag = match status {
        Status::Ok => "[ ok ]",
        Status::Warn => "[warn]",
        Status::Info => "[ -- ]",
    };
    outln!("{tag} {label}: {detail}");
}

/// True if we can create + remove a temp file inside `dir` (creating `dir` if
/// needed). Best-effort: any error means "not writable".
fn dir_writable(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".execkit-doctor-probe");
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// `doctor`: print a friendly report of the local environment so an operator can
/// see, before wiring an agent in, what is configured and what is missing.
pub fn doctor() -> anyhow::Result<()> {
    outln!("execkit-mcp {VERSION}");
    line(Status::Info, "binary", &binary_path());
    outln!();

    // Audit destination.
    if let Some(dir) = std::env::var_os("EXECKIT_MCP_AUDIT_DIR") {
        let dir = PathBuf::from(dir);
        if dir_writable(&dir) {
            line(
                Status::Ok,
                "audit dir",
                &format!("{} (writable)", dir.display()),
            );
        } else {
            line(
                Status::Warn,
                "audit dir",
                &format!("{} (not writable)", dir.display()),
            );
        }
    } else if let Some(file) = std::env::var_os("EXECKIT_MCP_AUDIT") {
        let file = PathBuf::from(file);
        let parent = file.parent().unwrap_or(Path::new("."));
        if dir_writable(parent) {
            line(
                Status::Ok,
                "audit log",
                &format!("{} (writable)", file.display()),
            );
        } else {
            line(
                Status::Warn,
                "audit log",
                &format!("{} (parent not writable)", file.display()),
            );
        }
    } else {
        line(
            Status::Info,
            "audit",
            "off (set EXECKIT_MCP_AUDIT or EXECKIT_MCP_AUDIT_DIR to record + watch activity)",
        );
    }

    // SSH key directory and known_hosts. Defaults resolve ~ like the server
    // does (paths::ssh_dir); both are overridable via the named env vars.
    let key_dir = std::env::var_os("EXECKIT_MCP_KEY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(execkit_mcp::paths::ssh_dir);
    if key_dir.is_dir() {
        line(
            Status::Ok,
            "ssh key dir",
            &format!("{} (override: EXECKIT_MCP_KEY_DIR)", key_dir.display()),
        );
    } else {
        line(
            Status::Info,
            "ssh key dir",
            &format!(
                "{} (absent; needed only for SSH sessions; override: EXECKIT_MCP_KEY_DIR)",
                key_dir.display()
            ),
        );
    }
    let known_hosts = std::env::var_os("EXECKIT_MCP_KNOWN_HOSTS")
        .map(PathBuf::from)
        .unwrap_or_else(execkit_mcp::paths::default_known_hosts_path);
    if known_hosts.is_file() {
        line(
            Status::Ok,
            "known_hosts",
            &format!("{}", known_hosts.display()),
        );
    } else {
        line(
            Status::Info,
            "known_hosts",
            &format!(
                "{} (absent; created on first SSH connect via TOFU)",
                known_hosts.display()
            ),
        );
    }

    // Docker availability (only matters for docker transport).
    match docker_status() {
        DockerStatus::Reachable => line(Status::Ok, "docker", "daemon reachable"),
        DockerStatus::NotRunning => line(
            Status::Warn,
            "docker",
            "CLI found but daemon not reachable (needed only for docker sessions)",
        ),
        DockerStatus::Absent => line(
            Status::Info,
            "docker",
            "not on PATH (needed only for docker sessions)",
        ),
    }

    // Operator command policy (advisory). Non-fatal here: the server fails fast
    // on an invalid file, but doctor reports it so an operator can diagnose.
    match std::env::var_os("EXECKIT_MCP_POLICY_FILE") {
        None => line(
            Status::Info,
            "policy",
            "off (set EXECKIT_MCP_POLICY_FILE to enable)",
        ),
        Some(p) => {
            let path = PathBuf::from(&p);
            match crate::policy_for_doctor(&path) {
                Ok((a, d, k)) => line(
                    Status::Ok,
                    "policy",
                    &format!("{} ({a} allow, {d} deny, {k} patterns)", path.display()),
                ),
                Err(e) => line(
                    Status::Warn,
                    "policy",
                    &format!("{} (invalid: {e:#})", path.display()),
                ),
            }
        }
    }

    Ok(())
}

enum DockerStatus {
    Reachable,
    NotRunning,
    Absent,
}

fn docker_status() -> DockerStatus {
    // `docker info` succeeds only when the CLI exists AND the daemon answers.
    match Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
    {
        Ok(out) if out.status.success() => DockerStatus::Reachable,
        Ok(_) => DockerStatus::NotRunning,
        Err(_) => DockerStatus::Absent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_block_contains_binary_and_server_name() {
        let b = config_block("/usr/local/bin/execkit-mcp");
        assert!(b.contains("\"execkit\""));
        assert!(b.contains("/usr/local/bin/execkit-mcp"));
        assert!(b.contains("mcpServers"));
    }

    /// A path containing a space, a backslash and a quote - the three
    /// characters that can appear in a real filesystem path and would
    /// otherwise break a JSON/TOML quoted string if pasted in raw.
    const TRICKY_PATH: &str = "/opt/weird path/exec\"kit\\bin/execkit-mcp";

    #[test]
    fn escape_quoted_escapes_backslash_and_quote_leaves_space_alone() {
        assert_eq!(
            escape_quoted(TRICKY_PATH),
            "/opt/weird path/exec\\\"kit\\\\bin/execkit-mcp"
        );
    }

    #[test]
    fn config_block_escapes_the_path_into_valid_json() {
        let block = config_block(TRICKY_PATH);
        let v: serde_json::Value = serde_json::from_str(&block).expect("valid json");
        assert_eq!(v["mcpServers"]["execkit"]["command"], TRICKY_PATH);
    }

    #[test]
    fn vscode_block_escapes_the_path_into_valid_json() {
        let block = vscode_block(TRICKY_PATH);
        let v: serde_json::Value = serde_json::from_str(&block).expect("valid json");
        assert_eq!(v["servers"]["execkit"]["command"], TRICKY_PATH);
    }

    #[test]
    fn codex_block_escapes_the_path_in_the_toml_string() {
        let block = codex_block(TRICKY_PATH);
        assert!(
            block.contains(&format!("command = \"{}\"", escape_quoted(TRICKY_PATH))),
            "got {block:?}"
        );
        // the raw (unescaped) backslash+quote sequence must not appear bare
        assert!(
            !block.contains("kit\\bin"),
            "unescaped backslash leaked into {block:?}"
        );
    }

    #[test]
    fn dir_writable_true_for_temp_false_for_bogus() {
        let tmp = std::env::temp_dir().join(format!("ek_doc_{}", std::process::id()));
        assert!(dir_writable(&tmp));
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(!dir_writable(Path::new(
            "/this/should/not/be/creatable/ekdoc"
        )));
    }
}
