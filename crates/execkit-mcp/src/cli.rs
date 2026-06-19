// SPDX-License-Identifier: Apache-2.0
//! Operator-facing subcommands (`--version`, `--help`, `setup`, `doctor`).
//! These are for a human at a terminal; the default no-arg invocation is the
//! stdio MCP server an agent launches, so nothing here touches that path.
use std::path::{Path, PathBuf};
use std::process::Command;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO: &str = "https://github.com/blinkingbit-oss/execkit";

pub fn version() {
    println!("execkit-mcp {VERSION}");
}

pub fn help() {
    print!(
        "execkit-mcp {VERSION}
An MCP (stdio) server exposing stateful, structured, safe shell sessions to AI agents.

USAGE:
  execkit-mcp                          Run the MCP server on stdio (default; how an agent launches it)
  execkit-mcp setup <client>           Print the config to wire execkit into a client
                                       client: claude | cursor | gemini
  execkit-mcp doctor                   Check the local environment and print a report
  execkit-mcp watch [--follow] <path>  Live, read-only viewer over the audit log
  execkit-mcp --version                Print version
  execkit-mcp --help                   Print this help

ENVIRONMENT (operator-controlled; see the README):
  EXECKIT_MCP_AUDIT                 Append a JSONL audit log of every command here
  EXECKIT_MCP_AUDIT_DIR             One JSONL file per session in this directory
  EXECKIT_MCP_AUDIT_RETENTION_DAYS  Prune per-session files older than N days (default 14)
  EXECKIT_MCP_KEY_DIR               Directory SSH keys must live under (default ~/.ssh)
  EXECKIT_MCP_KNOWN_HOSTS           SSH known_hosts file (default ~/.ssh/known_hosts)
  EXECKIT_MCP_MAX_SESSIONS          Soft cap on concurrent live sessions (default 64)
  EXECKIT_MCP_SESSION_TTL           Reap sessions idle longer than N seconds (default 1800)

Docs: {REPO}
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

fn config_block(bin: &str) -> String {
    format!(
        "{{
  \"mcpServers\": {{
    \"execkit\": {{ \"command\": \"{bin}\" }}
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
            println!("Wire execkit into Claude Code with one command:\n");
            println!("  claude mcp add execkit -- {bin}");
            println!("    (add `-s user` to enable it in every project)\n");
            println!("Or add this to your config by hand:\n\n{block}");
        }
        Some("cursor") => {
            println!("Add execkit to Cursor. Edit this file:\n");
            println!("  ~/.cursor/mcp.json   (project-scoped: .cursor/mcp.json in the repo)\n");
            println!("and merge in:\n\n{block}");
        }
        Some("gemini") => {
            println!("Add execkit to Gemini CLI. Edit this file:\n");
            println!("  ~/.gemini/settings.json\n");
            println!("and merge in:\n\n{block}");
        }
        Some(other) => {
            eprintln!("execkit-mcp setup: unknown client {other:?}. Use: claude | cursor | gemini");
            std::process::exit(2);
        }
        None => {
            eprintln!("execkit-mcp setup: name a client. Use: claude | cursor | gemini");
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
    println!("{tag} {label}: {detail}");
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"))
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
    println!("execkit-mcp {VERSION}");
    line(Status::Info, "binary", &binary_path());
    println!();

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

    // SSH key directory and known_hosts.
    let key_dir = std::env::var_os("EXECKIT_MCP_KEY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".ssh"));
    if key_dir.is_dir() {
        line(Status::Ok, "ssh key dir", &format!("{}", key_dir.display()));
    } else {
        line(
            Status::Info,
            "ssh key dir",
            &format!(
                "{} (absent; needed only for SSH sessions)",
                key_dir.display()
            ),
        );
    }
    let known_hosts = std::env::var_os("EXECKIT_MCP_KNOWN_HOSTS")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".ssh").join("known_hosts"));
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
