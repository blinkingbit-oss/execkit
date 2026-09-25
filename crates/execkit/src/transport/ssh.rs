// SPDX-License-Identifier: Apache-2.0
//! SSH transport configuration and host-key verification.
//!
//! The russh-backed I/O is wired separately; the pieces here - connection
//! config, auth, and the **host-key policy** (the load-bearing MITM defense) -
//! are pure and unit-tested, independent of any network.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Error, Result};

/// Default timeout for establishing the SSH TCP connection (see [`SshConfig::connect_timeout`]).
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How to reach an SSH host.
#[derive(Clone)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: SshAuth,
    pub host_key: HostKeyVerification,
    /// How long to wait for the TCP connection to be established before
    /// giving up. Does not cover auth or shell startup. Default 15s.
    pub connect_timeout: Duration,
}

impl SshConfig {
    /// `user@host` with sensible defaults (port 22, key path filled by caller).
    pub fn new(
        host: impl Into<String>,
        user: impl Into<String>,
        auth: SshAuth,
        host_key: HostKeyVerification,
    ) -> Self {
        Self {
            host: host.into(),
            port: 22,
            user: user.into(),
            auth,
            host_key,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }
}

/// Authentication method.
#[derive(Clone)]
pub enum SshAuth {
    Password(String),
    Key {
        path: PathBuf,
        passphrase: Option<String>,
    },
}

// Manual Debug so secrets never land in logs.
impl std::fmt::Debug for SshAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshAuth::Password(_) => f.write_str("Password(***)"),
            SshAuth::Key { path, .. } => write!(f, "Key {{ path: {path:?}, passphrase: *** }}"),
        }
    }
}

impl std::fmt::Debug for SshConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("auth", &self.auth)
            .field("host_key", &self.host_key)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

/// Server host-key policy - the defense against connecting into a MITM.
#[derive(Debug, Clone)]
pub enum HostKeyVerification {
    /// Require this exact fingerprint, e.g. `"SHA256:abc123..."`.
    Pinned(String),
    /// Trust-on-first-use against a `known_hosts`-style file (`host fingerprint`
    /// per line). A *changed* fingerprint for a known host is rejected.
    KnownHosts(PathBuf),
    /// DANGEROUS - accept any key. Tests only; never use in production.
    AcceptAny,
}

/// Verify a presented host fingerprint against the policy.
///
/// `Ok(true)` accept, `Ok(false)` reject (caller must abort the connection),
/// `Err` on IO trouble. Pure except for the known-hosts file read/append.
// Wired by the russh client Handler (next step); already unit-tested below.
#[allow(dead_code)]
pub(crate) fn verify_fingerprint(
    policy: &HostKeyVerification,
    host: &str,
    port: u16,
    fingerprint: &str,
) -> Result<bool> {
    match policy {
        HostKeyVerification::AcceptAny => Ok(true),
        HostKeyVerification::Pinned(expected) => Ok(expected == fingerprint),
        HostKeyVerification::KnownHosts(path) => verify_known_hosts(path, host, port, fingerprint),
    }
}

/// The known_hosts key for a host: bare `host` on the default SSH port (22),
/// else `[host]:port` - so a non-standard port never collides with (or is
/// silently verified against) the port-22 entry for the same hostname.
fn known_hosts_key(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

#[allow(dead_code)]
fn verify_known_hosts(path: &Path, host: &str, port: u16, fingerprint: &str) -> Result<bool> {
    let key = known_hosts_key(host, port);

    // SEC-2: distinguish "file absent" (first use -> TOFU) from "file present
    // but unreadable" (any other I/O error -> fail closed, return Err).
    // Using read() + from_utf8_lossy so that real ASCII/hashed lines still
    // parse even if there is a stray high byte, while a genuine read error
    // propagates instead of silently becoming an empty file (MITM bypass).
    let content = match std::fs::read(path) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };

    // execkit's own format is `<key> SHA256:<fp>`. Any line whose second field
    // is not a `SHA256:` fingerprint (e.g. a real OpenSSH known_hosts entry, if
    // an operator points the path at one) is not ours: it is never matched
    // against, and never treated as a mismatch. Its mere presence, though,
    // means this file is not execkit-managed - so an unseen host must not be
    // silently TOFU-pinned into it (that would mix formats and, for a hashed
    // OpenSSH file, be unreadable/unsafe to append to).
    let mut foreign_format = false;
    for line in content.lines() {
        let mut it = line.split_whitespace();
        let (Some(h), Some(fp)) = (it.next(), it.next()) else {
            continue;
        };
        if !fp.starts_with("SHA256:") {
            foreign_format = true;
            continue;
        }
        if h == key {
            // Known host: the fingerprint MUST match. A mismatch is a MITM
            // signal - reject loudly, never silently re-pin.
            return Ok(fp == fingerprint);
        }
    }

    if foreign_format {
        return Err(Error::Transport(format!(
            "known_hosts file {} is in OpenSSH format; point EXECKIT_MCP_KNOWN_HOSTS at an \
             execkit-managed file (default ~/.execkit/known_hosts) or pin 'fingerprint'",
            path.display()
        )));
    }

    // Unseen host in an execkit-managed (or absent) file: trust on first use
    // and pin it. One atomic O_APPEND write so a concurrent reader never sees
    // a partial line.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
                #[cfg(unix)]
                chmod_0700(parent)?;
            } else if is_default_known_hosts_dir(parent) {
                // The default parent (~/.execkit) is very likely to
                // already exist - the audit log and web-viewer state also
                // live there and may have created it first, with default
                // (non-private) permissions. Enforce 0700 on it too. Never
                // touch the permissions of a pre-existing *custom*
                // (EXECKIT_MCP_KNOWN_HOSTS-pointed) directory - an operator
                // may have deliberately set them.
                #[cfg(unix)]
                chmod_0700(parent)?;
            }
        }
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(format!("{key} {fingerprint}\n").as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(true)
}

/// Whether `dir` is the *default* known_hosts directory (`.../.execkit`),
/// as opposed to a custom location an operator pointed
/// `EXECKIT_MCP_KNOWN_HOSTS` at. This crate has no knowledge of `$HOME`
/// resolution (that lives in `execkit-mcp`/`execkit-py`), so the check is
/// structural: the parent directory's own name is `.execkit`. A custom path
/// nested under a directory that happens to also be named `.execkit` is
/// treated the same as the default - it is still "an execkit state dir",
/// just not literally `~/.execkit`; the intent (never mangling permissions
/// of a directory the operator chose and controls fully) is preserved
/// because any *other* name never matches.
fn is_default_known_hosts_dir(dir: &Path) -> bool {
    dir.file_name() == Some(std::ffi::OsStr::new(".execkit"))
}

/// Force `dir` to mode `0700` (owner rwx only). Unix only; a no-op crate
/// boundary on other platforms (callers gate this behind `#[cfg(unix)]`).
#[cfg(unix)]
fn chmod_0700(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

// ===========================================================================
// russh-backed transport (feature = "ssh")
// ===========================================================================

#[cfg(feature = "ssh")]
mod imp {
    use std::sync::mpsc as std_mpsc;
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::Duration;

    use russh::client;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc as tokio_mpsc;

    use super::{verify_fingerprint, HostKeyVerification, SshAuth, SshConfig};
    use crate::error::{Error, Result};
    use crate::transport::Transport;

    const CHANNEL_CAP: usize = 64;

    /// A persistent shell over SSH. A dedicated thread runs a current-thread
    /// tokio runtime; bytes bridge to the sync [`Transport`] API via channels.
    pub struct SshTransport {
        write_tx: Option<tokio_mpsc::Sender<Vec<u8>>>,
        // Option so Drop can close it *before* join - otherwise a runtime thread
        // parked in a full `read_tx.send()` (after a flood/timeout that stopped
        // draining) never observes shutdown and join() hangs forever.
        read_rx: Option<std_mpsc::Receiver<Vec<u8>>>,
        thread: Option<JoinHandle<()>>,
    }

    impl SshTransport {
        pub fn connect(cfg: SshConfig) -> Result<Self> {
            let (write_tx, write_rx) = tokio_mpsc::channel::<Vec<u8>>(CHANNEL_CAP);
            let (read_tx, read_rx) = std_mpsc::sync_channel::<Vec<u8>>(CHANNEL_CAP);
            let (ready_tx, ready_rx) = std_mpsc::channel::<Result<()>>();

            let thread = std::thread::spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(Error::Transport(format!("runtime: {e}"))));
                        return;
                    }
                };
                rt.block_on(io_loop(cfg, write_rx, read_tx, ready_tx));
            });

            // Block until the connection + auth + shell are established (or fail).
            match ready_rx.recv() {
                Ok(Ok(())) => Ok(SshTransport {
                    write_tx: Some(write_tx),
                    read_rx: Some(read_rx),
                    thread: Some(thread),
                }),
                Ok(Err(e)) => {
                    let _ = thread.join();
                    Err(e)
                }
                Err(_) => Err(Error::Transport("ssh thread died during connect".into())),
            }
        }
    }

    impl Transport for SshTransport {
        fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
            let tx = self
                .write_tx
                .as_ref()
                .ok_or_else(|| Error::Transport("ssh session closed".into()))?;
            tx.blocking_send(bytes.to_vec())
                .map_err(|_| Error::Transport("ssh session closed".into()))
        }

        fn recv_timeout(&self, dur: Duration) -> Option<Vec<u8>> {
            self.read_rx.as_ref()?.recv_timeout(dur).ok()
        }
    }

    impl Drop for SshTransport {
        fn drop(&mut self) {
            // End the I/O loop regardless of where its thread is parked:
            //  - dropping write_tx  -> the select! write arm returns None -> break
            //  - dropping read_rx   -> a blocked read_tx.send() returns Err -> break
            // The second is essential: after a flood/timeout the thread sits in a
            // full blocking send, NOT in select!, so closing only writes wouldn't
            // wake it and join() would hang.
            self.write_tx = None;
            self.read_rx = None;
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    /// Verifies the server host key against the configured policy.
    struct Handler {
        policy: HostKeyVerification,
        host: String,
        port: u16,
    }

    impl client::Handler for Handler {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            server_public_key: &russh::keys::ssh_key::PublicKey,
        ) -> std::result::Result<bool, Self::Error> {
            let fp = server_public_key
                .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
                .to_string();
            Ok(verify_fingerprint(&self.policy, &self.host, self.port, &fp).unwrap_or(false))
        }
    }

    /// TCP connect, key exchange (inside `client::connect`), and auth - the
    /// whole pre-shell handshake with the remote end. Callers wrap this in
    /// `cfg.connect_timeout`: a server that completes key exchange and
    /// then stalls during auth must not hang forever any more than one that
    /// never completes the TCP handshake.
    async fn connect_and_auth(cfg: &SshConfig) -> Result<client::Handle<Handler>> {
        let config = Arc::new(client::Config::default());
        let handler = Handler {
            policy: cfg.host_key.clone(),
            host: cfg.host.clone(),
            port: cfg.port,
        };
        let mut handle = client::connect(config, (cfg.host.as_str(), cfg.port), handler)
            .await
            .map_err(|e| Error::Transport(format!("ssh connect: {e}")))?;

        let result = match &cfg.auth {
            SshAuth::Password(p) => handle
                .authenticate_password(cfg.user.clone(), p.clone())
                .await
                .map_err(|e| Error::Transport(format!("ssh auth: {e}")))?,
            SshAuth::Key { path, passphrase } => {
                let key = russh::keys::load_secret_key(path, passphrase.as_deref())
                    .map_err(|e| Error::Transport(format!("load key: {e}")))?;
                // RSA keys must sign with rsa-sha2 (SHA-256/512) against modern
                // servers, which reject the legacy ssh-rsa (SHA-1). Negotiate the
                // server's preferred RSA hash; ignored for non-RSA keys.
                let hash = handle
                    .best_supported_rsa_hash()
                    .await
                    .ok()
                    .flatten()
                    .flatten();
                let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash);
                handle
                    .authenticate_publickey(cfg.user.clone(), key)
                    .await
                    .map_err(|e| Error::Transport(format!("ssh auth: {e}")))?
            }
        };
        if !result.success() {
            return Err(Error::Transport("ssh authentication failed".into()));
        }
        Ok(handle)
    }

    async fn establish(
        cfg: &SshConfig,
    ) -> Result<(client::Handle<Handler>, russh::Channel<client::Msg>)> {
        let handle = match tokio::time::timeout(cfg.connect_timeout, connect_and_auth(cfg)).await {
            Ok(Ok(handle)) => handle,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(Error::Transport(format!(
                    "ssh: connect to {}:{} timed out after {}s",
                    cfg.host,
                    cfg.port,
                    cfg.connect_timeout.as_secs()
                )))
            }
        };

        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Transport(format!("open channel: {e}")))?;
        channel
            .request_pty(false, "xterm-256color", 120, 40, 0, 0, &[])
            .await
            .map_err(|e| Error::Transport(format!("request pty: {e}")))?;
        // Run a clean POSIX shell rather than request_shell, which starts the
        // interactive LOGIN shell - its profile/rc, prompt, and readline behavior
        // desync the sentinel framing. /bin/sh is universally present (bash is
        // not, e.g. on Alpine); the framing is POSIX-compatible.
        channel
            .exec(false, "/bin/sh")
            .await
            .map_err(|e| Error::Transport(format!("start shell: {e}")))?;
        Ok((handle, channel))
    }

    async fn io_loop(
        cfg: SshConfig,
        mut write_rx: tokio_mpsc::Receiver<Vec<u8>>,
        read_tx: std_mpsc::SyncSender<Vec<u8>>,
        ready_tx: std_mpsc::Sender<Result<()>>,
    ) {
        let (handle, channel) = match establish(&cfg).await {
            Ok(v) => v,
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return;
            }
        };
        let _ = ready_tx.send(Ok(()));
        let _keep = handle; // keep the SSH session alive for the channel's lifetime

        // INVARIANT: we always request_pty above, so the server merges the
        // command's fd2 into the single PTY stream and never sends SSH
        // ExtendedData. `into_stream()` builds a reader with `ext: None`, whose
        // poll_read busy-spins on an ExtendedData message - so do NOT drop the
        // PTY request without also handling ext data here.
        let stream = channel.into_stream(); // AsyncRead + AsyncWrite (merged streams)
        let (mut rd, mut wr) = tokio::io::split(stream);
        let mut buf = [0u8; 8192];

        loop {
            tokio::select! {
                r = rd.read(&mut buf) => match r {
                    Ok(0) | Err(_) => break,
                    // Blocking send into the bounded queue applies backpressure
                    // (stalls reads -> TCP backpressure) under a flood.
                    Ok(n) => if read_tx.send(buf[..n].to_vec()).is_err() { break; },
                },
                w = write_rx.recv() => match w {
                    Some(bytes) => {
                        if wr.write_all(&bytes).await.is_err() { break; }
                        let _ = wr.flush().await;
                    }
                    None => break, // transport dropped
                },
            }
        }
    }
}

#[cfg(feature = "ssh")]
pub use imp::SshTransport;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_matches_only_exact() {
        let p = HostKeyVerification::Pinned("SHA256:abc".into());
        assert!(verify_fingerprint(&p, "h", 22, "SHA256:abc").unwrap());
        assert!(!verify_fingerprint(&p, "h", 22, "SHA256:evil").unwrap());
    }

    #[test]
    fn known_hosts_tofu_then_pins_and_detects_change() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("execkit_kh_test_{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let p = HostKeyVerification::KnownHosts(path.clone());

        // First sight: accepted (TOFU) and pinned.
        assert!(verify_fingerprint(&p, "prod-1", 22, "SHA256:good").unwrap());
        // Same key again: accepted.
        assert!(verify_fingerprint(&p, "prod-1", 22, "SHA256:good").unwrap());
        // Changed key for a known host: REJECTED (MITM).
        assert!(!verify_fingerprint(&p, "prod-1", 22, "SHA256:evil").unwrap());
        // A different host is independent.
        assert!(verify_fingerprint(&p, "prod-2", 22, "SHA256:other").unwrap());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn auth_debug_redacts_secrets() {
        let a = SshAuth::Password("hunter2".into());
        assert!(!format!("{a:?}").contains("hunter2"));
    }

    /// SEC-2: a known_hosts file containing any non-UTF-8 / undecodable bytes
    /// must NOT silently fall through to TOFU and accept a different key.
    /// The result must be Err (fail closed), not Ok(true).
    #[test]
    fn known_hosts_corrupt_file_fails_closed() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("execkit_kh_corrupt_{}", std::process::id()));
        // Write a valid pinned line followed by a raw non-UTF-8 byte sequence.
        let mut bytes = b"prod-1 SHA256:GOODKEY\n".to_vec();
        bytes.extend_from_slice(b"\xff\xfe bad\n");
        std::fs::write(&path, &bytes).unwrap();

        let p = HostKeyVerification::KnownHosts(path.clone());
        // Present a DIFFERENT (attacker) fingerprint for the already-pinned host.
        let result = verify_fingerprint(&p, "prod-1", 22, "SHA256:ATTACKER");
        let _ = std::fs::remove_file(&path);

        // Must be Ok(false) (pinned entry found and key mismatched) OR Err.
        // It must NOT be Ok(true) (TOFU bypass / silent MITM accept).
        if let Ok(true) = result {
            panic!("SEC-2: corrupt known_hosts silently accepted attacker key (TOFU bypass)");
        }
    }

    /// Confirm that an ABSENT known_hosts file still triggers TOFU (first-use accept + pin).
    #[test]
    fn known_hosts_absent_file_tofu_preserved() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("execkit_kh_absent_{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let p = HostKeyVerification::KnownHosts(path.clone());

        // File absent: first sight must be accepted (TOFU).
        assert!(
            verify_fingerprint(&p, "new-host", 22, "SHA256:firstkey").unwrap(),
            "TOFU must accept first-ever connection when known_hosts is absent"
        );
        let _ = std::fs::remove_file(&path);
    }

    fn unique_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "execkit_kh_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn tofu_writes_bracketed_host_port_key_for_non_default_port() {
        let path = unique_path("bracket");
        let _ = std::fs::remove_file(&path);

        assert!(verify_known_hosts(&path, "h", 2222, "SHA256:x").unwrap());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("[h]:2222 SHA256:x"),
            "expected bracketed host:port entry, got: {content:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn same_host_different_port_is_a_separate_unknown_entry() {
        let path = unique_path("portsep");
        let _ = std::fs::remove_file(&path);

        // Pin host "h" on port 2222.
        assert!(verify_known_hosts(&path, "h", 2222, "SHA256:x").unwrap());
        // Port 22 for the same host must be treated as unseen -> TOFU accept,
        // not compared against the port-2222 pin.
        assert!(verify_known_hosts(&path, "h", 22, "SHA256:y").unwrap());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[h]:2222 SHA256:x"));
        assert!(content.contains("h SHA256:y"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mismatch_on_same_host_and_port_is_rejected() {
        let path = unique_path("mismatch");
        let _ = std::fs::remove_file(&path);

        assert!(verify_known_hosts(&path, "h", 2222, "SHA256:good").unwrap());
        assert!(!verify_known_hosts(&path, "h", 2222, "SHA256:evil").unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn openssh_format_file_and_unknown_host_errors_with_guidance() {
        let path = unique_path("openssh_unknown");
        std::fs::write(&path, "otherhost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\n").unwrap();

        let err = verify_known_hosts(&path, "newhost", 22, "SHA256:whatever")
            .expect_err("OpenSSH-format file must block TOFU for an unknown host");
        let msg = err.to_string();
        assert!(
            msg.contains("OpenSSH format"),
            "error should mention OpenSSH format, got: {msg}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn openssh_line_for_same_host_is_ignored_not_treated_as_mismatch() {
        let path = unique_path("openssh_sameone");
        std::fs::write(&path, "samehost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\n").unwrap();

        let result = verify_known_hosts(&path, "samehost", 22, "SHA256:x");
        // Must NOT be Ok(false) (that would mean we treated the OpenSSH line as
        // a mismatching execkit pin). Either Err (foreign-format file blocks
        // TOFU) is correct here.
        assert!(
            !matches!(result, Ok(false)),
            "OpenSSH line must never be treated as a fingerprint mismatch"
        );
        assert!(
            result.is_err(),
            "expected Err (foreign-format file present)"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A foreign (OpenSSH-format) line for an unrelated host must not
    /// disturb verification of a host that DOES have a valid execkit
    /// (`SHA256:`) entry in the same file - it is neither blocked (as an
    /// unknown host would be) nor mismatched.
    #[test]
    fn openssh_line_for_other_host_does_not_block_known_execkit_host() {
        let path = unique_path("mixed_format");
        std::fs::write(
            &path,
            "otherhost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\nA SHA256:good\n",
        )
        .unwrap();

        assert!(
            verify_known_hosts(&path, "A", 22, "SHA256:good").unwrap(),
            "known execkit host must verify despite a foreign line elsewhere in the file"
        );
        assert!(
            !verify_known_hosts(&path, "A", 22, "SHA256:bad").unwrap(),
            "a mismatched fingerprint for the known host must still be rejected"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// `~/.execkit` is very likely to already exist by the time SSH
    /// first connects (the audit log / web viewer create it first, with
    /// default - not private - permissions). The default known_hosts
    /// parent must be forced to 0700 even when TOFU finds it already there.
    #[cfg(unix)]
    #[test]
    fn default_known_hosts_parent_is_forced_to_0700_even_if_preexisting() {
        use std::os::unix::fs::PermissionsExt;

        let base = unique_path("preexisting_execkit_dir");
        let parent = base.join(".execkit");
        std::fs::create_dir_all(&parent).unwrap();
        // Simulate the audit log / web viewer having created it first, with
        // whatever the umask gave them (not necessarily private).
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();

        let path = parent.join("known_hosts");
        assert!(verify_known_hosts(&path, "h", 22, "SHA256:x").unwrap());

        let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "pre-existing ~/.execkit must be tightened to 0700"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// A *custom* `EXECKIT_MCP_KNOWN_HOSTS` directory (not named
    /// `.execkit`) must never have its permissions changed - the operator
    /// chose that location and owns its permissions.
    #[cfg(unix)]
    #[test]
    fn custom_known_hosts_parent_permissions_are_never_touched() {
        use std::os::unix::fs::PermissionsExt;

        let base = unique_path("preexisting_custom_dir");
        let parent = base.join("my-custom-ssh-state");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();

        let path = parent.join("known_hosts");
        assert!(verify_known_hosts(&path, "h", 22, "SHA256:x").unwrap());

        let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "a custom known_hosts directory's permissions must be left alone"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The connect_timeout budget must cover the whole connect+auth
    /// handshake, not just the initial TCP connect - a peer that accepts the
    /// TCP connection but never speaks SSH (so key exchange, and any auth
    /// that would follow it, never completes) must still time out promptly.
    /// A real (but silent) local TCP peer, so this is fast and not
    /// network-dependent - no `#[ignore]` needed.
    #[cfg(feature = "ssh")]
    #[test]
    fn ssh_connect_times_out_when_peer_never_speaks_ssh() {
        use std::net::TcpListener;
        use std::time::{Duration, Instant};

        use super::SshTransport;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback port");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            // Accept the connection and hold it open, silently, well past
            // the client's connect_timeout below - never sending an SSH
            // identification string or any protocol bytes.
            if let Ok((stream, _)) = listener.accept() {
                std::thread::sleep(Duration::from_secs(5));
                drop(stream);
            }
        });

        let mut cfg = SshConfig::new(
            "127.0.0.1",
            "nobody",
            SshAuth::Password("x".into()),
            HostKeyVerification::AcceptAny,
        );
        cfg.port = port;
        cfg.connect_timeout = Duration::from_secs(1);

        let start = Instant::now();
        let err = match SshTransport::connect(cfg) {
            Ok(_) => panic!("connect to a silent peer must fail"),
            Err(e) => e,
        };
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(3),
            "connect took too long: {elapsed:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("timed out after 1s"),
            "expected a timeout message, got: {msg}"
        );
    }
}
