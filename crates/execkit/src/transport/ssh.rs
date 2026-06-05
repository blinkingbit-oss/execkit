// SPDX-License-Identifier: Apache-2.0
//! SSH transport configuration and host-key verification.
//!
//! The russh-backed I/O is wired separately; the pieces here - connection
//! config, auth, and the **host-key policy** (the load-bearing MITM defense) -
//! are pure and unit-tested, independent of any network.

use std::path::{Path, PathBuf};

use crate::error::Result;

/// How to reach an SSH host.
#[derive(Clone)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: SshAuth,
    pub host_key: HostKeyVerification,
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
    fingerprint: &str,
) -> Result<bool> {
    match policy {
        HostKeyVerification::AcceptAny => Ok(true),
        HostKeyVerification::Pinned(expected) => Ok(expected == fingerprint),
        HostKeyVerification::KnownHosts(path) => verify_known_hosts(path, host, fingerprint),
    }
}

#[allow(dead_code)]
fn verify_known_hosts(path: &Path, host: &str, fingerprint: &str) -> Result<bool> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    for line in content.lines() {
        let mut it = line.split_whitespace();
        if let (Some(h), Some(fp)) = (it.next(), it.next()) {
            if h == host {
                // Known host: the fingerprint MUST match. A mismatch is a MITM
                // signal - reject loudly, never silently re-pin.
                return Ok(fp == fingerprint);
            }
        }
    }
    // Unseen host: trust on first use and pin it. One atomic O_APPEND write so a
    // concurrent reader never sees a partial line.
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(format!("{host} {fingerprint}\n").as_bytes())?;
    Ok(true)
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
            Ok(verify_fingerprint(&self.policy, &self.host, &fp).unwrap_or(false))
        }
    }

    async fn establish(
        cfg: &SshConfig,
    ) -> Result<(client::Handle<Handler>, russh::Channel<client::Msg>)> {
        let config = Arc::new(client::Config::default());
        let handler = Handler {
            policy: cfg.host_key.clone(),
            host: cfg.host.clone(),
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
                let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
                handle
                    .authenticate_publickey(cfg.user.clone(), key)
                    .await
                    .map_err(|e| Error::Transport(format!("ssh auth: {e}")))?
            }
        };
        if !result.success() {
            return Err(Error::Transport("ssh authentication failed".into()));
        }

        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Transport(format!("open channel: {e}")))?;
        channel
            .request_pty(false, "xterm-256color", 120, 40, 0, 0, &[])
            .await
            .map_err(|e| Error::Transport(format!("request pty: {e}")))?;
        channel
            .request_shell(false)
            .await
            .map_err(|e| Error::Transport(format!("request shell: {e}")))?;
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
                    // (stalls reads → TCP backpressure) under a flood.
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
        assert!(verify_fingerprint(&p, "h", "SHA256:abc").unwrap());
        assert!(!verify_fingerprint(&p, "h", "SHA256:evil").unwrap());
    }

    #[test]
    fn known_hosts_tofu_then_pins_and_detects_change() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("execkit_kh_test_{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let p = HostKeyVerification::KnownHosts(path.clone());

        // First sight: accepted (TOFU) and pinned.
        assert!(verify_fingerprint(&p, "prod-1", "SHA256:good").unwrap());
        // Same key again: accepted.
        assert!(verify_fingerprint(&p, "prod-1", "SHA256:good").unwrap());
        // Changed key for a known host: REJECTED (MITM).
        assert!(!verify_fingerprint(&p, "prod-1", "SHA256:evil").unwrap());
        // A different host is independent.
        assert!(verify_fingerprint(&p, "prod-2", "SHA256:other").unwrap());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn auth_debug_redacts_secrets() {
        let a = SshAuth::Password("hunter2".into());
        assert!(!format!("{a:?}").contains("hunter2"));
    }
}
