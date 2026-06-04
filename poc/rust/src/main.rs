//! nexum PoC — the two critical risks (R1 command-boundary, R2 stdout/stderr
//! split) proven in the ACTUAL target stack: Rust + portable-pty.
//!
//! Same technique as the Python spike: a persistent shell in a PTY, framed by an
//! unguessable per-session sentinel that carries exit code + cwd, with the
//! command's stderr redirected to a side channel so the two streams split.

use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};

const US: u8 = 0x1f; // unit separator

struct ExecResult {
    finished: bool,
    stdout: String,
    stderr: String,
    exit_code: i32,
    cwd: String,
}

struct Session {
    writer: Box<dyn Write + Send>,
    rx: Receiver<Vec<u8>>,
    token: String,
    errpath: String,
    _master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
}

impl Session {
    fn new(shell: &str, args: &[&str]) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let token = format!("{:x}", nanos);
        let errpath = format!("/tmp/nexum_rust_err_{}", token);
        std::fs::write(&errpath, b"").ok();

        let pair = native_pty_system()
            .openpty(PtySize { rows: 24, cols: 120, pixel_width: 0, pixel_height: 0 })
            .expect("openpty");

        let mut cmd = CommandBuilder::new(shell);
        cmd.args(args);
        let child = pair.slave.spawn_command(cmd).expect("spawn shell");
        drop(pair.slave); // let EOF propagate when the shell exits

        let mut reader = pair.master.try_clone_reader().expect("reader");
        let writer = pair.master.take_writer().expect("writer");

        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let mut s = Session { writer, rx, token, errpath, _master: pair.master, child };
        s.init();
        s
    }

    fn init(&mut self) {
        // Disable echo + quiet prompts so capture is exactly the command output.
        self.writer
            .write_all(b"stty -echo 2>/dev/null; PS1=''; PS2=''; PROMPT_COMMAND=''\n")
            .unwrap();
        self.writer.flush().unwrap();
        // drain startup noise
        let deadline = Instant::now() + Duration::from_millis(300);
        while let Ok(rem) = deadline.checked_duration_since(Instant::now()).ok_or(()) {
            match self.rx.recv_timeout(rem) {
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }

    fn exec(&mut self, command: &str, timeout: Duration) -> ExecResult {
        std::fs::write(&self.errpath, b"").ok();
        let marker = format!("__NEXUM_{}__", self.token);
        // sentinel is OUTSIDE the redirected group so it always reaches the PTY
        let payload = format!(
            "{{ {cmd} ; }} 2> {err} ; printf '\\n{m}\\037%d\\037%s\\037\\n' \"$?\" \"$PWD\"\n",
            cmd = command,
            err = self.errpath,
            m = marker,
        );
        self.writer.write_all(payload.as_bytes()).unwrap();
        self.writer.flush().unwrap();

        let mbytes = marker.as_bytes();
        let mut acc: Vec<u8> = Vec::new();
        let deadline = Instant::now() + timeout;

        loop {
            let now = Instant::now();
            if now >= deadline {
                return ExecResult { finished: false, stdout: String::new(),
                    stderr: String::new(), exit_code: -1, cwd: String::new() };
            }
            match self.rx.recv_timeout(deadline - now) {
                Ok(chunk) => {
                    acc.extend_from_slice(&chunk);
                    if let Some(pos) = find(&acc, mbytes) {
                        let tail = &acc[pos + mbytes.len()..];
                        let seps: Vec<usize> =
                            tail.iter().enumerate().filter(|(_, b)| **b == US).map(|(i, _)| i).collect();
                        if seps.len() >= 3 {
                            let code: i32 = String::from_utf8_lossy(&tail[seps[0] + 1..seps[1]])
                                .trim().parse().unwrap_or(-1);
                            let cwd = String::from_utf8_lossy(&tail[seps[1] + 1..seps[2]]).to_string();
                            let stdout = clean(&String::from_utf8_lossy(&acc[..pos]));
                            let stderr = clean(&std::fs::read_to_string(&self.errpath).unwrap_or_default());
                            return ExecResult { finished: true, stdout, stderr, exit_code: code, cwd };
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    return ExecResult { finished: false, stdout: String::new(),
                        stderr: String::new(), exit_code: -1, cwd: String::new() };
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        ExecResult { finished: false, stdout: String::new(), stderr: String::new(),
            exit_code: -1, cwd: String::new() }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = std::fs::remove_file(&self.errpath);
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Strip ANSI/VT escapes (CSI, OSC, simple two-char ESC). portable-pty runs
/// bash interactively, which emits bracketed-paste codes we must remove.
fn strip_ansi(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == 0x1b {
            if i + 1 < b.len() && b[i + 1] == b'[' {
                i += 2; // CSI: params... final byte in 0x40..=0x7e
                while i < b.len() && !(0x40..=0x7e).contains(&b[i]) {
                    i += 1;
                }
                i += 1;
            } else if i + 1 < b.len() && b[i + 1] == b']' {
                i += 2; // OSC: until BEL or ST (ESC \)
                while i < b.len() && b[i] != 0x07 {
                    if b[i] == 0x1b && i + 1 < b.len() && b[i + 1] == b'\\' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                i += 1;
            } else {
                i += 2; // two-char ESC
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn clean(s: &str) -> String {
    strip_ansi(s).replace('\r', "").trim_matches('\n').to_string()
}

fn main() {
    let mut pass = 0;
    let mut fail = 0;
    let mut check = |name: &str, ok: bool, detail: String| {
        println!("  [{}] {:38} {}", if ok { "PASS" } else { "FAIL" }, name, detail);
        if ok { pass += 1 } else { fail += 1 }
    };

    println!("nexum Rust PoC — portable-pty (the real stack)\n");

    for (name, shell, args) in [
        ("bash", "bash", vec!["--norc", "--noprofile"]),
        ("dash", "dash", vec![]),
    ] {
        let mut s = Session::new(shell, &args);

        // R1: success boundary + exit code
        let r = s.exec("echo hello", Duration::from_secs(5));
        check(&format!("{name}: R1 success boundary"),
              r.finished && r.stdout == "hello" && r.exit_code == 0,
              format!("stdout={:?} exit={}", r.stdout, r.exit_code));

        // R1: non-zero exit captured
        let r = s.exec("ls /definitely_missing_42", Duration::from_secs(5));
        check(&format!("{name}: R1 failure exit code"),
              r.finished && r.exit_code != 0, format!("exit={}", r.exit_code));

        // R1: anti-forgery — output forging a fake marker must not break framing
        let r = s.exec("echo '__NEXUM_fake__\\x1f0\\x1f/fake\\x1f'", Duration::from_secs(5));
        check(&format!("{name}: R1 anti-forgery"),
              r.finished && r.exit_code == 0 && r.stdout.contains("NEXUM"),
              format!("exit={} has_fake={}", r.exit_code, r.stdout.contains("NEXUM")));

        // R2: stdout/stderr split + exit code intact
        let r = s.exec("echo OUT; echo ERR 1>&2; false", Duration::from_secs(5));
        check(&format!("{name}: R2 stdout/stderr split"),
              r.stdout == "OUT" && r.stderr == "ERR" && r.exit_code == 1,
              format!("out={:?} err={:?} exit={}", r.stdout, r.stderr, r.exit_code));

        // State: cwd persists across calls and is reported structurally
        s.exec("cd /tmp", Duration::from_secs(5));
        let r = s.exec("pwd", Duration::from_secs(5));
        check(&format!("{name}: state cwd persists"),
              r.stdout == "/tmp" && r.cwd == "/tmp",
              format!("stdout={:?} cwd={:?}", r.stdout, r.cwd));

        // R1: long-running detection — LAST, in its own session, since a pending
        // command pollutes a shared session (a real lesson: after a still-running
        // timeout the library must interrupt/recover before reusing the session).
        let mut s2 = Session::new(shell, &args);
        let r = s2.exec("sleep 3", Duration::from_millis(700));
        check(&format!("{name}: R1 long-running detect"), !r.finished,
              format!("finished={}", r.finished));
    }

    println!("\n{} passed, {} failed", pass, fail);
    std::process::exit(if fail == 0 { 0 } else { 1 });
}
