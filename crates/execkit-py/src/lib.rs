// SPDX-License-Identifier: Apache-2.0
//! Native Python bindings for execkit, built into the `execkit` PyPI wheel.
//!
//! The Rust `execkit` crate stays the single source of truth for all
//! security-critical behavior (policy fence, secret redaction, SSH host-key
//! verification, sentinel framing); this layer only marshals values and maps
//! errors. Blocking calls release the GIL via `Python::detach`.

use std::sync::Mutex;
use std::time::Duration;

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;

use execkit_core::{Budget, Grep, Keep, Policy as RsPolicy, Session as RsSession};

// --- exception hierarchy (see the design spec) ----------------------------
create_exception!(execkit, ExeckitError, PyException);
create_exception!(execkit, PolicyViolation, ExeckitError);
create_exception!(execkit, TransportError, ExeckitError);
create_exception!(execkit, Unsupported, ExeckitError);
create_exception!(execkit, BudgetError, ExeckitError);
create_exception!(execkit, SessionUnusable, ExeckitError);
create_exception!(execkit, Timeout, SessionUnusable);
create_exception!(execkit, ShellExited, SessionUnusable);
create_exception!(execkit, SessionPoisoned, SessionUnusable);

/// Map a Rust `execkit::Error` onto the Python exception tree. The wildcard arm
/// covers `Serde` and any future `#[non_exhaustive]` variant.
fn map_err(e: execkit_core::Error) -> PyErr {
    use execkit_core::Error as E;
    let msg = e.to_string();
    match e {
        E::PolicyDenied(_) => PolicyViolation::new_err(msg),
        E::Transport(_) | E::Io(_) => TransportError::new_err(msg),
        E::Unsupported(_) => Unsupported::new_err(msg),
        E::Budget(_) => BudgetError::new_err(msg),
        E::StillRunning => Timeout::new_err(msg),
        E::ShellExited => ShellExited::new_err(msg),
        E::SessionPoisoned => SessionPoisoned::new_err(msg),
        _ => ExeckitError::new_err(msg),
    }
}

/// A structured, secret-redacted, bounded result for one command.
#[pyclass(frozen, name = "ExecResult")]
struct ExecResult {
    #[pyo3(get)]
    command: String,
    #[pyo3(get)]
    stdout: String,
    #[pyo3(get)]
    stderr: String,
    #[pyo3(get)]
    exit_code: i32,
    #[pyo3(get)]
    duration_ms: u64,
    #[pyo3(get)]
    cwd: String,
    #[pyo3(get)]
    truncated: bool,
}

#[pymethods]
impl ExecResult {
    fn __repr__(&self) -> String {
        format!(
            "ExecResult(exit_code={}, cwd={:?}, truncated={}, stdout_len={}, stderr_len={})",
            self.exit_code,
            self.cwd,
            self.truncated,
            self.stdout.len(),
            self.stderr.len()
        )
    }
}

impl From<execkit_core::ExecResult> for ExecResult {
    fn from(r: execkit_core::ExecResult) -> Self {
        ExecResult {
            command: r.command,
            stdout: r.stdout,
            stderr: r.stderr,
            exit_code: r.exit_code,
            duration_ms: r.duration_ms,
            cwd: r.cwd,
            truncated: r.truncated,
        }
    }
}

/// Advisory command policy: deny-listed substrings are blocked before the shell.
// `from_py_object` so a `Policy` instance can be passed into the factory kwargs.
#[pyclass(name = "Policy", from_py_object)]
#[derive(Clone)]
struct Policy {
    allow: Vec<String>,
    deny: Vec<String>,
}

#[pymethods]
impl Policy {
    #[new]
    #[pyo3(signature = (allow=None, deny=None))]
    fn new(allow: Option<Vec<String>>, deny: Option<Vec<String>>) -> Self {
        Policy {
            allow: allow.unwrap_or_default(),
            deny: deny.unwrap_or_default(),
        }
    }
}

impl Policy {
    fn to_rust(&self) -> RsPolicy {
        RsPolicy {
            allow: self.allow.clone(),
            deny: self.deny.clone(),
        }
    }
}

/// Build an output `Budget` from the per-call/session kwargs, or `None` if none
/// were given (so the session default, if any, applies).
fn build_budget(
    tail: Option<usize>,
    head: Option<usize>,
    grep: Option<String>,
    max_chars: Option<usize>,
) -> Option<Budget> {
    if tail.is_none() && head.is_none() && grep.is_none() && max_chars.is_none() {
        return None;
    }
    let keep = match (head, tail) {
        (Some(h), Some(t)) => Keep::HeadTail(h, t),
        (Some(h), None) => Keep::Head(h),
        (None, Some(t)) => Keep::Tail(t),
        (None, None) => Keep::All,
    };
    Some(Budget {
        grep: grep.map(|pattern| Grep {
            pattern,
            context: 0,
        }),
        keep,
        max_chars,
    })
}

/// Apply the shared option kwargs to a freshly built session.
#[allow(clippy::too_many_arguments)]
fn apply_opts(
    mut s: RsSession,
    policy: Option<Policy>,
    timeout: Option<f64>,
    max_output_bytes: Option<usize>,
    tail: Option<usize>,
    head: Option<usize>,
    grep: Option<String>,
    max_chars: Option<usize>,
) -> PyResult<RsSession> {
    if let Some(p) = policy {
        s = s.with_policy(p.to_rust());
    }
    if let Some(t) = timeout {
        if !t.is_finite() || t < 0.0 {
            return Err(PyValueError::new_err(
                "timeout must be a non-negative number of seconds",
            ));
        }
        s = s.with_timeout(Duration::from_secs_f64(t));
    }
    if let Some(m) = max_output_bytes {
        s = s.with_max_output(m);
    }
    if let Some(b) = build_budget(tail, head, grep, max_chars) {
        s = s.with_output_budget(b);
    }
    Ok(s)
}

/// A persistent, stateful shell session (cwd/env stick across commands).
///
/// The session is held behind a `Mutex` so the `#[pyclass]` is `Sync` (the Rust
/// `Session` is `Send` but not `Sync`). A side benefit: two Python threads that
/// `exec` on the same `Session` serialize on the lock rather than racing the
/// single framed channel. The `Option` lets the context manager / `close()` drop
/// the underlying process deterministically.
#[pyclass(name = "Session")]
struct Session {
    inner: Mutex<Option<RsSession>>,
}

impl Session {
    fn wrap(s: RsSession) -> Self {
        Session {
            inner: Mutex::new(Some(s)),
        }
    }
}

#[pymethods]
impl Session {
    /// Open a local PTY session.
    #[staticmethod]
    #[pyo3(signature = (*, policy=None, timeout=None, max_output_bytes=None, tail=None, head=None, grep=None, max_chars=None))]
    #[allow(clippy::too_many_arguments)]
    fn local(
        py: Python<'_>,
        policy: Option<Policy>,
        timeout: Option<f64>,
        max_output_bytes: Option<usize>,
        tail: Option<usize>,
        head: Option<usize>,
        grep: Option<String>,
        max_chars: Option<usize>,
    ) -> PyResult<Self> {
        let s = py.detach(RsSession::local).map_err(map_err)?;
        let s = apply_opts(
            s,
            policy,
            timeout,
            max_output_bytes,
            tail,
            head,
            grep,
            max_chars,
        )?;
        Ok(Session::wrap(s))
    }

    /// Attach to a running Docker container (`docker exec`).
    #[staticmethod]
    #[pyo3(signature = (container, *, policy=None, timeout=None, max_output_bytes=None, tail=None, head=None, grep=None, max_chars=None))]
    #[allow(clippy::too_many_arguments)]
    fn docker(
        py: Python<'_>,
        container: String,
        policy: Option<Policy>,
        timeout: Option<f64>,
        max_output_bytes: Option<usize>,
        tail: Option<usize>,
        head: Option<usize>,
        grep: Option<String>,
        max_chars: Option<usize>,
    ) -> PyResult<Self> {
        let s = py
            .detach(|| RsSession::docker(&container))
            .map_err(map_err)?;
        let s = apply_opts(
            s,
            policy,
            timeout,
            max_output_bytes,
            tail,
            head,
            grep,
            max_chars,
        )?;
        Ok(Session::wrap(s))
    }

    /// Run a command and return a structured result. Releases the GIL while the
    /// command runs. Per-call budget kwargs override the session default.
    #[pyo3(signature = (command, *, tail=None, head=None, grep=None, max_chars=None))]
    fn exec(
        &self,
        py: Python<'_>,
        command: String,
        tail: Option<usize>,
        head: Option<usize>,
        grep: Option<String>,
        max_chars: Option<usize>,
    ) -> PyResult<ExecResult> {
        let budget = build_budget(tail, head, grep, max_chars);
        let mut guard = self.inner.lock().unwrap();
        let s = guard
            .as_mut()
            .ok_or_else(|| ExeckitError::new_err("session is closed"))?;
        let r = py
            .detach(|| match &budget {
                Some(b) => s.exec_budgeted(&command, b),
                None => s.exec(&command),
            })
            .map_err(map_err)?;
        Ok(r.into())
    }

    /// True if a prior timeout left the session unusable (or it is closed).
    #[getter]
    fn is_poisoned(&self) -> bool {
        self.inner
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|s| s.is_poisoned())
    }

    /// Drop the underlying session and its process. Idempotent.
    fn close(&self, py: Python<'_>) {
        let taken = self.inner.lock().unwrap().take();
        if let Some(s) = taken {
            py.detach(move || drop(s));
        }
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    #[pyo3(signature = (_exc_type, _exc_value, _traceback))]
    fn __exit__(
        &self,
        py: Python<'_>,
        _exc_type: &Bound<'_, PyAny>,
        _exc_value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) -> bool {
        self.close(py);
        false
    }
}

#[pymodule]
fn execkit(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add_class::<Session>()?;
    m.add_class::<ExecResult>()?;
    m.add_class::<Policy>()?;
    m.add("ExeckitError", py.get_type::<ExeckitError>())?;
    m.add("PolicyViolation", py.get_type::<PolicyViolation>())?;
    m.add("TransportError", py.get_type::<TransportError>())?;
    m.add("Unsupported", py.get_type::<Unsupported>())?;
    m.add("BudgetError", py.get_type::<BudgetError>())?;
    m.add("SessionUnusable", py.get_type::<SessionUnusable>())?;
    m.add("Timeout", py.get_type::<Timeout>())?;
    m.add("ShellExited", py.get_type::<ShellExited>())?;
    m.add("SessionPoisoned", py.get_type::<SessionPoisoned>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
