# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the execkit Python SDK over the local transport.

These assert the binding/marshaling (values cross the FFI boundary correctly and
errors map to the right exception types). The Rust core is the source of truth
for the behavior itself.
"""
import pytest

import execkit
from execkit import (
    Session,
    Policy,
    ExecResult,
    ExeckitError,
    PolicyViolation,
    SessionUnusable,
    Timeout,
)


def test_version_is_exposed():
    assert isinstance(execkit.__version__, str)
    assert execkit.__version__.count(".") >= 2


def test_exec_splits_streams_exit_code_and_persists_cwd():
    with Session.local() as s:
        r = s.exec("echo OUT; echo ERR 1>&2; cd /tmp; false")
        assert isinstance(r, ExecResult)
        assert r.stdout == "OUT"
        assert r.stderr == "ERR"
        assert r.exit_code == 1
        assert r.cwd == "/tmp"
        assert r.duration_ms >= 0
        assert r.truncated is False
        # cwd persists into the next command (stateful session)
        assert s.exec("pwd").stdout == "/tmp"


def test_repr_is_friendly_and_hides_payload():
    with Session.local() as s:
        r = s.exec("echo hello")
        text = repr(r)
        assert text.startswith("ExecResult(")
        assert "exit_code=0" in text
        assert "hello" not in text  # repr summarizes, does not dump output


def test_secret_redaction_flows_through():
    with Session.local() as s:
        r = s.exec("echo k=AKIAIOSFODNN7EXAMPLE")
        assert "[REDACTED]" in r.stdout
        assert "AKIA" not in r.stdout


def test_policy_denial_raises_policy_violation():
    with Session.local(policy=Policy(deny=["rm"])) as s:
        with pytest.raises(PolicyViolation) as ei:
            s.exec("rm -rf /tmp/whatever")
        assert isinstance(ei.value, ExeckitError)  # category catch works


def test_output_budget_tail_kwarg_trims_and_flags_truncated():
    with Session.local() as s:
        r = s.exec("for i in $(seq 1 100); do echo line$i; done", tail=3)
        lines = r.stdout.splitlines()
        assert lines[-3:] == ["line98", "line99", "line100"]
        assert r.truncated is True


def test_output_budget_grep_kwarg_filters():
    with Session.local() as s:
        r = s.exec(
            "echo apple; echo banana; echo ERROR boom; echo cherry",
            grep="ERROR",
        )
        assert "ERROR boom" in r.stdout
        assert "apple" not in r.stdout


def test_timeout_raises_timeout_and_poisons_session():
    with Session.local(timeout=1.0) as s:
        assert s.is_poisoned is False
        with pytest.raises(Timeout) as ei:
            s.exec("sleep 5")
        # Timeout is a SessionUnusable is an ExeckitError
        assert isinstance(ei.value, SessionUnusable)
        assert isinstance(ei.value, ExeckitError)
        assert s.is_poisoned is True


def test_context_manager_closes_session():
    s = Session.local()
    assert s.exec("echo hi").stdout == "hi"
    s.__exit__(None, None, None)
    with pytest.raises(ExeckitError):
        s.exec("echo nope")


def test_close_is_idempotent():
    s = Session.local()
    s.close()
    s.close()  # second close must not raise
    assert s.is_poisoned is True


def test_invalid_timeout_raises_value_error():
    with pytest.raises(ValueError):
        Session.local(timeout=-1.0)
