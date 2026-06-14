# SPDX-License-Identifier: Apache-2.0
"""SSH binding tests.

The arg-validation tests run everywhere (they exercise `build_ssh_config`
without a network). The live test is gated on `EXECKIT_TEST_SSH` and runs in the
ssh-e2e CI job against the same throwaway sshd the Rust smoke uses.
"""
import os

import pytest

from execkit import Session


def test_ssh_requires_an_auth_method():
    with pytest.raises(ValueError):
        Session.ssh("host", user="u")


def test_ssh_rejects_two_auth_methods():
    with pytest.raises(ValueError):
        Session.ssh("host", user="u", password="p", key_path="/some/key")


def _parse(spec):
    # format: user:password@host:port
    userpass, hostport = spec.rsplit("@", 1)
    user, password = userpass.split(":", 1)
    host, port = hostport.split(":", 1)
    return user, password, host, int(port)


@pytest.mark.skipif(
    not os.environ.get("EXECKIT_TEST_SSH"),
    reason="set EXECKIT_TEST_SSH=user:password@host:port for the live SSH test",
)
def test_ssh_live_exec_and_state_persists():
    user, password, host, port = _parse(os.environ["EXECKIT_TEST_SSH"])
    # The CI sshd presents a fresh host key; accept-any is the test-only opt-in.
    with Session.ssh(
        host,
        user=user,
        password=password,
        port=port,
        insecure_accept_any_host_key=True,
    ) as s:
        r = s.exec("echo OUT; echo ERR 1>&2; cd /tmp; true")
        assert r.exit_code == 0
        assert "OUT" in r.stdout
        assert r.stderr == "ERR"
        assert r.cwd == "/tmp"
        # cwd persists across commands on the same SSH session
        assert s.exec("pwd").stdout == "/tmp"
