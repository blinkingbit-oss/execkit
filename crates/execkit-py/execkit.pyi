# SPDX-License-Identifier: Apache-2.0
"""Type stubs for the execkit native extension."""
from typing import Optional, final

__version__: str

@final
class Policy:
    def __init__(
        self,
        allow: Optional[list[str]] = ...,
        deny: Optional[list[str]] = ...,
    ) -> None: ...

@final
class ExecResult:
    @property
    def command(self) -> str: ...
    @property
    def stdout(self) -> str: ...
    @property
    def stderr(self) -> str: ...
    @property
    def exit_code(self) -> int: ...
    @property
    def duration_ms(self) -> int: ...
    @property
    def cwd(self) -> str: ...
    @property
    def truncated(self) -> bool: ...
    def __repr__(self) -> str: ...

@final
class Session:
    @staticmethod
    def local(
        *,
        policy: Optional[Policy] = ...,
        timeout: Optional[float] = ...,
        max_output_bytes: Optional[int] = ...,
        tail: Optional[int] = ...,
        head: Optional[int] = ...,
        grep: Optional[str] = ...,
        max_chars: Optional[int] = ...,
    ) -> "Session": ...
    @staticmethod
    def docker(
        container: str,
        *,
        policy: Optional[Policy] = ...,
        timeout: Optional[float] = ...,
        max_output_bytes: Optional[int] = ...,
        tail: Optional[int] = ...,
        head: Optional[int] = ...,
        grep: Optional[str] = ...,
        max_chars: Optional[int] = ...,
    ) -> "Session": ...
    @staticmethod
    def ssh(
        host: str,
        *,
        user: str,
        port: int = ...,
        password: Optional[str] = ...,
        key_path: Optional[str] = ...,
        key_passphrase: Optional[str] = ...,
        known_hosts: Optional[str] = ...,
        pin: Optional[str] = ...,
        insecure_accept_any_host_key: bool = ...,
        policy: Optional[Policy] = ...,
        timeout: Optional[float] = ...,
        max_output_bytes: Optional[int] = ...,
        tail: Optional[int] = ...,
        head: Optional[int] = ...,
        grep: Optional[str] = ...,
        max_chars: Optional[int] = ...,
    ) -> "Session": ...
    def exec(
        self,
        command: str,
        *,
        tail: Optional[int] = ...,
        head: Optional[int] = ...,
        grep: Optional[str] = ...,
        max_chars: Optional[int] = ...,
    ) -> ExecResult: ...
    @property
    def is_poisoned(self) -> bool: ...
    def close(self) -> None: ...
    def __enter__(self) -> "Session": ...
    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool: ...

class ExeckitError(Exception): ...
class PolicyViolation(ExeckitError): ...
class TransportError(ExeckitError): ...
class Unsupported(ExeckitError): ...
class BudgetError(ExeckitError): ...
class SessionUnusable(ExeckitError): ...
class Timeout(SessionUnusable): ...
class ShellExited(SessionUnusable): ...
class SessionPoisoned(SessionUnusable): ...
