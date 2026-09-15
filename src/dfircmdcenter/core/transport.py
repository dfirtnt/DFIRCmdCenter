"""Bounded HTTP and subprocess transports for platform adapters.

These primitives intentionally expose no arbitrary URL or shell surface.  Each
adapter supplies a fixed policy and receives only bounded output.  Diagnostics
contain metadata only: request/response bodies, headers, query values, command
arguments, and environments are never emitted.
"""

from __future__ import annotations

import email.utils
import os
import random
import re
import selectors
import signal
import subprocess
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from types import TracebackType
from typing import IO, Literal, cast
from urllib.parse import unquote, urlsplit

import httpx


class TransmissionState(str, Enum):
    """How confidently a failed request can be classified."""

    NOT_SENT = "not_sent"
    RESPONSE_RECEIVED = "response_received"
    UNKNOWN = "unknown"


class TransportError(RuntimeError):
    """Base error that never embeds untrusted output or credentials."""

    def __init__(self, message: str, *, transmission: TransmissionState) -> None:
        super().__init__(message)
        self.transmission = transmission


class UnsafeTransportInput(TransportError):
    def __init__(self, message: str) -> None:
        super().__init__(message, transmission=TransmissionState.NOT_SENT)


class ResponseLimitExceeded(TransportError):
    def __init__(self) -> None:
        super().__init__(
            "HTTP response exceeded the configured byte limit",
            transmission=TransmissionState.RESPONSE_RECEIVED,
        )


class ProcessLimitExceeded(TransportError):
    def __init__(self, dimension: str) -> None:
        super().__init__(
            f"subprocess exceeded the configured {dimension} limit",
            transmission=TransmissionState.UNKNOWN,
        )


class ProcessTimedOut(TransportError):
    def __init__(self) -> None:
        super().__init__(
            "subprocess exceeded the configured runtime limit",
            transmission=TransmissionState.UNKNOWN,
        )


@dataclass(frozen=True, slots=True)
class HttpLimits:
    connect_timeout: float = 5.0
    read_timeout: float = 20.0
    write_timeout: float = 10.0
    pool_timeout: float = 5.0
    overall_timeout: float = 30.0
    max_response_bytes: int = 4 * 1024 * 1024
    max_query_fields: int = 24
    max_query_value_chars: int = 2048
    max_attempts: int = 3
    base_retry_delay: float = 0.25
    max_retry_delay: float = 5.0

    def __post_init__(self) -> None:
        positive = (
            self.connect_timeout,
            self.read_timeout,
            self.write_timeout,
            self.pool_timeout,
            self.overall_timeout,
            self.max_response_bytes,
            self.max_query_fields,
            self.max_query_value_chars,
            self.max_attempts,
            self.max_retry_delay,
        )
        if any(value <= 0 for value in positive) or self.base_retry_delay < 0:
            raise ValueError("HTTP transport limits must be positive")


@dataclass(frozen=True, slots=True)
class HttpPolicy:
    """Fixed request surface for one adapter HTTP client."""

    base_url: str
    allowed_origins: frozenset[str]
    allowed_query_keys: frozenset[str] = field(default_factory=frozenset)
    allowed_request_headers: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"accept", "authorization", "content-type", "user-agent"}
        )
    )


@dataclass(frozen=True, slots=True)
class HttpDiagnostic:
    """Safe metadata event.  It never contains headers, bodies, or query data."""

    method: str
    path: str
    attempt: int
    event: Literal["request", "retry", "response", "error"]
    status_code: int | None = None
    response_bytes: int | None = None
    sensitive_response: bool = False


@dataclass(frozen=True, slots=True)
class BoundedHttpResponse:
    status_code: int
    body: bytes
    headers: Mapping[str, str]
    method: str
    path: str


type QueryScalar = str | int | float | bool
type QueryValue = QueryScalar | Sequence[QueryScalar]

_READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
_SAFE_RESPONSE_HEADERS = frozenset(
    {"content-length", "content-type", "date", "etag", "last-modified", "retry-after"}
)
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeTransportInput("HTTP origin must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise UnsafeTransportInput("HTTP origin cannot contain credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise UnsafeTransportInput("allowlisted origins cannot include a path")
    if parsed.scheme == "http" and parsed.hostname.lower() not in _LOOPBACK_HOSTS:
        raise UnsafeTransportInput("cleartext HTTP is allowed only for loopback origins")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port
    suffix = "" if port in {None, default_port} else f":{port}"
    return f"{parsed.scheme.lower()}://{host}{suffix}"


def _validate_relative_path(path: str) -> str:
    if not path.startswith("/") or path.startswith("//"):
        raise UnsafeTransportInput("HTTP path must be one absolute-path reference")
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or "\\" in path:
        raise UnsafeTransportInput("HTTP path cannot contain an origin, query, or fragment")
    decoded = unquote(parsed.path)
    if _CONTROL_RE.search(decoded):
        raise UnsafeTransportInput("HTTP path contains control characters")
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        raise UnsafeTransportInput("HTTP path traversal is not allowed")
    return parsed.path


def _validate_header(name: str, value: str, allowed: frozenset[str]) -> tuple[str, str]:
    normalized = name.lower()
    if normalized not in allowed:
        raise UnsafeTransportInput(f"request header is not allowlisted: {normalized}")
    if _CONTROL_RE.search(name) or _CONTROL_RE.search(value):
        raise UnsafeTransportInput("request header contains control characters")
    return normalized, value


class HttpTransport:
    """Synchronous, origin-pinned, bounded HTTP transport."""

    def __init__(
        self,
        policy: HttpPolicy,
        *,
        limits: HttpLimits | None = None,
        default_headers: Mapping[str, str] | None = None,
        client: httpx.Client | None = None,
        diagnostic_hook: Callable[[HttpDiagnostic], None] | None = None,
        redactor: Callable[[str], str] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        jitter: Callable[[float, float], float] = random.uniform,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy
        self.limits = limits or HttpLimits()
        origins = frozenset(_origin(item) for item in policy.allowed_origins)
        if not origins:
            raise UnsafeTransportInput("at least one HTTP origin must be allowlisted")

        base = urlsplit(policy.base_url)
        base_origin = _origin(f"{base.scheme}://{base.netloc}")
        if base_origin not in origins:
            raise UnsafeTransportInput("configured base URL is not in the origin allowlist")
        if base.query or base.fragment or base.username or base.password:
            raise UnsafeTransportInput("configured base URL contains unsafe components")
        if base.path:
            _validate_relative_path(base.path)
        self._base_url = policy.base_url.rstrip("/")

        self._headers = dict(
            _validate_header(name, value, policy.allowed_request_headers)
            for name, value in (default_headers or {}).items()
        )
        self._diagnostic_hook = diagnostic_hook
        self._redactor = redactor or (lambda value: value)
        self._sleep = sleep
        self._jitter = jitter
        self._monotonic = monotonic
        self._owns_client = client is None
        self._client = client or httpx.Client(follow_redirects=False, trust_env=False)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> HttpTransport:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, QueryValue] | None = None,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
        json: object | None = None,
        sensitive_response: bool = False,
    ) -> BoundedHttpResponse:
        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"}:
            raise UnsafeTransportInput("HTTP method is not supported")
        safe_path = _validate_relative_path(path)
        params = self._validate_query(query or {})
        request_headers = dict(self._headers)
        for name, value in (headers or {}).items():
            key, clean_value = _validate_header(
                name, value, self.policy.allowed_request_headers
            )
            request_headers[key] = clean_value

        if content is not None and json is not None:
            raise UnsafeTransportInput("provide either content or JSON, not both")

        started = self._monotonic()
        for attempt in range(1, self.limits.max_attempts + 1):
            self._emit(
                HttpDiagnostic(
                    method=method,
                    path=safe_path,
                    attempt=attempt,
                    event="request",
                    sensitive_response=sensitive_response or self._looks_sensitive(safe_path),
                )
            )
            remaining = self.limits.overall_timeout - (self._monotonic() - started)
            if remaining <= 0:
                raise TransportError(
                    "HTTP request exceeded the configured overall timeout",
                    transmission=TransmissionState.NOT_SENT,
                )

            timeout = httpx.Timeout(
                timeout=min(remaining, self.limits.overall_timeout),
                connect=min(self.limits.connect_timeout, remaining),
                read=min(self.limits.read_timeout, remaining),
                write=min(self.limits.write_timeout, remaining),
                pool=min(self.limits.pool_timeout, remaining),
            )
            try:
                with self._client.stream(
                    method,
                    f"{self._base_url}{safe_path}",
                    params=params,
                    headers=request_headers,
                    content=content,
                    json=json,
                    timeout=timeout,
                ) as response:
                    bounded = self._read_response(response, method, safe_path)
            except ResponseLimitExceeded:
                self._emit_error(method, safe_path, attempt, sensitive_response)
                raise
            except httpx.HTTPError as exc:
                transmission = self._classify_exception(exc)
                self._emit_error(method, safe_path, attempt, sensitive_response)
                if method in _READ_ONLY_METHODS and attempt < self.limits.max_attempts:
                    if self._retry_sleep(attempt, None, started):
                        self._emit_retry(method, safe_path, attempt, sensitive_response)
                        continue
                raise TransportError(
                    "HTTP transport failed without exposing response content",
                    transmission=transmission,
                ) from exc

            self._emit(
                HttpDiagnostic(
                    method=method,
                    path=safe_path,
                    attempt=attempt,
                    event="response",
                    status_code=bounded.status_code,
                    response_bytes=len(bounded.body),
                    sensitive_response=sensitive_response or self._looks_sensitive(safe_path),
                )
            )
            if (
                method in _READ_ONLY_METHODS
                and bounded.status_code in _RETRYABLE_STATUS
                and attempt < self.limits.max_attempts
                and self._retry_sleep(attempt, bounded.headers.get("retry-after"), started)
            ):
                self._emit_retry(method, safe_path, attempt, sensitive_response)
                continue
            return bounded

        raise AssertionError("HTTP attempt loop exhausted unexpectedly")

    def _validate_query(self, query: Mapping[str, QueryValue]) -> httpx.QueryParams:
        if len(query) > self.limits.max_query_fields:
            raise UnsafeTransportInput("too many HTTP query fields")
        result: list[tuple[str, str | int | float | bool | None]] = []
        for key, raw_value in query.items():
            if key not in self.policy.allowed_query_keys:
                raise UnsafeTransportInput(f"query field is not allowlisted: {key}")
            values: Iterable[QueryScalar]
            if isinstance(raw_value, (str, int, float, bool)):
                values = (raw_value,)
            else:
                values = raw_value
            for value in values:
                text = str(value)
                if len(text) > self.limits.max_query_value_chars or _CONTROL_RE.search(text):
                    raise UnsafeTransportInput("HTTP query value exceeds safety bounds")
                result.append((key, text))
        return httpx.QueryParams(result)

    def _read_response(
        self, response: httpx.Response, method: str, path: str
    ) -> BoundedHttpResponse:
        raw_length = response.headers.get("content-length")
        if raw_length is not None:
            try:
                if int(raw_length) > self.limits.max_response_bytes:
                    raise ResponseLimitExceeded
            except ValueError:
                pass

        body = bytearray()
        for chunk in response.iter_bytes():
            if len(body) + len(chunk) > self.limits.max_response_bytes:
                raise ResponseLimitExceeded
            body.extend(chunk)
        safe_headers = {
            key.lower(): value
            for key, value in response.headers.items()
            if key.lower() in _SAFE_RESPONSE_HEADERS
        }
        return BoundedHttpResponse(
            status_code=response.status_code,
            body=bytes(body),
            headers=safe_headers,
            method=method,
            path=path,
        )

    def _retry_sleep(
        self, attempt: int, retry_after: str | None, started: float
    ) -> bool:
        delay = self._parse_retry_after(retry_after)
        if delay is None:
            maximum = min(
                self.limits.max_retry_delay,
                self.limits.base_retry_delay * (2 ** (attempt - 1)),
            )
            delay = self._jitter(0.0, maximum)
        delay = min(delay, self.limits.max_retry_delay)
        remaining = self.limits.overall_timeout - (self._monotonic() - started)
        if delay >= remaining:
            return False
        self._sleep(delay)
        return True

    @staticmethod
    def _parse_retry_after(value: str | None) -> float | None:
        if value is None:
            return None
        try:
            return max(0.0, float(value.strip()))
        except ValueError:
            try:
                parsed = email.utils.parsedate_to_datetime(value)
            except (TypeError, ValueError):
                return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return max(0.0, (parsed - datetime.now(UTC)).total_seconds())

    @staticmethod
    def _classify_exception(exc: httpx.HTTPError) -> TransmissionState:
        if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)):
            return TransmissionState.NOT_SENT
        return TransmissionState.UNKNOWN

    @staticmethod
    def _looks_sensitive(path: str) -> bool:
        return any(part in {"token", "login", "authenticate"} for part in path.lower().split("/"))

    def _emit(self, diagnostic: HttpDiagnostic) -> None:
        if self._diagnostic_hook is not None:
            self._diagnostic_hook(
                HttpDiagnostic(
                    method=diagnostic.method,
                    path=self._redactor(diagnostic.path),
                    attempt=diagnostic.attempt,
                    event=diagnostic.event,
                    status_code=diagnostic.status_code,
                    response_bytes=diagnostic.response_bytes,
                    sensitive_response=diagnostic.sensitive_response,
                )
            )

    def _emit_error(
        self, method: str, path: str, attempt: int, sensitive_response: bool
    ) -> None:
        self._emit(
            HttpDiagnostic(
                method=method,
                path=path,
                attempt=attempt,
                event="error",
                sensitive_response=sensitive_response or self._looks_sensitive(path),
            )
        )

    def _emit_retry(
        self, method: str, path: str, attempt: int, sensitive_response: bool
    ) -> None:
        self._emit(
            HttpDiagnostic(
                method=method,
                path=path,
                attempt=attempt,
                event="retry",
                sensitive_response=sensitive_response or self._looks_sensitive(path),
            )
        )


@dataclass(frozen=True, slots=True)
class ProcessLimits:
    timeout_seconds: float = 30.0
    max_stdout_bytes: int = 2 * 1024 * 1024
    max_stderr_bytes: int = 256 * 1024
    max_stdout_lines: int = 50_000
    max_stderr_lines: int = 5_000
    max_arguments: int = 128
    max_argument_chars: int = 16_384
    max_environment_fields: int = 16
    max_environment_value_chars: int = 4096

    def __post_init__(self) -> None:
        if any(
            value <= 0
            for value in (
                self.timeout_seconds,
                self.max_stdout_bytes,
                self.max_stderr_bytes,
                self.max_stdout_lines,
                self.max_stderr_lines,
                self.max_arguments,
                self.max_argument_chars,
                self.max_environment_fields,
                self.max_environment_value_chars,
            )
        ):
            raise ValueError("subprocess limits must be positive")


@dataclass(frozen=True, slots=True)
class ExecutablePolicy:
    """Allowlisted executable, verbs, paths, environment, and visible output."""

    executable: Path
    allowed_argument_prefixes: tuple[tuple[str, ...], ...]
    allowed_environment: frozenset[str] = field(default_factory=frozenset)
    allowed_cwd_roots: tuple[Path, ...] = ()
    allowed_output_roots: tuple[Path, ...] = ()
    stdout_line_allowlist: tuple[str, ...] = ()
    stderr_line_allowlist: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.executable.is_absolute():
            raise ValueError("allowlisted executables must use absolute paths")
        if not self.allowed_argument_prefixes or any(
            not prefix for prefix in self.allowed_argument_prefixes
        ):
            raise ValueError("each executable needs at least one non-empty argument prefix")


@dataclass(frozen=True, slots=True)
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str
    omitted_stdout_lines: int
    omitted_stderr_lines: int


class SubprocessTransport:
    """Run fixed CLI operations without a shell or inherited environment."""

    def __init__(
        self,
        policies: Sequence[ExecutablePolicy],
        *,
        limits: ProcessLimits | None = None,
        redactor: Callable[[str], str] | None = None,
    ) -> None:
        if not policies:
            raise ValueError("at least one executable policy is required")
        self.limits = limits or ProcessLimits()
        self._redactor = redactor or (lambda value: value)
        self._policies: dict[Path, ExecutablePolicy] = {}
        for policy in policies:
            resolved = policy.executable.resolve(strict=True)
            if not resolved.is_file():
                raise ValueError("allowlisted executable is not a file")
            if resolved in self._policies:
                raise ValueError("duplicate executable policy")
            for pattern in (*policy.stdout_line_allowlist, *policy.stderr_line_allowlist):
                re.compile(pattern)
            self._policies[resolved] = policy

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        environment: Mapping[str, str] | None = None,
        output_paths: Sequence[Path] = (),
    ) -> ProcessResult:
        if not argv or len(argv) > self.limits.max_arguments:
            raise UnsafeTransportInput("subprocess argument count is outside bounds")
        if any(
            not isinstance(arg, str)
            or len(arg) > self.limits.max_argument_chars
            or _CONTROL_RE.search(arg)
            for arg in argv
        ):
            raise UnsafeTransportInput("subprocess argument is outside safety bounds")

        requested = Path(argv[0])
        if not requested.is_absolute():
            raise UnsafeTransportInput("subprocess executable must be an absolute path")
        try:
            executable = requested.resolve(strict=True)
        except OSError as exc:
            raise UnsafeTransportInput("subprocess executable does not exist") from exc
        policy = self._policies.get(executable)
        if policy is None:
            raise UnsafeTransportInput("subprocess executable is not allowlisted")
        if not any(
            tuple(argv[1 : 1 + len(prefix)]) == prefix
            for prefix in policy.allowed_argument_prefixes
        ):
            raise UnsafeTransportInput("subprocess operation is not allowlisted")

        safe_cwd = self._validate_cwd(cwd, policy)
        self._validate_output_paths(output_paths, policy)
        clean_env = self._build_environment(environment or {}, policy)
        command = [str(executable), *argv[1:]]

        try:
            process = subprocess.Popen(  # noqa: S603 - executable and operation are allowlisted
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                cwd=safe_cwd,
                env=clean_env,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            raise TransportError(
                "subprocess could not be started",
                transmission=TransmissionState.NOT_SENT,
            ) from exc
        stdout, stderr = self._collect_bounded(process)
        visible_stdout, omitted_stdout = self._filter_output(
            stdout, policy.stdout_line_allowlist
        )
        visible_stderr, omitted_stderr = self._filter_output(
            stderr, policy.stderr_line_allowlist
        )
        return ProcessResult(
            returncode=process.returncode,
            stdout=visible_stdout,
            stderr=visible_stderr,
            omitted_stdout_lines=omitted_stdout,
            omitted_stderr_lines=omitted_stderr,
        )

    def _validate_cwd(self, cwd: Path | None, policy: ExecutablePolicy) -> str:
        if cwd is None:
            return "/"
        resolved = cwd.resolve(strict=True)
        roots = tuple(root.resolve(strict=True) for root in policy.allowed_cwd_roots)
        if not roots or not any(
            resolved == root or resolved.is_relative_to(root) for root in roots
        ):
            raise UnsafeTransportInput("subprocess working directory is not allowlisted")
        if not resolved.is_dir():
            raise UnsafeTransportInput("subprocess working directory is not a directory")
        return str(resolved)

    def _validate_output_paths(
        self, output_paths: Sequence[Path], policy: ExecutablePolicy
    ) -> None:
        roots = tuple(root.resolve(strict=True) for root in policy.allowed_output_roots)
        for candidate in output_paths:
            if not candidate.is_absolute():
                raise UnsafeTransportInput("subprocess output path must be absolute")
            resolved = candidate.resolve(strict=False)
            if not roots or not any(
                resolved == root or resolved.is_relative_to(root) for root in roots
            ):
                raise UnsafeTransportInput("subprocess output path is not allowlisted")

    def _build_environment(
        self, supplied: Mapping[str, str], policy: ExecutablePolicy
    ) -> dict[str, str]:
        if len(supplied) > self.limits.max_environment_fields:
            raise UnsafeTransportInput("subprocess environment has too many fields")
        result = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
        }
        for key, value in supplied.items():
            if key not in policy.allowed_environment:
                raise UnsafeTransportInput("subprocess environment field is not allowlisted")
            if (
                not re.fullmatch(r"[A-Z][A-Z0-9_]*", key)
                or len(value) > self.limits.max_environment_value_chars
                or _CONTROL_RE.search(value)
            ):
                raise UnsafeTransportInput("subprocess environment value is outside bounds")
            result[key] = value
        return result

    def _collect_bounded(self, process: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
        assert process.stdout is not None
        assert process.stderr is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        line_counts = {"stdout": 0, "stderr": 0}
        byte_limits = {
            "stdout": self.limits.max_stdout_bytes,
            "stderr": self.limits.max_stderr_bytes,
        }
        line_limits = {
            "stdout": self.limits.max_stdout_lines,
            "stderr": self.limits.max_stderr_lines,
        }
        deadline = time.monotonic() + self.limits.timeout_seconds

        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._terminate(process)
                    raise ProcessTimedOut
                events = selector.select(min(remaining, 0.1))
                if not events and process.poll() is not None:
                    # EOF readiness is delivered on the next selector iteration.
                    continue
                for key, _ in events:
                    file_obj = cast(IO[bytes], key.fileobj)
                    chunk = os.read(file_obj.fileno(), 8192)
                    stream = key.data
                    if not chunk:
                        selector.unregister(key.fileobj)
                        file_obj.close()
                        continue
                    buffers[stream].extend(chunk)
                    line_counts[stream] += chunk.count(b"\n")
                    if len(buffers[stream]) > byte_limits[stream]:
                        self._terminate(process)
                        raise ProcessLimitExceeded(f"{stream} byte")
                    if line_counts[stream] > line_limits[stream]:
                        self._terminate(process)
                        raise ProcessLimitExceeded(f"{stream} line")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._terminate(process)
                raise ProcessTimedOut
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            self._terminate(process)
            raise ProcessTimedOut from exc
        finally:
            selector.close()

        for stream, data in buffers.items():
            total_lines = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
            if total_lines > line_limits[stream]:
                raise ProcessLimitExceeded(f"{stream} line")
        return bytes(buffers["stdout"]), bytes(buffers["stderr"])

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                # Some sandboxes permit terminating the direct child but deny
                # signaling its otherwise isolated process group.
                process.kill()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass

    def _filter_output(self, raw: bytes, allowlist: tuple[str, ...]) -> tuple[str, int]:
        lines = raw.decode("utf-8", errors="replace").splitlines()
        patterns = tuple(re.compile(pattern) for pattern in allowlist)
        visible: list[str] = []
        omitted = 0
        for line in lines:
            if patterns and any(pattern.fullmatch(line) for pattern in patterns):
                visible.append(self._redactor(line))
            else:
                omitted += 1
        return "\n".join(visible), omitted


__all__ = [
    "BoundedHttpResponse",
    "ExecutablePolicy",
    "HttpDiagnostic",
    "HttpLimits",
    "HttpPolicy",
    "HttpTransport",
    "ProcessLimitExceeded",
    "ProcessLimits",
    "ProcessResult",
    "ProcessTimedOut",
    "ResponseLimitExceeded",
    "SubprocessTransport",
    "TransmissionState",
    "TransportError",
    "UnsafeTransportInput",
]
