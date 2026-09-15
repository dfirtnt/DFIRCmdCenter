from __future__ import annotations

import re
import shutil
from dataclasses import asdict
from pathlib import Path

import httpx
import pytest

from dfircmdcenter.core.transport import (
    ExecutablePolicy,
    HttpDiagnostic,
    HttpLimits,
    HttpPolicy,
    HttpTransport,
    ProcessLimitExceeded,
    ProcessLimits,
    ProcessTimedOut,
    ResponseLimitExceeded,
    SubprocessTransport,
    TransmissionState,
    TransportError,
    UnsafeTransportInput,
)


def _command(name: str) -> Path:
    resolved = shutil.which(name)
    if resolved is None:
        pytest.skip(f"required test command is unavailable: {name}")
    return Path(resolved).resolve()


def _http_policy(**changes: object) -> HttpPolicy:
    values: dict[str, object] = {
        "base_url": "https://api.vendor.example/v1",
        "allowed_origins": frozenset({"https://api.vendor.example"}),
        "allowed_query_keys": frozenset({"limit", "offset"}),
    }
    values.update(changes)
    return HttpPolicy(**values)  # type: ignore[arg-type]


def test_http_rejects_unallowlisted_origin_and_unsafe_paths() -> None:
    with pytest.raises(UnsafeTransportInput, match="origin allowlist"):
        HttpTransport(
            _http_policy(base_url="https://evil.example/v1"),
            client=httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))),
        )

    transport = HttpTransport(
        _http_policy(),
        client=httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))),
    )
    with pytest.raises(UnsafeTransportInput, match="absolute-path"):
        transport.request("GET", "https://evil.example/collect")
    with pytest.raises(UnsafeTransportInput, match="traversal"):
        transport.request("GET", "/clients/%2e%2e/secrets")
    with pytest.raises(UnsafeTransportInput, match="query field"):
        transport.request("GET", "/clients", query={"next_url": "https://evil.example"})
    with pytest.raises(UnsafeTransportInput, match="traversal"):
        HttpTransport(
            _http_policy(base_url="https://api.vendor.example/%2e%2e/private"),
            client=httpx.Client(
                transport=httpx.MockTransport(lambda request: httpx.Response(200))
            ),
        )


def test_http_retries_read_only_with_retry_after_but_never_writes() -> None:
    calls: list[str] = []
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "GET" and calls.count("GET") == 1:
            return httpx.Response(429, headers={"Retry-After": "0.01"})
        return httpx.Response(503 if request.method == "POST" else 200, content=b"ok")

    transport = HttpTransport(
        _http_policy(),
        limits=HttpLimits(max_attempts=3, overall_timeout=2, max_retry_delay=1),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep=sleeps.append,
        jitter=lambda low, high: high,
    )

    assert transport.request("GET", "/status").status_code == 200
    assert calls == ["GET", "GET"]
    assert sleeps == [0.01]

    assert transport.request("POST", "/changes", json={"enabled": True}).status_code == 503
    assert calls == ["GET", "GET", "POST"]


def test_http_write_timeout_is_unknown_and_is_not_retried() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("secret response text", request=request)

    transport = HttpTransport(
        _http_policy(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(TransportError) as raised:
        transport.request("POST", "/changes", json={"token": "do-not-log"})

    assert raised.value.transmission is TransmissionState.UNKNOWN
    assert "secret" not in str(raised.value)
    assert calls == 1


def test_http_response_is_bounded_before_it_is_returned() -> None:
    transport = HttpTransport(
        _http_policy(),
        limits=HttpLimits(max_response_bytes=4),
        client=httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"12345"))
        ),
    )
    with pytest.raises(ResponseLimitExceeded):
        transport.request("GET", "/status")


def test_http_diagnostics_never_contain_headers_query_values_or_token_response() -> None:
    diagnostics: list[HttpDiagnostic] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer top-secret"
        return httpx.Response(200, json={"access_token": "response-secret"})

    transport = HttpTransport(
        _http_policy(),
        default_headers={"Authorization": "Bearer top-secret"},
        diagnostic_hook=diagnostics.append,
        redactor=lambda value: value.replace("oauth2", "[REDACTED]"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    response = transport.request(
        "POST",
        "/oauth2/token",
        query={"limit": "query-secret"},
        content=b"client_secret=body-secret",
    )

    assert b"response-secret" in response.body
    rendered = repr([asdict(item) for item in diagnostics])
    for secret in ("top-secret", "query-secret", "body-secret", "response-secret"):
        assert secret not in rendered
    assert all(item.sensitive_response for item in diagnostics)
    assert all("oauth2" not in item.path for item in diagnostics)


def test_subprocess_requires_an_absolute_allowlisted_executable_and_operation() -> None:
    printf = _command("printf")
    transport = SubprocessTransport(
        [
            ExecutablePolicy(
                executable=printf,
                allowed_argument_prefixes=(("%s",),),
                stdout_line_allowlist=(r"safe",),
            )
        ]
    )

    with pytest.raises(UnsafeTransportInput, match="absolute path"):
        transport.run(["printf", "%s", "safe"])
    with pytest.raises(UnsafeTransportInput, match="operation"):
        transport.run([str(printf), "%d", "1"])


def test_subprocess_uses_no_shell_and_filters_then_redacts_output(tmp_path: Path) -> None:
    printf = _command("printf")
    marker = tmp_path / "must-not-exist"
    payload = f"$(touch {marker})"
    transport = SubprocessTransport(
        [
            ExecutablePolicy(
                executable=printf,
                allowed_argument_prefixes=(("%s",),),
                stdout_line_allowlist=(re.escape(payload),),
            )
        ],
        redactor=lambda line: line.replace("touch", "[REDACTED]"),
    )

    result = transport.run([str(printf), "%s", payload])

    assert not marker.exists()
    assert "touch" not in result.stdout
    assert "[REDACTED]" in result.stdout


def test_subprocess_environment_is_clean_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    env_command = _command("env")
    monkeypatch.setenv("DFIR_SHOULD_NOT_LEAK", "ambient-secret")
    transport = SubprocessTransport(
        [
            ExecutablePolicy(
                executable=env_command,
                allowed_argument_prefixes=(("--",),),
                allowed_environment=frozenset({"DFIR_ALLOWED"}),
                stdout_line_allowlist=(r"(?:PATH|LANG|LC_ALL|TZ|DFIR_ALLOWED)=.*",),
            )
        ]
    )

    result = transport.run(
        [str(env_command), "--"], environment={"DFIR_ALLOWED": "fixture"}
    )

    assert "DFIR_ALLOWED=fixture" in result.stdout
    assert "DFIR_SHOULD_NOT_LEAK" not in result.stdout
    assert "ambient-secret" not in result.stdout
    with pytest.raises(UnsafeTransportInput, match="not allowlisted"):
        transport.run([str(env_command), "--"], environment={"API_TOKEN": "secret"})


def test_subprocess_enforces_output_runtime_and_path_bounds(tmp_path: Path) -> None:
    printf = _command("printf")
    tiny = SubprocessTransport(
        [
            ExecutablePolicy(
                executable=printf,
                allowed_argument_prefixes=(("%s",),),
                stdout_line_allowlist=(r".*",),
            )
        ],
        limits=ProcessLimits(max_stdout_bytes=4),
    )
    with pytest.raises(ProcessLimitExceeded, match="stdout byte"):
        tiny.run([str(printf), "%s", "12345"])

    sleep = _command("sleep")
    timed = SubprocessTransport(
        [ExecutablePolicy(executable=sleep, allowed_argument_prefixes=(("1",),))],
        limits=ProcessLimits(timeout_seconds=0.01),
    )
    with pytest.raises(ProcessTimedOut):
        timed.run([str(sleep), "1"])

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    path_checked = SubprocessTransport(
        [
            ExecutablePolicy(
                executable=printf,
                allowed_argument_prefixes=(("%s",),),
                allowed_output_roots=(allowed,),
            )
        ]
    )
    with pytest.raises(UnsafeTransportInput, match="output path"):
        path_checked.run(
            [str(printf), "%s", "safe"], output_paths=[tmp_path / "outside.txt"]
        )
