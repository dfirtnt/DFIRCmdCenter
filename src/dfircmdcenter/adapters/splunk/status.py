"""Read-only local Splunk Free status without broad config or process dumps."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from dfircmdcenter.adapters.status import StatusLevel, StatusReport, fixture_report
from dfircmdcenter.core.records import Platform
from dfircmdcenter.core.transport import ExecutablePolicy, ProcessLimits, SubprocessTransport

SPLUNK_BINARY = Path("/Users/starlord/splunk/bin/splunk")
_SECTIONS = (
    "identity",
    "binding",
    "indexes",
    "inputs",
    "license",
    "daily_usage",
    "reset_boundary",
)
_PAGINATED = ("indexes", "inputs")


def fixture_status(path: Path, *, captured_at: datetime) -> StatusReport:
    return fixture_report(
        platform=Platform.SPLUNK,
        path=path,
        captured_at=captured_at,
        paginated_sections=_PAGINATED,
        required_sections=_SECTIONS,
    )


def local_status(*, captured_at: datetime) -> StatusReport:
    state: dict[str, object] = {
        "identity": "unknown",
        "binding": "unknown",
        "indexes": "unknown",
        "inputs": "unknown",
        "license": "unknown",
        "daily_usage": "unknown",
        "reset_boundary": "unknown",
    }
    unavailable: list[str] = []
    if SPLUNK_BINARY.is_file():
        transport = SubprocessTransport(
            [
                ExecutablePolicy(
                    executable=SPLUNK_BINARY,
                    allowed_argument_prefixes=(("version",),),
                    stdout_line_allowlist=(r"^Splunk(?: Enterprise)? [0-9][^\r\n]*$",),
                    stderr_line_allowlist=(r"^$",),
                )
            ],
            limits=ProcessLimits(timeout_seconds=10, max_stdout_bytes=4096),
        )
        result = transport.run([str(SPLUNK_BINARY), "version"])
        if result.returncode == 0 and result.stdout:
            state["identity"] = result.stdout.strip()
        else:
            unavailable.append("Splunk version command failed")
    else:
        unavailable.append("Splunk binary is missing at the configured path")
    unavailable.extend(
        (
            "safe binding summary unavailable until credentialed local REST is configured",
            "dfir index and monitor inventory unavailable until credentialed local REST "
            "is configured",
            "license usage and reset boundary unavailable; ingestion must remain blocked",
        )
    )
    return StatusReport(
        platform=Platform.SPLUNK,
        level=StatusLevel.UNKNOWN,
        captured_at=captured_at,
        source="live:local-splunk",
        state=state,
        unavailable=tuple(unavailable),
    )
