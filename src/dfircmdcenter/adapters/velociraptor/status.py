"""Read-only local Velociraptor status with no config-file parsing."""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

from dfircmdcenter.adapters.status import StatusLevel, StatusReport, fixture_report
from dfircmdcenter.core.records import Platform
from dfircmdcenter.core.transport import ExecutablePolicy, ProcessLimits, SubprocessTransport

VELOCIRAPTOR_BINARY = Path("/Users/starlord/.local/bin/velociraptor")
DFIRMEDIC_ROOT = Path("/Users/starlord/Code/Active/DFIRMedic")
PINNED_HELPERS = (
    DFIRMEDIC_ROOT / "tools" / "check-collection-logs.py",
    DFIRMEDIC_ROOT / "tools" / "extract-evidence.py",
)

_SECTIONS = ("identity", "clients", "hunts", "flows", "artifacts", "helper_hashes")
_PAGINATED = ("clients", "hunts", "flows", "artifacts")


def fixture_status(path: Path, *, captured_at: datetime) -> StatusReport:
    return fixture_report(
        platform=Platform.VELOCIRAPTOR,
        path=path,
        captured_at=captured_at,
        paginated_sections=_PAGINATED,
        required_sections=_SECTIONS,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def local_status(*, captured_at: datetime) -> StatusReport:
    state: dict[str, object] = {
        "identity": "unknown",
        "clients": "unknown",
        "hunts": "unknown",
        "flows": "unknown",
        "artifacts": "unknown",
        "helper_hashes": {},
    }
    unavailable: list[str] = []
    if VELOCIRAPTOR_BINARY.is_file():
        transport = SubprocessTransport(
            [
                ExecutablePolicy(
                    executable=VELOCIRAPTOR_BINARY,
                    allowed_argument_prefixes=(("version",),),
                    stdout_line_allowlist=(
                        r"^(?:name|version|commit|build_time|ci_build_url|compiler|system|architecture):.*$",
                    ),
                    stderr_line_allowlist=(r"^$",),
                )
            ],
            limits=ProcessLimits(timeout_seconds=10, max_stdout_bytes=16_384),
        )
        result = transport.run([str(VELOCIRAPTOR_BINARY), "version"])
        if result.returncode == 0 and result.stdout:
            state["identity"] = result.stdout.splitlines()
        else:
            unavailable.append("Velociraptor binary identity command failed")
    else:
        unavailable.append("Velociraptor binary is missing at the configured path")

    helper_hashes: dict[str, str] = {}
    for helper in PINNED_HELPERS:
        if helper.is_file():
            helper_hashes[helper.name] = _sha256(helper)
        else:
            unavailable.append(f"required DFIRMedic helper is missing: {helper.name}")
    state["helper_hashes"] = helper_hashes
    unavailable.extend(
        (
            "API client inventory unavailable until fixed VQL templates are enabled",
            "hunt, flow, and artifact inventory unavailable without the API boundary",
        )
    )
    return StatusReport(
        platform=Platform.VELOCIRAPTOR,
        level=StatusLevel.UNKNOWN,
        captured_at=captured_at,
        source="live:local-velociraptor",
        state=state,
        unavailable=tuple(unavailable),
    )

