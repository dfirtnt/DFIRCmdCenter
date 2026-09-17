"""Bounded live Velociraptor status through fixed read-only API queries."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from dfircmdcenter.adapters.status import (
    FixtureError,
    StatusLevel,
    StatusReport,
    fixture_report,
    sanitize_untrusted,
)
from dfircmdcenter.adapters.velociraptor.client import (
    CLIENT_LIMIT,
    FLOW_LIMIT,
    HUNT_LIMIT,
    SELECTED_ARTIFACTS,
    VelociraptorApiClient,
    VelociraptorApiError,
    client_id,
    flow_id,
    hunt_id,
)
from dfircmdcenter.core.records import Platform
from dfircmdcenter.core.transport import TransportError

VELOCIRAPTOR_BINARY = Path("/Users/starlord/.local/bin/velociraptor")
VELOCIRAPTOR_API_CONFIG = Path("/Users/starlord/.dfirmedic/velociraptor/api.config.yaml")
VELOCIRAPTOR_API_ENDPOINT = "127.0.0.1:8501"
DFIRMEDIC_ROOT = Path("/Users/starlord/Code/Active/DFIRMedic")

_SECTIONS = ("identity", "clients", "hunts", "flows", "artifacts", "helper_hashes")
_PAGINATED = ("clients", "hunts", "flows", "artifacts")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class StatusReader(Protocol):
    def version(self) -> Mapping[str, str]: ...

    def query(self, name: str) -> tuple[Mapping[str, Any], ...]: ...


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


def _text(
    row: Mapping[str, Any],
    key: str,
    *,
    allow_none: bool = False,
    max_chars: int = 1024,
) -> str | None:
    value = row.get(key)
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not value or len(value) > max_chars:
        raise VelociraptorApiError(f"Velociraptor {key} value is malformed")
    return value


def _string_list(row: Mapping[str, Any], key: str, *, max_items: int = 128) -> list[str]:
    value = row.get(key)
    if not isinstance(value, list) or len(value) > max_items:
        raise VelociraptorApiError(f"Velociraptor {key} list is malformed")
    if any(not isinstance(item, str) or len(item) > 1024 for item in value):
        raise VelociraptorApiError(f"Velociraptor {key} item is malformed")
    return list(value)


def _nonnegative_int(row: Mapping[str, Any], key: str) -> int:
    value = row.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise VelociraptorApiError(f"Velociraptor {key} value is malformed")
    return value


def _total(rows: tuple[Mapping[str, Any], ...]) -> int:
    if len(rows) != 1:
        raise VelociraptorApiError("Velociraptor count query returned an unexpected row count")
    return _nonnegative_int(rows[0], "Total")


def _normalize_client(row: Mapping[str, Any]) -> Mapping[str, Any]:
    identifier = _text(row, "ClientId", max_chars=128)
    assert isinstance(identifier, str)
    client_id(identifier)
    return {
        "client_id": identifier,
        "fqdn": _text(row, "FQDN", allow_none=True),
        "os": _text(row, "OS", allow_none=True, max_chars=128),
        "agent_version": _text(row, "AgentVersion", allow_none=True, max_chars=128),
        "last_seen_at": _text(row, "LastSeen", allow_none=True, max_chars=128),
        "labels": _string_list(row, "Labels"),
    }


def _normalize_hunt(row: Mapping[str, Any]) -> Mapping[str, Any]:
    identifier = _text(row, "HuntId", max_chars=128)
    assert isinstance(identifier, str)
    hunt_id(identifier)
    return {
        "hunt_id": identifier,
        "state": _text(row, "State", max_chars=128),
        "created_at": _text(row, "Created", allow_none=True, max_chars=128),
        "started_at": _text(row, "Started", allow_none=True, max_chars=128),
        "expires_at": _text(row, "Expires", allow_none=True, max_chars=128),
        "artifacts": _string_list(row, "Artifacts"),
    }


def _normalize_flow(row: Mapping[str, Any]) -> Mapping[str, Any]:
    client = _text(row, "ClientId", max_chars=128)
    flow = _text(row, "FlowId", max_chars=128)
    assert isinstance(client, str)
    assert isinstance(flow, str)
    client_id(client)
    flow_id(flow)
    return {
        "client_id": client,
        "flow_id": flow,
        "state": _text(row, "State", max_chars=128),
        "created_at": _text(row, "Created", allow_none=True, max_chars=128),
        "last_active_at": _text(row, "LastActive", allow_none=True, max_chars=128),
        "requested_artifacts": _string_list(row, "RequestedArtifacts"),
        "result_artifacts": _string_list(row, "ArtifactsWithResults"),
        "collected_rows": _nonnegative_int(row, "CollectedRows"),
        "uploaded_files": _nonnegative_int(row, "UploadedFiles"),
        "uploaded_bytes": _nonnegative_int(row, "UploadedBytes"),
    }


def _bounded_inventory(
    reader: StatusReader,
    *,
    name: str,
    limit: int,
    normalize: Callable[[Mapping[str, Any]], Mapping[str, Any]],
) -> tuple[list[Mapping[str, Any]], int, str | None]:
    before = _total(reader.query(f"{name}_count"))
    raw_items = reader.query(name)
    after = _total(reader.query(f"{name}_count"))
    items = [normalize(item) for item in raw_items[:limit]]
    if before != after:
        return items, after, f"{name}: total changed during inventory"
    if after > limit:
        return items, after, f"{name}: incomplete pagination ({after} exceeds limit {limit})"
    if len(raw_items) != after:
        return items, after, f"{name}: incomplete pagination"
    return items, after, None


def _artifact_paths(root: Path) -> Mapping[str, Path]:
    artifacts = root / "server" / "artifacts"
    return {name: artifacts / f"{name}.yaml" for name in SELECTED_ARTIFACTS}


def _artifact_inventory(
    reader: StatusReader,
    *,
    dfirmedic_root: Path,
) -> tuple[list[Mapping[str, Any]], bool]:
    server_rows: dict[str, Mapping[str, Any]] = {}
    for row in reader.query("artifacts"):
        name = _text(row, "Name", max_chars=256)
        artifact_type = _text(row, "Type", max_chars=64)
        sha256 = _text(row, "Sha256", max_chars=64)
        built_in = row.get("BuiltIn")
        if not isinstance(name, str) or name not in SELECTED_ARTIFACTS:
            raise VelociraptorApiError("Velociraptor returned an unrequested artifact")
        if name in server_rows:
            raise VelociraptorApiError("Velociraptor returned a duplicate artifact")
        if artifact_type != "client" or built_in is not False:
            raise VelociraptorApiError("Velociraptor artifact metadata is unexpected")
        if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
            raise VelociraptorApiError("Velociraptor artifact hash is malformed")
        server_rows[name] = {"sha256": sha256, "type": artifact_type, "built_in": built_in}

    drift = False
    inventory: list[Mapping[str, Any]] = []
    for name, path in _artifact_paths(dfirmedic_root).items():
        local_sha256 = _sha256(path) if path.is_file() else None
        server = server_rows.get(name)
        server_sha256 = None if server is None else server["sha256"]
        if server is None:
            status = "missing_on_server"
        elif local_sha256 is None:
            status = "missing_locally"
        elif server_sha256 != local_sha256:
            status = "drift"
        else:
            status = "match"
        drift = drift or status != "match"
        inventory.append(
            {
                "name": name,
                "status": status,
                "server_sha256": server_sha256,
                "local_sha256": local_sha256,
            }
        )
    return inventory, drift


def _helper_hashes(root: Path, unavailable: list[str]) -> Mapping[str, str]:
    hashes: dict[str, str] = {}
    for name in ("check-collection-logs.py", "extract-evidence.py"):
        helper = root / "tools" / name
        if helper.is_file():
            hashes[name] = _sha256(helper)
        else:
            unavailable.append(f"required DFIRMedic helper is missing: {name}")
    return hashes


def local_status(
    *,
    captured_at: datetime,
    binary: Path = VELOCIRAPTOR_BINARY,
    api_config: Path = VELOCIRAPTOR_API_CONFIG,
    dfirmedic_root: Path = DFIRMEDIC_ROOT,
    reader: StatusReader | None = None,
) -> StatusReport:
    state: dict[str, Any] = {
        "identity": "unknown",
        "clients": "unknown",
        "hunts": "unknown",
        "flows": "unknown",
        "artifacts": "unknown",
        "helper_hashes": {},
        "inventory_counts": {},
    }
    unavailable: list[str] = []
    drift = False

    if reader is None:
        if not binary.is_file():
            unavailable.append("Velociraptor binary is missing at the configured path")
        elif not api_config.is_file():
            unavailable.append("Velociraptor API configuration is missing at the external path")
        else:
            try:
                reader = VelociraptorApiClient(binary=binary, api_config=api_config)
            except (OSError, ValueError, TransportError):
                unavailable.append("Velociraptor API client could not be initialized safely")

    if reader is not None:
        try:
            version = dict(reader.version())
            api_identity = reader.query("identity")
            if len(api_identity) != 1:
                raise VelociraptorApiError("Velociraptor identity query returned wrong row count")
            identity_row = api_identity[0]
            state["identity"] = {
                "binary": version,
                "api": {
                    "principal": _text(identity_row, "Principal", max_chars=256),
                    "org_id": _text(identity_row, "OrgId", max_chars=256),
                    "org_name": _text(identity_row, "OrgName", max_chars=256),
                    "endpoint": VELOCIRAPTOR_API_ENDPOINT,
                    "transport": "grpc_mtls",
                },
            }
        except (VelociraptorApiError, TransportError, ValueError):
            unavailable.append("identity: live read failed or returned an invalid response")

        for name, limit, normalize in (
            ("clients", CLIENT_LIMIT, _normalize_client),
            ("hunts", HUNT_LIMIT, _normalize_hunt),
            ("flows", FLOW_LIMIT, _normalize_flow),
        ):
            try:
                items, total, issue = _bounded_inventory(
                    reader,
                    name=name,
                    limit=limit,
                    normalize=normalize,
                )
                state[name] = items
                state["inventory_counts"][name] = total
                if issue:
                    unavailable.append(issue)
            except (VelociraptorApiError, TransportError, ValueError):
                unavailable.append(f"{name}: live read failed or returned an invalid response")

        try:
            artifacts, artifact_drift = _artifact_inventory(
                reader,
                dfirmedic_root=dfirmedic_root,
            )
            state["artifacts"] = artifacts
            state["inventory_counts"]["artifacts"] = len(artifacts)
            drift = drift or artifact_drift
        except (OSError, VelociraptorApiError, TransportError, ValueError):
            unavailable.append("artifacts: live read failed or returned an invalid response")

    try:
        state["helper_hashes"] = _helper_hashes(dfirmedic_root, unavailable)
    except OSError:
        state["helper_hashes"] = {}
        unavailable.append("DFIRMedic helper hashes could not be read safely")
    try:
        sanitized, findings = sanitize_untrusted(state, source="live:local-velociraptor")
    except FixtureError:
        sanitized = {
            "identity": "unknown",
            "clients": "unknown",
            "hunts": "unknown",
            "flows": "unknown",
            "artifacts": "unknown",
            "helper_hashes": {},
            "inventory_counts": {},
        }
        findings = ()
        unavailable.append("live inventory contained an unsupported value")
    assert isinstance(sanitized, dict)

    if unavailable:
        level = StatusLevel.UNKNOWN
    elif drift or findings:
        level = StatusLevel.DEGRADED
    else:
        level = StatusLevel.OK
    return StatusReport(
        platform=Platform.VELOCIRAPTOR,
        level=level,
        captured_at=captured_at,
        source="live:local-velociraptor-api",
        state=sanitized,
        unavailable=tuple(unavailable),
        findings=findings,
    )
