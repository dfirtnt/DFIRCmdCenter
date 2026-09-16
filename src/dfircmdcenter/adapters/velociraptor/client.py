"""Exact, read-only Velociraptor API query boundary."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from dfircmdcenter.core.transport import (
    ExecutablePolicy,
    ProcessLimits,
    ProcessResult,
    SubprocessTransport,
)

_CLIENT = re.compile(r"^C\.[A-Za-z0-9]+$")
_FLOW = re.compile(r"^F\.[A-Za-z0-9]+(?:\.H)?$")
_HUNT = re.compile(r"^H\.[A-Za-z0-9]+$")

CLIENT_LIMIT = 100
HUNT_LIMIT = 100
FLOW_LIMIT = 500

SELECTED_ARTIFACTS = (
    "Custom.DFIRMedic.StagingEvidence",
    "Custom.Windows.KapeTriage",
    "Custom.DFIRMedic.BaselineTriage",
    "Custom.DFIRMedic.ScamTriage",
    "Custom.DFIRMedic.QuickAssistEvidence",
    "Custom.DFIRMedic.ScreenConnectEvidence",
    "Custom.DFIRMedic.RemoteToolFollowup",
    "Custom.DFIRMedic.MemoryAcquisition",
)

FIXED_QUERIES: Mapping[str, str] = {
    "identity": "server_identity_v1",
    "clients": "client_inventory_v1",
    "hunts": "hunt_inventory_v1",
    "flows": "flow_inventory_v1",
    "artifacts": "artifact_definition_v1",
    "flow_export": "create_flow_download_v1",
    "hunt_export": "create_hunt_download_v1",
}


@dataclass(frozen=True, slots=True)
class ReadOnlyQuery:
    vql: str
    keys: frozenset[str]
    max_rows: int
    require_row: bool = False


_IDENTITY_KEYS = frozenset({"Principal", "OrgId", "OrgName"})
_CLIENT_KEYS = frozenset({"ClientId", "FQDN", "OS", "AgentVersion", "LastSeen", "Labels"})
_HUNT_KEYS = frozenset({"HuntId", "State", "Created", "Started", "Expires", "Artifacts"})
_FLOW_KEYS = frozenset(
    {
        "ClientId",
        "FlowId",
        "State",
        "Created",
        "LastActive",
        "RequestedArtifacts",
        "ArtifactsWithResults",
        "CollectedRows",
        "UploadedFiles",
        "UploadedBytes",
    }
)
_ARTIFACT_KEYS = frozenset({"Name", "Type", "BuiltIn", "Sha256"})
_COUNT_KEYS = frozenset({"Total"})

_FLOW_SOURCE = (
    "foreach(row={ SELECT client_id FROM clients() }, query={ SELECT client_id, "
    "session_id, state, create_time, active_time, request, artifacts_with_results, "
    "total_collected_rows, total_uploaded_files, total_uploaded_bytes "
    "FROM flows(client_id=client_id) })"
)
_ARTIFACT_NAMES = ", ".join(f'"{name}"' for name in SELECTED_ARTIFACTS)

READ_ONLY_QUERIES: Mapping[str, ReadOnlyQuery] = {
    "identity": ReadOnlyQuery(
        vql=(
            "SELECT whoami() AS Principal, org().id AS OrgId, org().name AS OrgName "
            "FROM scope() LIMIT 1"
        ),
        keys=_IDENTITY_KEYS,
        max_rows=1,
        require_row=True,
    ),
    "clients_count": ReadOnlyQuery(
        vql=(
            "LET Records <= SELECT * FROM clients() SELECT len(list=Records) AS Total FROM scope()"
        ),
        keys=_COUNT_KEYS,
        max_rows=1,
        require_row=True,
    ),
    "clients": ReadOnlyQuery(
        vql=(
            "SELECT client_id AS ClientId, os_info.fqdn AS FQDN, os_info.system AS OS, "
            "agent_information.version AS AgentVersion, "
            "timestamp(epoch=last_seen_at) AS LastSeen, labels AS Labels "
            f"FROM clients() ORDER BY ClientId LIMIT {CLIENT_LIMIT + 1}"
        ),
        keys=_CLIENT_KEYS,
        max_rows=CLIENT_LIMIT + 1,
    ),
    "hunts_count": ReadOnlyQuery(
        vql=("LET Records <= SELECT * FROM hunts() SELECT len(list=Records) AS Total FROM scope()"),
        keys=_COUNT_KEYS,
        max_rows=1,
        require_row=True,
    ),
    "hunts": ReadOnlyQuery(
        vql=(
            "SELECT hunt_id AS HuntId, state AS State, timestamp(epoch=create_time) AS Created, "
            "timestamp(epoch=start_time) AS Started, timestamp(epoch=expires) AS Expires, "
            f"artifacts AS Artifacts FROM hunts() ORDER BY HuntId LIMIT {HUNT_LIMIT + 1}"
        ),
        keys=_HUNT_KEYS,
        max_rows=HUNT_LIMIT + 1,
    ),
    "flows_count": ReadOnlyQuery(
        vql=(
            f"LET Records <= SELECT * FROM {_FLOW_SOURCE} "
            "SELECT len(list=Records) AS Total FROM scope()"
        ),
        keys=_COUNT_KEYS,
        max_rows=1,
        require_row=True,
    ),
    "flows": ReadOnlyQuery(
        vql=(
            "SELECT client_id AS ClientId, session_id AS FlowId, state AS State, "
            "timestamp(epoch=create_time) AS Created, "
            "timestamp(epoch=active_time) AS LastActive, request.artifacts AS RequestedArtifacts, "
            "artifacts_with_results AS ArtifactsWithResults, "
            "total_collected_rows AS CollectedRows, total_uploaded_files AS UploadedFiles, "
            f"total_uploaded_bytes AS UploadedBytes FROM {_FLOW_SOURCE} LIMIT {FLOW_LIMIT + 1}"
        ),
        keys=_FLOW_KEYS,
        max_rows=FLOW_LIMIT + 1,
    ),
    "artifacts": ReadOnlyQuery(
        vql=(
            "SELECT name AS Name, type AS Type, built_in AS BuiltIn, "
            'hash(accessor="data", path=raw).SHA256 AS Sha256 '
            f"FROM artifact_definitions(names=[{_ARTIFACT_NAMES}]) ORDER BY Name LIMIT 20"
        ),
        keys=_ARTIFACT_KEYS,
        max_rows=20,
    ),
}


class ProcessRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        environment: Mapping[str, str] | None = None,
        output_paths: Sequence[Path] = (),
    ) -> ProcessResult: ...


class VelociraptorApiError(RuntimeError):
    """A safe API-boundary failure without server output or credentials."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VelociraptorApiError("Velociraptor returned duplicate JSON keys")
        result[key] = value
    return result


def _api_arguments(api_config: Path, query: ReadOnlyQuery) -> tuple[str, ...]:
    return (
        "--api_config",
        str(api_config),
        "query",
        "--nobanner",
        "--nocolor",
        "--timeout",
        "20",
        "--format",
        "jsonl",
        query.vql,
    )


def _parse_jsonl(output: str, *, query: ReadOnlyQuery) -> tuple[Mapping[str, Any], ...]:
    if not output:
        if query.require_row:
            raise VelociraptorApiError("Velociraptor returned no required result row")
        return ()
    lines = output.splitlines()
    if len(lines) > query.max_rows:
        raise VelociraptorApiError("Velociraptor returned too many result rows")
    rows: list[Mapping[str, Any]] = []
    for line in lines:
        try:
            loaded = json.loads(
                line,
                object_pairs_hook=_unique_object,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    VelociraptorApiError(f"non-finite JSON number: {value}")
                ),
            )
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise VelociraptorApiError("Velociraptor returned malformed JSONL") from exc
        if not isinstance(loaded, dict) or frozenset(loaded) != query.keys:
            raise VelociraptorApiError("Velociraptor returned an unexpected result schema")
        rows.append(loaded)
    if query.require_row and len(rows) != 1:
        raise VelociraptorApiError("Velociraptor returned an unexpected row count")
    return tuple(rows)


class VelociraptorApiClient:
    """Run only compiled-in read queries through the official API client boundary."""

    def __init__(
        self,
        *,
        binary: Path,
        api_config: Path,
        runner: ProcessRunner | None = None,
    ) -> None:
        self.binary = binary
        self.api_config = api_config
        if runner is None:
            allowed_arguments = (("version",),) + tuple(
                _api_arguments(api_config, query) for query in READ_ONLY_QUERIES.values()
            )
            runner = SubprocessTransport(
                [
                    ExecutablePolicy(
                        executable=binary,
                        allowed_argument_prefixes=allowed_arguments,
                        stdout_line_allowlist=(
                            r"^(?:name|version|commit|build_time|ci_build_url|compiler|system|architecture):.*$",
                            r"^\{.*\}$",
                        ),
                        stderr_line_allowlist=(),
                        require_exact_arguments=True,
                    )
                ],
                limits=ProcessLimits(
                    timeout_seconds=30,
                    max_stdout_bytes=2 * 1024 * 1024,
                    max_stderr_bytes=64 * 1024,
                    max_stdout_lines=600,
                    max_stderr_lines=100,
                ),
            )
        self._runner = runner

    def version(self) -> Mapping[str, str]:
        result = self._runner.run([str(self.binary), "version"])
        if (
            result.returncode != 0
            or result.omitted_stdout_lines
            or result.omitted_stderr_lines
            or not result.stdout
        ):
            raise VelociraptorApiError("Velociraptor binary identity command failed")
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            key, separator, value = line.partition(":")
            if not separator or key in values:
                raise VelociraptorApiError("Velociraptor returned malformed version output")
            values[key] = value.strip().strip('"')
        required = {
            "name",
            "version",
            "commit",
            "build_time",
            "compiler",
            "system",
            "architecture",
        }
        if not required.issubset(values):
            raise VelociraptorApiError("Velociraptor version output is incomplete")
        return values

    def query(self, name: str) -> tuple[Mapping[str, Any], ...]:
        try:
            query = READ_ONLY_QUERIES[name]
        except KeyError as exc:
            raise ValueError("query is not a configured fixed read template") from exc
        argv = [str(self.binary), *_api_arguments(self.api_config, query)]
        result = self._runner.run(argv)
        if result.returncode != 0 or result.omitted_stdout_lines or result.omitted_stderr_lines:
            raise VelociraptorApiError("Velociraptor API query failed safely")
        return _parse_jsonl(result.stdout, query=query)


def client_id(value: str) -> str:
    if not _CLIENT.fullmatch(value):
        raise ValueError("invalid Velociraptor client ID")
    return value


def flow_id(value: str) -> str:
    if not _FLOW.fullmatch(value):
        raise ValueError("invalid Velociraptor flow ID")
    return value


def hunt_id(value: str) -> str:
    if not _HUNT.fullmatch(value):
        raise ValueError("invalid Velociraptor hunt ID")
    return value


def fixed_query(name: str) -> str:
    try:
        return FIXED_QUERIES[name]
    except KeyError as exc:
        raise ValueError("query is not a configured fixed template") from exc
