"""Fixed Velociraptor API query identifiers; arbitrary VQL is prohibited."""

from __future__ import annotations

import re
from collections.abc import Mapping

_CLIENT = re.compile(r"^C\.[A-Za-z0-9]+$")
_FLOW = re.compile(r"^F\.[A-Za-z0-9]+$")
_HUNT = re.compile(r"^H\.[A-Za-z0-9]+$")

FIXED_QUERIES: Mapping[str, str] = {
    "identity": "server_identity_v1",
    "clients": "client_inventory_v1",
    "hunts": "hunt_inventory_v1",
    "flows": "flow_inventory_v1",
    "artifacts": "artifact_definition_v1",
    "flow_export": "create_flow_download_v1",
    "hunt_export": "create_hunt_download_v1",
}


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

