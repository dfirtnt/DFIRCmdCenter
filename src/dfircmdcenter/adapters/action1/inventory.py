"""Exact Action1 package and cross-platform endpoint identity records."""

from __future__ import annotations

import re
from dataclasses import dataclass

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class DeploymentPackage:
    package_id: str
    version: str
    upstream_sha256: str
    repackaged_sha256: str
    client_configuration_sha256: str
    provenance: str

    def __post_init__(self) -> None:
        for value in (
            self.upstream_sha256,
            self.repackaged_sha256,
            self.client_configuration_sha256,
        ):
            if not _SHA256.fullmatch(value):
                raise ValueError("deployment package hashes must be lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class EndpointIdentity:
    action1_endpoint_id: str
    velociraptor_client_id: str
    action1_hostname: str
    velociraptor_hostname: str
    action1_machine_id: str | None = None
    velociraptor_machine_id: str | None = None
    action1_serial: str | None = None
    velociraptor_serial: str | None = None

    def verified(self) -> bool:
        strong_matches = (
            self.action1_machine_id is not None
            and self.velociraptor_machine_id is not None
            and self.action1_machine_id == self.velociraptor_machine_id,
            self.action1_serial is not None
            and self.velociraptor_serial is not None
            and self.action1_serial == self.velociraptor_serial,
        )
        return any(strong_matches)

    def require_verified(self) -> None:
        if not self.verified():
            raise ValueError("hostname alone is insufficient endpoint identity correlation")

