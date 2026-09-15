"""Provenance record for supported exports and datastore-derived outputs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from dfircmdcenter.core.canonical import canonical_digest
from dfircmdcenter.core.time import ensure_utc


@dataclass(frozen=True, slots=True)
class ExportProvenance:
    server_identity: str
    source_kind: str
    source_id: str
    client_id: str | None
    artifact_names: tuple[str, ...]
    settings_digest: str
    integrity_status: str
    output_sha256: str
    output_bytes: int
    completed_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "completed_at", ensure_utc(self.completed_at))
        if self.output_bytes < 0 or len(self.output_sha256) != 64:
            raise ValueError("provenance requires a valid output size and hash")

    @property
    def digest(self) -> str:
        return canonical_digest(self)

