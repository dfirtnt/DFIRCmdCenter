"""Exact client and standing-hunt scope models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from dfircmdcenter.core.canonical import canonical_digest
from dfircmdcenter.core.time import ensure_utc

from .client import client_id


class ScopeDriftError(RuntimeError):
    """Live label membership differs from the reviewed immutable client set."""


@dataclass(frozen=True, slots=True)
class ResolvedClientScope:
    client_ids: tuple[str, ...]
    resolved_at: datetime
    source_label: str | None = None

    def __post_init__(self) -> None:
        normalized = tuple(sorted({client_id(value) for value in self.client_ids}))
        if not normalized:
            raise ValueError("an immediate operation needs at least one exact client ID")
        object.__setattr__(self, "client_ids", normalized)
        object.__setattr__(self, "resolved_at", ensure_utc(self.resolved_at))

    @property
    def digest(self) -> str:
        return canonical_digest(
            {"client_ids": self.client_ids, "source_label": self.source_label}
        )

    def revalidate(self, current_client_ids: tuple[str, ...]) -> None:
        current = tuple(sorted({client_id(value) for value in current_client_ids}))
        if current != self.client_ids:
            raise ScopeDriftError("resolved label membership changed before submission")


@dataclass(frozen=True, slots=True)
class StandingHuntScope:
    label: str
    current_client_ids: tuple[str, ...]
    includes_future_matching_clients: bool = True

    def __post_init__(self) -> None:
        if not self.label.strip() or not self.includes_future_matching_clients:
            raise ValueError("standing hunts must disclose their future-client scope")
        normalized = tuple(sorted({client_id(value) for value in self.current_client_ids}))
        object.__setattr__(self, "current_client_ids", normalized)

    @property
    def digest(self) -> str:
        return canonical_digest(self)

