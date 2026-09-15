"""Explicit adapter capability registry with a default-deny posture."""

from __future__ import annotations

from collections.abc import Iterable

from .records import Capability, Platform


class UnsupportedCapabilityError(RuntimeError):
    """The requested platform capability is absent, unsupported, or mismatched."""


class CapabilityRegistry:
    def __init__(self, capabilities: Iterable[Capability] = ()) -> None:
        self._capabilities: dict[tuple[Platform, str], Capability] = {}
        for capability in capabilities:
            self.register(capability)

    def register(self, capability: Capability) -> None:
        key = (capability.platform, capability.name)
        if key in self._capabilities:
            raise ValueError(f"duplicate capability: {capability.platform.value}/{capability.name}")
        self._capabilities[key] = capability

    def get(self, platform: Platform, name: str) -> Capability | None:
        return self._capabilities.get((platform, name))

    def require(self, platform: Platform, name: str, *, mutating: bool) -> Capability:
        capability = self.get(platform, name)
        if capability is None:
            raise UnsupportedCapabilityError(
                f"capability is not registered: {platform.value}/{name}"
            )
        if not capability.supported:
            reason = f": {capability.reason}" if capability.reason else ""
            raise UnsupportedCapabilityError(f"capability is not supported{reason}")
        if capability.mutating is not mutating:
            raise UnsupportedCapabilityError("capability mutability does not match the operation")
        return capability

    def for_platform(self, platform: Platform) -> tuple[Capability, ...]:
        return tuple(
            capability
            for (candidate, _), capability in self._capabilities.items()
            if candidate is platform
        )
