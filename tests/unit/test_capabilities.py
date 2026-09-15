from __future__ import annotations

import pytest

from dfircmdcenter.core.capabilities import (
    CapabilityRegistry,
    UnsupportedCapabilityError,
)
from dfircmdcenter.core.records import Capability, Platform


def test_capability_registry_is_default_deny_and_checks_mutability() -> None:
    registry = CapabilityRegistry(
        (
            Capability(
                platform=Platform.SPLUNK,
                name="status",
                supported=True,
                mutating=False,
                constraints={"bounded": True},
            ),
            Capability(
                platform=Platform.SPLUNK,
                name="oneshot",
                supported=False,
                mutating=True,
                constraints={},
                reason="live contract disabled",
            ),
        )
    )

    assert registry.require(Platform.SPLUNK, "status", mutating=False).supported
    with pytest.raises(UnsupportedCapabilityError, match="not registered"):
        registry.require(Platform.ACTION1, "status", mutating=False)
    with pytest.raises(UnsupportedCapabilityError, match="not supported"):
        registry.require(Platform.SPLUNK, "oneshot", mutating=True)
    with pytest.raises(UnsupportedCapabilityError, match="mutability"):
        registry.require(Platform.SPLUNK, "status", mutating=True)
    assert len(registry.for_platform(Platform.SPLUNK)) == 2


def test_capability_registry_rejects_duplicate_registration() -> None:
    capability = Capability(
        platform=Platform.VELOCIRAPTOR,
        name="status",
        supported=True,
        mutating=False,
        constraints={},
    )
    registry = CapabilityRegistry((capability,))
    with pytest.raises(ValueError, match="duplicate"):
        registry.register(capability)
