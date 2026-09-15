"""Static configuration and duplicate-safe policy loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from yaml.constructor import ConstructorError  # type: ignore[import-untyped]

PROJECT_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = PROJECT_ROOT / "policies"
POLICY_FILES = {
    "approval-gates": POLICY_DIR / "approval-gates.yaml",
    "splunk-ingest": POLICY_DIR / "splunk-ingest.yaml",
}


class DuplicateKeySafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader that rejects duplicate keys at every mapping level."""


def _construct_unique_mapping(
    loader: DuplicateKeySafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key ({key!r})",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


DuplicateKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_yaml(path: Path) -> Any:
    """Load trusted repository YAML while rejecting duplicate keys."""

    with path.open("r", encoding="utf-8") as stream:
        return yaml.load(stream, Loader=DuplicateKeySafeLoader)


def load_policy(name: str) -> dict[str, Any]:
    """Load one allowlisted governance policy by stable name."""

    try:
        policy_path = POLICY_FILES[name]
    except KeyError as exc:
        raise ValueError(f"unknown policy: {name}") from exc

    policy = load_yaml(policy_path)
    if not isinstance(policy, dict):
        raise ValueError(f"policy must be a mapping: {name}")
    return policy
