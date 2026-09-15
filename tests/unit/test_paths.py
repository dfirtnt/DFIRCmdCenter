from __future__ import annotations

from pathlib import Path

import pytest

from dfircmdcenter.core.paths import PathContainmentError, resolve_within


def test_resolves_relative_path_within_root(tmp_path: Path) -> None:
    root = tmp_path / "exports"
    root.mkdir()

    assert resolve_within(root, "flow/results.json") == root / "flow/results.json"


def test_rejects_relative_and_absolute_path_escape(tmp_path: Path) -> None:
    root = tmp_path / "exports"
    root.mkdir()

    with pytest.raises(PathContainmentError):
        resolve_within(root, "../outside.txt")
    with pytest.raises(PathContainmentError):
        resolve_within(root, tmp_path / "outside.txt")


def test_rejects_symlink_component(tmp_path: Path) -> None:
    root = tmp_path / "exports"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)

    with pytest.raises(PathContainmentError, match="symlink"):
        resolve_within(root, "linked/result.json")


def test_must_exist_is_enforced(tmp_path: Path) -> None:
    root = tmp_path / "exports"
    root.mkdir()

    with pytest.raises(FileNotFoundError):
        resolve_within(root, "missing.json", must_exist=True)

