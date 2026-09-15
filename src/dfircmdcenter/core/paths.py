"""Filesystem containment checks for untrusted and derived paths."""

from __future__ import annotations

from os import PathLike
from pathlib import Path

PathInput = str | PathLike[str]


class PathContainmentError(ValueError):
    """A candidate path escaped its root or crossed a forbidden symlink."""


def _reject_symlink_components(root: Path, relative: Path) -> None:
    if root.is_symlink():
        raise PathContainmentError(f"containment root is a symlink: {root}")
    current = root
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise PathContainmentError(f"path contains a symlink component: {current}")


def resolve_within(
    root: PathInput,
    candidate: PathInput,
    *,
    must_exist: bool = False,
    allow_symlinks: bool = False,
) -> Path:
    """Resolve *candidate* beneath *root* or fail closed.

    Absolute candidates are accepted only when already contained by the root.
    Traversal components are rejected even when they would normalize back into
    the root, keeping decoded archive paths auditable and unambiguous.
    """

    root_path = Path(root)
    candidate_path = Path(candidate)
    if ".." in candidate_path.parts:
        raise PathContainmentError(f"parent traversal is forbidden: {candidate_path}")

    root_resolved = root_path.resolve(strict=True)
    unresolved = candidate_path if candidate_path.is_absolute() else root_resolved / candidate_path

    try:
        lexical_relative = unresolved.relative_to(root_resolved)
    except ValueError as exc:
        raise PathContainmentError(f"path is outside containment root: {candidate_path}") from exc

    if not allow_symlinks:
        _reject_symlink_components(root_path, lexical_relative)

    resolved = unresolved.resolve(strict=must_exist)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        message = f"path resolves outside containment root: {candidate_path}"
        raise PathContainmentError(message) from exc
    if must_exist and not resolved.exists():
        raise FileNotFoundError(resolved)
    return resolved


def safe_join(root: PathInput, *parts: str, must_exist: bool = False) -> Path:
    return resolve_within(root, Path(*parts), must_exist=must_exist)
