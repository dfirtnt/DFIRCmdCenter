"""Pinned DFIRMedic helper contracts and datastore-extraction containment."""

from __future__ import annotations

import hashlib
import os
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from dfircmdcenter.core.canonical import canonical_digest
from dfircmdcenter.core.paths import PathContainmentError

from .client import client_id, flow_id

DFIRMEDIC_ROOT = Path("/Users/starlord/Code/Active/DFIRMedic")
CHECK_HELPER = DFIRMEDIC_ROOT / "tools" / "check-collection-logs.py"
EXTRACT_HELPER = DFIRMEDIC_ROOT / "tools" / "extract-evidence.py"
DATASTORE_ROOT = Path("/Users/starlord/.dfirmedic/velociraptor/datastore")


class ExtractionPreflightError(RuntimeError):
    """Datastore-derived extraction cannot be proven contained and deterministic."""


@dataclass(frozen=True, slots=True)
class HelperPin:
    path: Path
    sha256: str

    @classmethod
    def capture(cls, path: Path) -> HelperPin:
        return cls(path.resolve(strict=True), _sha256(path))

    def verify(self) -> None:
        if self.path.resolve(strict=True) != self.path or _sha256(self.path) != self.sha256:
            raise ExtractionPreflightError("pinned helper path or hash changed")


@dataclass(frozen=True, slots=True)
class ExtractionEntry:
    source_relative: str
    destination_relative: str
    source_size: int
    source_sha256: str
    kind: str = "regular_file"
    source_is_symlink: bool = False


@dataclass(frozen=True, slots=True)
class ExtractionPlan:
    client_id: str
    flow_id: str
    output_directory: Path
    entries: tuple[ExtractionEntry, ...]
    source_inventory_digest: str
    helper_sha256: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def readable_upload_path(relative: str) -> str:
    """Mirror the pinned helper's URL/accessor cleanup for preflight."""

    parts = [unquote(part) for part in Path(relative).parts if part]
    if parts and parts[0] in {"ntfs", "auto", "sparse", "file", "registry"}:
        parts = parts[1:]
    cleaned: list[str] = []
    for part in parts:
        value = part.replace("\\\\.\\", "").replace("\\", "_")
        value = value.rstrip(":").replace(":", "_")
        if value not in {"", ".", ".."}:
            cleaned.append(value)
    return os.path.join(*cleaned) if cleaned else "unnamed"


def decompress_concatenated_for_validation(
    raw: bytes,
    *,
    max_output_bytes: int,
) -> tuple[bytes, bool]:
    """Decode concatenated zlib streams with explicit truncation and size bounds."""

    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be positive")
    if not raw:
        return b"", False
    offset = 0
    output = bytearray()
    truncated = False
    while offset < len(raw):
        decoder = zlib.decompressobj()
        try:
            output.extend(decoder.decompress(raw[offset:], max_output_bytes - len(output) + 1))
        except zlib.error:
            if offset == 0:
                return raw, False
            truncated = True
            break
        if len(output) > max_output_bytes:
            raise ExtractionPreflightError("decoded output exceeds the configured byte limit")
        consumed = len(raw[offset:]) - len(decoder.unused_data)
        if consumed <= 0:
            truncated = True
            break
        offset += consumed
        if not decoder.eof:
            truncated = True
            break
    return bytes(output), truncated


def preflight_extraction(
    *,
    client: str,
    flow: str,
    flow_state: str,
    output_directory: Path,
    entries: tuple[ExtractionEntry, ...],
    helper: HelperPin,
    max_files: int = 10_000,
    max_source_bytes: int = 20_000_000_000,
) -> ExtractionPlan:
    exact_client = client_id(client)
    exact_flow = flow_id(flow)
    helper.verify()
    if flow_state != "FINISHED":
        raise ExtractionPreflightError("datastore extraction requires an exact finished flow")
    if output_directory.exists() or not output_directory.is_absolute():
        raise ExtractionPreflightError("output directory must be a fresh absolute path")
    if len(entries) > max_files or sum(item.source_size for item in entries) > max_source_bytes:
        raise ExtractionPreflightError("extraction exceeds configured resource limits")
    if not entries:
        raise ExtractionPreflightError("source inventory is empty")
    claimed: set[str] = set()
    for entry in entries:
        if entry.kind != "regular_file" or entry.source_is_symlink or entry.source_size < 0:
            raise ExtractionPreflightError("source inventory contains an unsafe file entry")
        destination = Path(entry.destination_relative)
        source = Path(entry.source_relative)
        if source.is_absolute() or ".." in source.parts:
            raise ExtractionPreflightError("source inventory path escapes the exact flow")
        if destination.is_absolute() or ".." in destination.parts:
            raise PathContainmentError("decoded destination escapes the output directory")
        key = destination.as_posix().casefold()
        if key in claimed:
            raise ExtractionPreflightError("decoded destinations collide")
        claimed.add(key)
    return ExtractionPlan(
        client_id=exact_client,
        flow_id=exact_flow,
        output_directory=output_directory,
        entries=entries,
        source_inventory_digest=canonical_digest(entries),
        helper_sha256=helper.sha256,
    )


def check_helper_argv(*, client: str, flow: str) -> tuple[str, ...]:
    return (
        sys.executable,
        str(CHECK_HELPER),
        client_id(client),
        "--flow",
        flow_id(flow),
        "--datastore",
        str(DATASTORE_ROOT),
    )


def extract_helper_argv(plan: ExtractionPlan, *, dry_run: bool) -> tuple[str, ...]:
    arguments = [
        sys.executable,
        str(EXTRACT_HELPER),
        plan.client_id,
        "--flow",
        plan.flow_id,
        "--datastore",
        str(DATASTORE_ROOT),
        "--outdir",
        str(plan.output_directory),
    ]
    if dry_run:
        arguments.append("--dry-run")
    return tuple(arguments)


def postvalidate_extraction(
    plan: ExtractionPlan,
    *,
    source_inventory_digest_after: str,
    output_entries: tuple[ExtractionEntry, ...],
    truncation_detected: bool,
) -> None:
    if source_inventory_digest_after != plan.source_inventory_digest:
        raise ExtractionPreflightError("source inventory changed during extraction")
    expected = {
        item.destination_relative.casefold(): item for item in plan.entries
    }
    actual = {item.destination_relative.casefold(): item for item in output_entries}
    if set(expected) != set(actual):
        raise ExtractionPreflightError("output inventory does not match the reviewed plan")
    if truncation_detected:
        raise ExtractionPreflightError("extraction produced truncated output")
    if any(item.source_is_symlink or item.kind != "regular_file" for item in output_entries):
        raise ExtractionPreflightError("output inventory contains an unsafe file entry")
