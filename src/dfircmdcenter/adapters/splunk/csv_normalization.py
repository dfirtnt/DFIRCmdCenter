"""Strict, deterministic CSV validation and normalization."""

from __future__ import annotations

import csv
import hashlib
import io
import os
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from dfircmdcenter.core.canonical import canonical_digest
from dfircmdcenter.core.time import render_eastern

from .naming import normalize_host
from .timestamps import TimestampPolicy, event_range_eastern

MAX_CSV_BYTES = 400_000_000
_GENERATED_FIELDS = (
    "host",
    "host_raw",
    "source_timestamp_raw",
    "source_zone_decision",
    "event_time_utc",
)
_GENERATED_FIELD_SET = frozenset(_GENERATED_FIELDS)


class CsvGovernanceError(ValueError):
    """A CSV cannot be normalized without guessing or losing provenance."""


@dataclass(frozen=True, slots=True)
class HostMapping:
    mode: str
    constant: str | None = None
    source_field: str | None = None
    reviewed_per_row_transform: bool = False
    forbidden_hosts: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.mode == "constant":
            if self.constant is None or self.source_field is not None:
                raise CsvGovernanceError("constant host mapping requires exactly one host")
        elif self.mode == "per_row":
            if self.source_field is None or self.constant is not None:
                raise CsvGovernanceError("per-row host mapping requires one source field")
            if not self.reviewed_per_row_transform:
                raise CsvGovernanceError("per-row host mapping requires a reviewed transform")
        else:
            raise CsvGovernanceError("host mapping mode must be constant or per_row")


@dataclass(frozen=True, slots=True)
class NormalizedCsv:
    source_path: Path
    normalized_path: Path
    source_sha256: str
    normalized_sha256: str
    source_bytes: int
    normalized_bytes: int
    row_count: int
    field_map: Mapping[str, str]
    row_fingerprints: tuple[str, ...]
    event_time_range_eastern: tuple[str, str]
    host_values: tuple[str, ...]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _normalized_header(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold().strip()
    normalized = re.sub(r"[^a-z0-9]+", "_", normalized).strip("_")
    if not normalized:
        raise CsvGovernanceError("CSV contains an empty normalized header")
    return normalized


def _decode_source(path: Path) -> tuple[str, bytes]:
    raw = path.read_bytes()
    if not raw:
        raise CsvGovernanceError("CSV is empty")
    if len(raw) > MAX_CSV_BYTES:
        raise CsvGovernanceError("CSV exceeds the operational daily byte ceiling")
    try:
        return raw.decode("utf-8-sig"), raw
    except UnicodeDecodeError as exc:
        raise CsvGovernanceError("CSV must be unambiguous UTF-8") from exc


def _publish_exclusive(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.parent / f".{path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def normalize_csv(
    source: Path,
    destination: Path,
    *,
    timestamp: TimestampPolicy,
    host_mapping: HostMapping,
    delimiter: str = ",",
) -> NormalizedCsv:
    """Normalize one immutable source CSV and publish a fresh derived copy."""

    if delimiter not in {",", "\t", ";", "|"}:
        raise CsvGovernanceError("delimiter is not allowlisted")
    text, source_bytes = _decode_source(source)
    try:
        sniffed = csv.Sniffer().sniff(text[:8192], delimiters=",\t;|").delimiter
    except csv.Error as exc:
        header_line = text.splitlines()[0]
        alternatives = {candidate for candidate in ",\t;|" if candidate in header_line}
        if alternatives != {delimiter}:
            raise CsvGovernanceError("CSV delimiter is ambiguous") from exc
        sniffed = delimiter
    if sniffed != delimiter:
        raise CsvGovernanceError("CSV delimiter differs from the explicit contract")
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True))
    except csv.Error as exc:
        raise CsvGovernanceError("CSV syntax is malformed") from exc
    if not rows or not rows[0] or any(not header.strip() for header in rows[0]):
        raise CsvGovernanceError("CSV requires a non-empty header row")
    raw_headers = rows[0]
    if len(raw_headers) != len(set(raw_headers)):
        raise CsvGovernanceError("CSV headers must be unique")
    normalized_headers = [_normalized_header(header) for header in raw_headers]
    if len(normalized_headers) != len(set(normalized_headers)):
        raise CsvGovernanceError("CSV headers collide after normalization")
    field_map = dict(zip(raw_headers, normalized_headers, strict=True))
    if timestamp.field not in raw_headers:
        raise CsvGovernanceError("explicit timestamp field is missing")
    if any(header in _GENERATED_FIELD_SET for header in normalized_headers):
        if not (
            host_mapping.mode == "per_row"
            and host_mapping.source_field in raw_headers
            and field_map[host_mapping.source_field] == "host"
        ):
            raise CsvGovernanceError("CSV collides with generated governance fields")

    timestamp_index = raw_headers.index(timestamp.field)
    host_index = (
        raw_headers.index(host_mapping.source_field)
        if host_mapping.mode == "per_row" and host_mapping.source_field in raw_headers
        else None
    )
    if host_mapping.mode == "per_row" and host_index is None:
        raise CsvGovernanceError("reviewed per-row host source field is missing")

    output_headers = [
        ("host_raw_input" if header == "host" and host_index == index else header)
        for index, header in enumerate(normalized_headers)
    ]
    output_headers.extend(_GENERATED_FIELDS)
    normalized_rows: list[dict[str, str]] = []
    instants = []
    hosts: set[str] = set()
    for number, row in enumerate(rows[1:], start=2):
        if len(row) != len(raw_headers):
            raise CsvGovernanceError(f"CSV row {number} has the wrong column count")
        parsed = timestamp.parse(row[timestamp_index])
        instants.append(parsed.instant_utc)
        raw_host = host_mapping.constant if host_index is None else row[host_index]
        assert raw_host is not None
        host = normalize_host(raw_host, forbidden=host_mapping.forbidden_hosts)
        hosts.add(host.host)
        normalized_row = dict(zip(output_headers[: len(row)], row, strict=True))
        normalized_row.update(
            {
                "host": host.host,
                "host_raw": host.host_raw or "",
                "source_timestamp_raw": parsed.raw,
                "source_zone_decision": parsed.zone_decision.value,
                "event_time_utc": parsed.instant_utc.isoformat(),
            }
        )
        normalized_rows.append(normalized_row)
    if not normalized_rows:
        raise CsvGovernanceError("CSV contains no data rows")

    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=output_headers, lineterminator="\n")
    writer.writeheader()
    writer.writerows(normalized_rows)
    payload = output.getvalue().encode("utf-8")
    _publish_exclusive(destination, payload)
    fingerprints = tuple(canonical_digest(row) for row in normalized_rows)
    time_range = event_range_eastern(instants)
    # Explicitly exercise offset-bearing Eastern rendering as an invariant.
    assert all(render_eastern(value)[-6:-5] in {"+", "-"} for value in instants)
    return NormalizedCsv(
        source_path=source.resolve(),
        normalized_path=destination.resolve(),
        source_sha256=_sha256_bytes(source_bytes),
        normalized_sha256=_sha256_bytes(payload),
        source_bytes=len(source_bytes),
        normalized_bytes=len(payload),
        row_count=len(normalized_rows),
        field_map=field_map,
        row_fingerprints=fingerprints,
        event_time_range_eastern=time_range,
        host_values=tuple(sorted(hosts)),
    )
