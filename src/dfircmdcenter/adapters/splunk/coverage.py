"""Conservative duplicate and overlap classification for Splunk datasets."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from dfircmdcenter.core.canonical import canonical_digest

from .csv_normalization import NormalizedCsv


class CoverageClass(StrEnum):
    NEW = "new"
    EXACT_DUPLICATE = "exact_duplicate"
    PARTIAL_OVERLAP = "partial_overlap"
    ALTERNATE_REPRESENTATION = "alternate_representation"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class PriorDataset:
    dataset_id: str
    source_sha256: str
    normalized_sha256: str
    row_fingerprints: frozenset[str]


@dataclass(frozen=True, slots=True)
class CoverageEvidence:
    prior_datasets: tuple[PriorDataset, ...]
    indexed_search_complete: bool
    monitor_inventory_complete: bool
    overlapping_monitor: bool = False

    @property
    def digest(self) -> str:
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class CoverageDecision:
    classification: CoverageClass
    matching_dataset_ids: tuple[str, ...]
    reason: str
    evidence_digest: str


def classify_coverage(candidate: NormalizedCsv, evidence: CoverageEvidence) -> CoverageDecision:
    if (
        not evidence.indexed_search_complete
        or not evidence.monitor_inventory_complete
        or evidence.overlapping_monitor
    ):
        return CoverageDecision(
            CoverageClass.UNKNOWN,
            (),
            "indexed coverage or monitored-input state is incomplete or overlapping",
            evidence.digest,
        )
    exact = tuple(
        item.dataset_id
        for item in evidence.prior_datasets
        if item.source_sha256 == candidate.source_sha256
    )
    if exact:
        return CoverageDecision(
            CoverageClass.EXACT_DUPLICATE,
            exact,
            "the exact source hash was previously ingested",
            evidence.digest,
        )
    alternate = tuple(
        item.dataset_id
        for item in evidence.prior_datasets
        if item.normalized_sha256 == candidate.normalized_sha256
    )
    if alternate:
        return CoverageDecision(
            CoverageClass.ALTERNATE_REPRESENTATION,
            alternate,
            "different source bytes normalize to an existing dataset",
            evidence.digest,
        )
    current_rows = frozenset(candidate.row_fingerprints)
    partial = tuple(
        item.dataset_id
        for item in evidence.prior_datasets
        if current_rows.intersection(item.row_fingerprints)
    )
    if partial:
        return CoverageDecision(
            CoverageClass.PARTIAL_OVERLAP,
            partial,
            "one or more canonical rows already exist",
            evidence.digest,
        )
    return CoverageDecision(
        CoverageClass.NEW,
        (),
        "no source, normalized, row, indexed, or monitor overlap was found",
        evidence.digest,
    )

