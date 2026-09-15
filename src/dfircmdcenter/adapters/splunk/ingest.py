"""Approval-ready Splunk one-shot CSV proposals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from dfircmdcenter.core.records import Platform, Proposal

from .budget import BudgetDecision
from .coverage import CoverageClass, CoverageDecision
from .csv_normalization import NormalizedCsv
from .naming import validate_index, validate_sourcetype


class IngestBlockedError(RuntimeError):
    """Governance blocked ingestion before any submission."""


def build_oneshot_argv(
    *,
    splunk_binary: Path,
    normalized_path: Path,
    index: str,
    host: str,
    sourcetype: str,
) -> tuple[str, ...]:
    validate_index(index)
    validate_sourcetype(sourcetype)
    if not splunk_binary.is_absolute() or not normalized_path.is_absolute():
        raise ValueError("Splunk executable and one-shot path must be absolute")
    return (
        str(splunk_binary),
        "add",
        "oneshot",
        str(normalized_path),
        "-index",
        index,
        "-host",
        host,
        "-sourcetype",
        sourcetype,
    )


def build_ingest_proposal(
    *,
    dataset: NormalizedCsv,
    coverage: CoverageDecision,
    budget: BudgetDecision,
    index: str,
    sourcetype: str,
    policy_version: str,
    parsing_contract_sha256: str,
    before_state: Mapping[str, Any],
    created_at: datetime,
) -> Proposal:
    validate_index(index)
    validate_sourcetype(sourcetype)
    if coverage.classification is not CoverageClass.NEW:
        raise IngestBlockedError(
            f"coverage classification blocks ingestion: {coverage.classification}"
        )
    if not budget.allowed:
        raise IngestBlockedError(f"license budget blocks ingestion: {budget.reason}")
    if len(dataset.host_values) != 1:
        raise IngestBlockedError("one-shot proposal requires one exact normalized host")
    if budget.proposed_bytes != dataset.normalized_bytes:
        raise IngestBlockedError("budget reservation does not match normalized source bytes")
    scope = {
        "dataset_source_path": str(dataset.source_path),
        "normalized_path": str(dataset.normalized_path),
        "source_sha256": dataset.source_sha256,
        "normalized_sha256": dataset.normalized_sha256,
        "index": index,
        "host": dataset.host_values[0],
        "sourcetype": sourcetype,
        "license_day": budget.license_day,
    }
    preconditions = {
        "source_sha256": dataset.source_sha256,
        "normalized_sha256": dataset.normalized_sha256,
        "coverage_evidence_digest": coverage.evidence_digest,
        "budget": {
            "measured_bytes": budget.measured_bytes,
            "pending_bytes": budget.pending_bytes,
            "competing_bytes": budget.competing_bytes,
            "projected_bytes": budget.projected_bytes,
        },
        "parsing_contract_sha256": parsing_contract_sha256,
    }
    return Proposal.create(
        platform=Platform.SPLUNK,
        operation="oneshot_csv_ingest",
        scope=scope,
        preconditions=preconditions,
        policy_version=policy_version,
        dependency_hashes={"parsing_contract": parsing_contract_sha256},
        validation={
            "coverage": coverage.classification,
            "row_count": dataset.row_count,
            "field_map": dataset.field_map,
            "event_time_range_eastern": dataset.event_time_range_eastern,
        },
        expires_at=created_at + timedelta(minutes=20),
        expected_effects={
            "indexed_event_count": dataset.row_count,
            "projected_license_bytes": dataset.normalized_bytes,
            "index": index,
            "host": dataset.host_values[0],
            "sourcetype": sourcetype,
        },
        before_state=before_state,
        proposed_after_state={
            "dataset_present": True,
            "indexed_event_count_delta": dataset.row_count,
        },
        human_diff=(
            f"Ingest exactly {dataset.row_count} rows ({dataset.normalized_bytes} source bytes) "
            f"once into index={index}, host={dataset.host_values[0]}, sourcetype={sourcetype}."
        ),
        rollback_or_recovery=(
            "Do not resubmit after ambiguity. Reconcile indexed metadata and event fingerprints; "
            "any deletion is a separate approved operation."
        ),
        created_at=created_at,
    )
