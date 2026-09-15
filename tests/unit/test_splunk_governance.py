from __future__ import annotations

import csv
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfircmdcenter.adapters.splunk.budget import evaluate_budget
from dfircmdcenter.adapters.splunk.coverage import (
    CoverageClass,
    CoverageEvidence,
    PriorDataset,
    classify_coverage,
)
from dfircmdcenter.adapters.splunk.csv_normalization import (
    CsvGovernanceError,
    HostMapping,
    normalize_csv,
)
from dfircmdcenter.adapters.splunk.ingest import IngestBlockedError, build_ingest_proposal
from dfircmdcenter.adapters.splunk.naming import (
    NamingError,
    normalize_host,
    validate_index,
    validate_sourcetype,
)
from dfircmdcenter.adapters.splunk.timestamps import TimestampPolicy
from dfircmdcenter.core.time import AmbiguousLocalTimeError, NonexistentLocalTimeError

NOW = datetime(2026, 9, 15, 17, tzinfo=UTC)


def write_csv(path: Path, body: str, *, bom: bool = False) -> None:
    prefix = "\ufeff" if bom else ""
    path.write_text(prefix + body, encoding="utf-8")


def normalize_fixture(
    tmp_path: Path,
    *,
    body: str = "Time,Message\n2026-09-15T12:00:00Z,one\n",
    name: str = "source.csv",
    bom: bool = False,
):  # type: ignore[no-untyped-def]
    source = tmp_path / name
    destination = tmp_path / f"normalized-{name}"
    write_csv(source, body, bom=bom)
    return normalize_csv(
        source,
        destination,
        timestamp=TimestampPolicy("Time"),
        host_mapping=HostMapping(mode="constant", constant="LAB-WIN11.EXAMPLE.TEST"),
    )


def complete_coverage(*prior: PriorDataset):  # type: ignore[no-untyped-def]
    return CoverageEvidence(
        prior_datasets=tuple(prior),
        indexed_search_complete=True,
        monitor_inventory_complete=True,
    )


def test_multiline_and_bom_csv_normalize_deterministically(tmp_path: Path) -> None:
    dataset = normalize_fixture(
        tmp_path,
        body='Time,Message\n2026-09-15T12:00:00Z,"line one\nline two"\n',
        bom=True,
    )

    with dataset.normalized_path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert dataset.row_count == 1
    assert rows[0]["message"] == "line one\nline two"
    assert rows[0]["host"] == "lab-win11.example.test"
    assert rows[0]["host_raw"] == "LAB-WIN11.EXAMPLE.TEST"
    assert rows[0]["source_timestamp_raw"] == "2026-09-15T12:00:00Z"
    assert dataset.event_time_range_eastern == (
        "2026-09-15T08:00:00-04:00",
        "2026-09-15T08:00:00-04:00",
    )


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("Time,Message,time\n2026-09-15T12:00:00Z,x,y\n", "collide"),
        ("Time,Message\n2026-09-15T12:00:00Z\n", "column count"),
        ("Time;Message\n2026-09-15T12:00:00Z;x\n", "delimiter differs"),
    ],
)
def test_malformed_or_ambiguous_csv_is_blocked(
    tmp_path: Path, body: str, message: str
) -> None:
    with pytest.raises(CsvGovernanceError, match=message):
        normalize_fixture(tmp_path, body=body)


def test_non_utf8_csv_is_blocked(tmp_path: Path) -> None:
    source = tmp_path / "source.csv"
    source.write_bytes(b"Time,Message\n2026-09-15T12:00:00Z,\xff\n")

    with pytest.raises(CsvGovernanceError, match="UTF-8"):
        normalize_csv(
            source,
            tmp_path / "normalized.csv",
            timestamp=TimestampPolicy("Time"),
            host_mapping=HostMapping(mode="constant", constant="lab-win11"),
        )


def test_multi_host_requires_a_reviewed_per_row_mapping(tmp_path: Path) -> None:
    with pytest.raises(CsvGovernanceError, match="reviewed transform"):
        HostMapping(mode="per_row", source_field="Computer")

    source = tmp_path / "multi.csv"
    write_csv(
        source,
        "Time,Computer,Message\n"
        "2026-09-15T12:00:00Z,Host-One,x\n"
        "2026-09-15T12:01:00Z,host-two.example.test,y\n",
    )
    dataset = normalize_csv(
        source,
        tmp_path / "normalized.csv",
        timestamp=TimestampPolicy("Time"),
        host_mapping=HostMapping(
            mode="per_row",
            source_field="Computer",
            reviewed_per_row_transform=True,
        ),
    )
    assert dataset.host_values == ("host-one", "host-two.example.test")


def test_naive_eastern_timestamps_require_evidence_and_dst_fold(tmp_path: Path) -> None:
    body = "Time,Message\n2026-11-01T01:30:00,repeated\n"
    with pytest.raises(AmbiguousLocalTimeError):
        normalize_fixture_with_policy(
            tmp_path,
            body,
            TimestampPolicy(
                "Time",
                source_zone="America/New_York",
                rationale="source system records Eastern wall time",
            ),
        )
    dataset = normalize_fixture_with_policy(
        tmp_path,
        body,
        TimestampPolicy(
            "Time",
            source_zone="America/New_York",
            fold=1,
            rationale="source sequence proves the second 01:30 occurrence",
        ),
        name="fold.csv",
    )
    assert dataset.event_time_range_eastern[0].endswith("-05:00")

    with pytest.raises(NonexistentLocalTimeError):
        normalize_fixture_with_policy(
            tmp_path,
            "Time,Message\n2026-03-08T02:30:00,gap\n",
            TimestampPolicy(
                "Time",
                source_zone="America/New_York",
                rationale="source system records Eastern wall time",
            ),
            name="gap.csv",
        )


def normalize_fixture_with_policy(
    tmp_path: Path,
    body: str,
    policy: TimestampPolicy,
    *,
    name: str = "source.csv",
):  # type: ignore[no-untyped-def]
    source = tmp_path / name
    write_csv(source, body)
    return normalize_csv(
        source,
        tmp_path / f"normalized-{name}",
        timestamp=policy,
        host_mapping=HostMapping(mode="constant", constant="lab-win11"),
    )


def test_naming_is_consistent_and_default_deny() -> None:
    assert validate_index("dfir") == "dfir"
    assert normalize_host("WORKSTATION.Example.COM.").host == "workstation.example.com"
    assert validate_sourcetype("dfir:velociraptor:autoruns:v1")
    with pytest.raises(NamingError):
        validate_index("main")
    with pytest.raises(NamingError):
        validate_sourcetype("csv")
    with pytest.raises(NamingError):
        normalize_host("this mac", forbidden=frozenset({"this-mac"}))


def test_coverage_classifies_exact_alternate_partial_new_and_unknown(tmp_path: Path) -> None:
    candidate = normalize_fixture(
        tmp_path,
        body=(
            "Time,Message\n"
            "2026-09-15T12:00:00Z,one\n"
            "2026-09-15T12:01:00Z,two\n"
        ),
    )
    exact = PriorDataset(
        "exact",
        candidate.source_sha256,
        "0" * 64,
        frozenset(),
    )
    alternate = PriorDataset(
        "alternate",
        "1" * 64,
        candidate.normalized_sha256,
        frozenset(),
    )
    partial = PriorDataset(
        "partial",
        "2" * 64,
        "3" * 64,
        frozenset({candidate.row_fingerprints[0]}),
    )
    assert (
        classify_coverage(candidate, complete_coverage(exact)).classification
        is CoverageClass.EXACT_DUPLICATE
    )
    assert (
        classify_coverage(candidate, complete_coverage(alternate)).classification
        is CoverageClass.ALTERNATE_REPRESENTATION
    )
    assert (
        classify_coverage(candidate, complete_coverage(partial)).classification
        is CoverageClass.PARTIAL_OVERLAP
    )
    assert classify_coverage(candidate, complete_coverage()).classification is CoverageClass.NEW
    unknown = CoverageEvidence((), False, True)
    assert classify_coverage(candidate, unknown).classification is CoverageClass.UNKNOWN


@pytest.mark.parametrize(
    ("proposed", "allowed"),
    [(399_000_000, True), (400_000_000, True), (401_000_000, False)],
)
def test_budget_boundaries(proposed: int, allowed: bool) -> None:
    decision = evaluate_budget(
        now=NOW,
        measured_bytes=0,
        pending_bytes=0,
        competing_bytes=0,
        proposed_bytes=proposed,
        measurement_complete=True,
        reset_boundary_confirmed=True,
    )
    assert decision.allowed is allowed
    assert decision.license_day == "2026-09-15"


def test_budget_blocks_measurement_lag_competing_unknown_and_pending_bytes() -> None:
    for changes in (
        {"measurement_complete": False},
        {"competing_bytes": None},
        {"reset_boundary_confirmed": False},
    ):
        arguments = {
            "now": NOW,
            "measured_bytes": 1,
            "pending_bytes": 2,
            "competing_bytes": 3,
            "proposed_bytes": 4,
            "measurement_complete": True,
            "reset_boundary_confirmed": True,
            **changes,
        }
        assert not evaluate_budget(**arguments).allowed
    assert not evaluate_budget(
        now=NOW,
        measured_bytes=200_000_000,
        pending_bytes=150_000_000,
        competing_bytes=1,
        proposed_bytes=50_000_000,
        measurement_complete=True,
        reset_boundary_confirmed=True,
    ).allowed


def test_ingest_proposal_binds_exact_governance_state(tmp_path: Path) -> None:
    dataset = normalize_fixture(tmp_path)
    coverage = classify_coverage(dataset, complete_coverage())
    budget = evaluate_budget(
        now=NOW,
        measured_bytes=10,
        pending_bytes=20,
        competing_bytes=30,
        proposed_bytes=dataset.normalized_bytes,
        measurement_complete=True,
        reset_boundary_confirmed=True,
    )
    proposal = build_ingest_proposal(
        dataset=dataset,
        coverage=coverage,
        budget=budget,
        index="dfir",
        sourcetype="dfir:velociraptor:processes:v1",
        policy_version="1",
        parsing_contract_sha256="a" * 64,
        before_state={"indexed_events": 0},
        created_at=NOW,
    )

    assert proposal.scope["source_sha256"] == dataset.source_sha256
    assert proposal.expected_effects["indexed_event_count"] == 1
    assert proposal.scope["host"] == "lab-win11.example.test"

    blocked = classify_coverage(
        dataset,
        complete_coverage(
            PriorDataset(
                "old",
                dataset.source_sha256,
                dataset.normalized_sha256,
                frozenset(dataset.row_fingerprints),
            )
        ),
    )
    with pytest.raises(IngestBlockedError, match="coverage"):
        build_ingest_proposal(
            dataset=dataset,
            coverage=blocked,
            budget=budget,
            index="dfir",
            sourcetype="dfir:velociraptor:processes:v1",
            policy_version="1",
            parsing_contract_sha256="a" * 64,
            before_state={},
            created_at=NOW,
        )
