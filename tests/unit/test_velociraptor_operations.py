from __future__ import annotations

import hashlib
import zlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfircmdcenter.adapters.velociraptor.client import client_id, flow_id
from dfircmdcenter.adapters.velociraptor.collections import (
    CollectionSpec,
    build_collection_proposal,
    load_collection_spec,
)
from dfircmdcenter.adapters.velociraptor.exports import build_export_proposal
from dfircmdcenter.adapters.velociraptor.helpers import (
    ExtractionEntry,
    ExtractionPreflightError,
    HelperPin,
    decompress_concatenated_for_validation,
    postvalidate_extraction,
    preflight_extraction,
    readable_upload_path,
)
from dfircmdcenter.adapters.velociraptor.hunts import build_hunt_proposal
from dfircmdcenter.adapters.velociraptor.integrity import verify_collection
from dfircmdcenter.adapters.velociraptor.scope import (
    ResolvedClientScope,
    ScopeDriftError,
    StandingHuntScope,
)
from dfircmdcenter.core.paths import PathContainmentError
from dfircmdcenter.core.records import VerificationStatus

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 9, 15, 19, tzinfo=UTC)


def spec() -> CollectionSpec:
    return load_collection_spec(
        ROOT / "platforms" / "velociraptor" / "collections" / "windows-system-pslist.yaml"
    )


def test_immediate_label_scope_resolves_to_exact_clients_and_revalidates() -> None:
    scope = ResolvedClientScope(
        ("C.second", "C.first", "C.first"),
        resolved_at=NOW,
        source_label="lab",
    )
    assert scope.client_ids == ("C.first", "C.second")
    scope.revalidate(("C.second", "C.first"))
    with pytest.raises(ScopeDriftError):
        scope.revalidate(("C.first", "C.third"))


def test_collection_proposal_pins_scope_artifact_and_limits() -> None:
    scope = ResolvedClientScope(("C.first",), resolved_at=NOW)
    proposal = build_collection_proposal(
        scope=scope,
        specification=spec(),
        policy_version="1",
        server_identity="velo-local",
        created_at=NOW,
    )
    assert proposal.scope["client_ids"] == ("C.first",)
    assert proposal.preconditions["artifact_sha256"] == "a" * 64
    assert proposal.validation["max_rows"] == 100_000


def test_standing_hunt_explicitly_includes_future_clients() -> None:
    scope = StandingHuntScope("lab", ("C.first",))
    proposal = build_hunt_proposal(
        scope=scope,
        specification=spec(),
        policy_version="1",
        server_identity="velo-local",
        created_at=NOW,
    )
    assert proposal.operation == "create_standing_hunt"
    assert proposal.expected_effects["includes_future_matching_clients"] is True
    assert proposal.scope["target"]["includes_future_matching_clients"] is True  # type: ignore[index]


@pytest.mark.parametrize(
    ("helper_exit", "flow_state", "rows", "uploads", "status"),
    [
        (0, "FINISHED", {"table": 1}, {"archive": 5}, VerificationStatus.PASSED),
        (1, "FINISHED", {"table": 1}, {"archive": 5}, VerificationStatus.FAILED),
        (2, "FINISHED", {"table": 1}, {"archive": 5}, VerificationStatus.UNKNOWN),
        (0, "RUNNING", {"table": 1}, {"archive": 5}, VerificationStatus.PARTIAL),
        (0, "FINISHED", {"table": 0}, {"archive": 5}, VerificationStatus.PARTIAL),
        (0, "FINISHED", {"table": 1}, {}, VerificationStatus.PARTIAL),
    ],
)
def test_collection_integrity_requires_more_than_finished(
    helper_exit: int,
    flow_state: str,
    rows: dict[str, int],
    uploads: dict[str, int],
    status: VerificationStatus,
) -> None:
    result = verify_collection(
        checked_at=NOW,
        helper_exit=helper_exit,
        flow_state=flow_state,
        table_rows=rows,
        upload_bytes=uploads,
        expected_tables=("table",),
        expected_upload_classes=("archive",),
        max_upload_bytes=100,
    )
    assert result.status is status


def test_supported_export_scope_and_destination_are_exact(tmp_path: Path) -> None:
    allowed = tmp_path / "exports"
    proposal = build_export_proposal(
        kind="flow",
        identifier="F.flowone",
        client="C.clientone",
        server_identity="velo-local",
        destination_root=allowed / "F.flowone",
        allowed_export_root=allowed,
        policy_version="1",
        created_at=NOW,
    )
    assert proposal.operation == "create_flow_export"
    with pytest.raises(ValueError, match="outside"):
        build_export_proposal(
            kind="flow",
            identifier="F.flowone",
            client="C.clientone",
            server_identity="velo-local",
            destination_root=tmp_path / "outside",
            allowed_export_root=allowed,
            policy_version="1",
            created_at=NOW,
        )
    with pytest.raises(ValueError):
        build_export_proposal(
            kind="flow",
            identifier="F.other/unsafe",
            client="C.clientone",
            server_identity="velo-local",
            destination_root=allowed,
            allowed_export_root=allowed,
            policy_version="1",
            created_at=NOW,
        )


def helper_pin(tmp_path: Path) -> HelperPin:
    helper = tmp_path / "extract.py"
    helper.write_text("fixture helper", encoding="utf-8")
    return HelperPin.capture(helper)


def entry(
    destination: str = "F.flow__Artifact/C/Windows/file.txt",
    *,
    source: str = "uploads/ntfs/file.zlib",
    symlink: bool = False,
) -> ExtractionEntry:
    return ExtractionEntry(
        source_relative=source,
        destination_relative=destination,
        source_size=10,
        source_sha256="a" * 64,
        source_is_symlink=symlink,
    )


def test_datastore_extraction_preflight_blocks_escape_collision_symlink_and_drift(
    tmp_path: Path,
) -> None:
    pin = helper_pin(tmp_path)
    base = {
        "client": "C.clientone",
        "flow": "F.flowone",
        "flow_state": "FINISHED",
        "output_directory": tmp_path / "fresh-output",
        "helper": pin,
    }
    with pytest.raises(PathContainmentError):
        preflight_extraction(entries=(entry("../escape"),), **base)
    with pytest.raises(ExtractionPreflightError, match="collide"):
        preflight_extraction(entries=(entry("same"), entry("SAME")), **base)
    with pytest.raises(ExtractionPreflightError, match="unsafe"):
        preflight_extraction(entries=(entry(symlink=True),), **base)
    with pytest.raises(ExtractionPreflightError, match="source inventory path"):
        preflight_extraction(entries=(entry(source="../other-flow"),), **base)

    pin.path.write_text("changed helper", encoding="utf-8")
    with pytest.raises(ExtractionPreflightError, match="helper"):
        preflight_extraction(entries=(entry(),), **base)


def test_datastore_postvalidation_detects_source_change_missing_output_and_truncation(
    tmp_path: Path,
) -> None:
    plan = preflight_extraction(
        client="C.clientone",
        flow="F.flowone",
        flow_state="FINISHED",
        output_directory=tmp_path / "fresh-output",
        entries=(entry(),),
        helper=helper_pin(tmp_path),
    )
    with pytest.raises(ExtractionPreflightError, match="source inventory changed"):
        postvalidate_extraction(
            plan,
            source_inventory_digest_after="b" * 64,
            output_entries=(entry(),),
            truncation_detected=False,
        )
    with pytest.raises(ExtractionPreflightError, match="output inventory"):
        postvalidate_extraction(
            plan,
            source_inventory_digest_after=plan.source_inventory_digest,
            output_entries=(),
            truncation_detected=False,
        )
    with pytest.raises(ExtractionPreflightError, match="truncated"):
        postvalidate_extraction(
            plan,
            source_inventory_digest_after=plan.source_inventory_digest,
            output_entries=(entry(),),
            truncation_detected=True,
        )


def test_concatenated_zlib_validation_decodes_all_streams_and_flags_truncation() -> None:
    first = zlib.compress(b"first")
    second = zlib.compress(b"second")
    output, truncated = decompress_concatenated_for_validation(
        first + second,
        max_output_bytes=100,
    )
    assert output == b"firstsecond"
    assert not truncated

    output, truncated = decompress_concatenated_for_validation(
        first + second[:-2],
        max_output_bytes=100,
    )
    assert output.startswith(b"first")
    assert truncated


def test_helper_path_decoding_and_identifier_guards() -> None:
    assert readable_upload_path("ntfs/%5C%5C.%5CC%3A/Windows/a.txt") == "C/Windows/a.txt"
    assert client_id("C.good") == "C.good"
    assert flow_id("F.good") == "F.good"
    with pytest.raises(ValueError):
        client_id("C.good/../../bad")


def test_helper_hash_is_sha256(tmp_path: Path) -> None:
    pin = helper_pin(tmp_path)
    assert pin.sha256 == hashlib.sha256(b"fixture helper").hexdigest()

