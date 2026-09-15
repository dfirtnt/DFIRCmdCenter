from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from dfircmdcenter.cli import main
from dfircmdcenter.core.approvals import ControlStore
from dfircmdcenter.core.records import Platform, Proposal
from dfircmdcenter.core.time import workflow_now

ROOT = Path(__file__).resolve().parents[2]


def test_limacharlie_rule_inspection_and_fixture_plan(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rule = ROOT / "platforms" / "limacharlie" / "rules" / "windows-log-clear.yaml"
    assert main(["limacharlie", "inspect-rule", str(rule)]) == 0
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["responses"][0]["action"] == "report"

    assert (
        main(
            [
                "--state-root",
                str(tmp_path),
                "limacharlie",
                "plan",
                "fixture-create",
                str(rule),
                "--organization-id",
                "oid-fixture",
            ]
        )
        == 0
    )
    planned = json.loads(capsys.readouterr().out)
    assert planned["policy_version"] == "fixture-1"
    assert main(["--state-root", str(tmp_path), "proposal", "show", planned["proposal_id"]]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["proposal_digest"] == planned["proposal_digest"]


def test_velociraptor_collection_and_export_plans_are_persisted(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    spec = (
        ROOT
        / "platforms"
        / "velociraptor"
        / "collections"
        / "windows-system-pslist.yaml"
    )
    assert (
        main(
            [
                "--state-root",
                str(tmp_path),
                "velociraptor",
                "plan",
                "collection",
                "--spec",
                str(spec),
                "--client-id",
                "C.fixture",
            ]
        )
        == 0
    )
    collection = json.loads(capsys.readouterr().out)
    assert collection["operation"] == "launch_collection"

    assert (
        main(
            [
                "--state-root",
                str(tmp_path),
                "velociraptor",
                "plan",
                "export",
                "flow",
                "F.fixture",
                "--client-id",
                "C.fixture",
            ]
        )
        == 0
    )
    export = json.loads(capsys.readouterr().out)
    assert export["scope"]["destination_root"].startswith(str(tmp_path))


def test_splunk_fixture_csv_plan_normalizes_but_cannot_be_live_approved(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "events.csv"
    source.write_text("Time,Value\n2026-09-15T12:00:00Z,one\n", encoding="utf-8")
    assert (
        main(
            [
                "--state-root",
                str(tmp_path / "state"),
                "splunk",
                "plan",
                "fixture-csv",
                str(source),
                "--timestamp-field",
                "Time",
                "--host",
                "lab-win11",
                "--sourcetype",
                "dfir:fixture:events:v1",
            ]
        )
        == 0
    )
    proposal = json.loads(capsys.readouterr().out)
    normalized = Path(proposal["scope"]["normalized_path"])
    assert normalized.is_file()
    assert (
        main(
            [
                "--state-root",
                str(tmp_path / "state"),
                "proposal",
                "approve",
                proposal["proposal_id"],
                "--approval-ref",
                "chat-turn-test",
                "--confirm-exact-chat-approval",
            ]
        )
        == 2
    )
    assert "fixture proposals cannot" in capsys.readouterr().err


def test_real_proposal_approval_requires_explicit_chat_confirmation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    now = workflow_now()
    proposal = Proposal.create(
        platform=Platform.VELOCIRAPTOR,
        operation="create_flow_export",
        scope={"client_id": "C.fixture", "flow_id": "F.fixture"},
        preconditions={"flow_state": "FINISHED"},
        policy_version="1",
        dependency_hashes={"contract": "a" * 64},
        validation={"contained": True},
        expires_at=now + timedelta(hours=1),
        expected_effects={"export_jobs": 1},
        before_state={"export": None},
        proposed_after_state={"export": "prepared"},
        human_diff="Prepare one exact flow export.",
        rollback_or_recovery="Reconcile with reads; do not resubmit automatically.",
        created_at=now,
    )
    store = ControlStore(tmp_path / "control" / "state.sqlite3")
    store.register_proposal(proposal)

    base = [
        "--state-root",
        str(tmp_path),
        "proposal",
        "approve",
        proposal.proposal_id,
        "--approval-ref",
        "chat-turn-verified",
    ]
    assert main(base) == 2
    assert "after Andrew approved" in capsys.readouterr().err
    assert main([*base, "--confirm-exact-chat-approval"]) == 0
    approval = json.loads(capsys.readouterr().out)
    assert approval["proposal_digest"] == proposal.proposal_digest

    assert main(["--state-root", str(tmp_path), "apply", proposal.proposal_id]) == 2
    assert "approval was not consumed" in capsys.readouterr().err
    stored = store.latest_approval_for(proposal.proposal_digest)
    assert stored is not None and stored.consumed_at is None

