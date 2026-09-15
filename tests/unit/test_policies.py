from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from yaml.constructor import ConstructorError

from dfircmdcenter.config import PROJECT_ROOT, load_policy, load_yaml


def test_policies_load_with_duplicate_safe_loader() -> None:
    assert load_policy("approval-gates")["default"] == "deny"
    assert load_policy("splunk-ingest")["splunk_ingest_governance"]["default"] == "deny"


def test_duplicate_yaml_key_is_rejected(tmp_path: Path) -> None:
    duplicate_policy = tmp_path / "duplicate.yaml"
    duplicate_policy.write_text("default: deny\ndefault: allow\n", encoding="utf-8")

    with pytest.raises(ConstructorError, match="duplicate key"):
        load_yaml(duplicate_policy)


def test_approval_policy_has_required_fail_closed_controls() -> None:
    policy = load_policy("approval-gates")

    assert policy["proposal"]["exact_binding_required"] is True
    assert policy["approval"]["required_for_each_consequential_action"] is True
    assert policy["stale_state"]["changed_precondition"] == "invalidate_approval"
    assert policy["consumption"]["exactly_once"] is True
    assert policy["retry"]["automatic_write_retry"] == "forbidden"


def test_splunk_policy_has_approved_governance_controls() -> None:
    policy = load_policy("splunk-ingest")
    ingest = policy["splunk_ingest_governance"]
    naming = policy["splunk_naming"]
    csv_ingest = policy["csv_ingest"]

    assert ingest["duplicates"]["exact_duplicate"] == "block"
    assert ingest["duplicates"]["partial_overlap"] == "block"
    assert ingest["license"]["operational_daily_limit_source_bytes"] == 400_000_000
    assert ingest["time"]["display_timezone"] == "America/New_York"
    assert naming["index"]["default"] == "dfir"
    assert naming["host"]["missing_or_ambiguous_host"] == "block_and_review"
    assert naming["sourcetype"]["automatic_sourcetype_detection"] == "forbidden"
    assert csv_ingest["method"] == "approval_gated_one_shot"
    assert csv_ingest["incoming_folder_is_monitored"] is False
    assert policy["monitored_inputs"]["forbidden_for"] == "ad_hoc_forensic_csv"


@pytest.mark.parametrize(
    "private_path",
    [
        "var/control/state.sqlite3",
        "var/splunk/incoming/evidence.csv",
        ".env",
        ".env.local",
        "settings.local.yaml",
        ".dfircmdcenter/session.json",
        "src/dfircmdcenter/__pycache__/config.cpython-312.pyc",
        ".coverage",
        "htmlcov/index.html",
        "dist/dfircmdcenter.whl",
    ],
)
def test_private_and_generated_paths_are_ignored(private_path: str) -> None:
    result = subprocess.run(
        ["git", "check-ignore", "--quiet", private_path],
        cwd=PROJECT_ROOT,
        check=False,
    )

    assert result.returncode == 0, private_path

