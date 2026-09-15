"""Bounded CLI handlers for proposals and non-live planning."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from dfircmdcenter.adapters.action1.deployments import build_deployment_proposal
from dfircmdcenter.adapters.action1.inventory import DeploymentPackage, EndpointIdentity
from dfircmdcenter.adapters.limacharlie.rules import build_rule_proposal, load_rule
from dfircmdcenter.adapters.limacharlie.validation import RuleTestResult, validate_rule_results
from dfircmdcenter.adapters.splunk.budget import evaluate_budget
from dfircmdcenter.adapters.splunk.coverage import CoverageEvidence, classify_coverage
from dfircmdcenter.adapters.splunk.csv_normalization import (
    HostMapping,
    normalize_csv,
)
from dfircmdcenter.adapters.splunk.ingest import build_ingest_proposal
from dfircmdcenter.adapters.splunk.timestamps import TimestampPolicy
from dfircmdcenter.adapters.velociraptor.collections import (
    build_collection_proposal,
    load_collection_spec,
)
from dfircmdcenter.adapters.velociraptor.exports import build_export_proposal
from dfircmdcenter.adapters.velociraptor.hunts import build_hunt_proposal
from dfircmdcenter.adapters.velociraptor.scope import (
    ResolvedClientScope,
    StandingHuntScope,
)
from dfircmdcenter.config import PROJECT_ROOT
from dfircmdcenter.core.approvals import ControlStore
from dfircmdcenter.core.canonical import canonical_json
from dfircmdcenter.core.records import Approval, Proposal
from dfircmdcenter.core.time import workflow_now

DEFAULT_STATE_ROOT = PROJECT_ROOT / "var"


def _store(arguments: argparse.Namespace) -> ControlStore:
    state_root = Path(arguments.state_root)
    return ControlStore(state_root / "control" / "state.sqlite3")


def _print(value: object, *, pretty: bool = True) -> None:
    serialized = canonical_json(value)
    if pretty:
        print(json.dumps(json.loads(serialized), indent=2, ensure_ascii=False))
    else:
        print(serialized)


def _proposal_mapping(proposal: Proposal) -> dict[str, Any]:
    return {
        "proposal_id": proposal.proposal_id,
        "proposal_digest": proposal.proposal_digest,
        "created_at": proposal.created_at,
        **dict(proposal.digest_payload()),
    }


def _save_proposal(arguments: argparse.Namespace, proposal: Proposal) -> int:
    _store(arguments).register_proposal(proposal)
    _print(_proposal_mapping(proposal))
    return 0


def proposal_show(arguments: argparse.Namespace) -> int:
    proposal = _store(arguments).get_proposal(arguments.proposal_id)
    _print(_proposal_mapping(proposal))
    return 0


def proposal_approve(arguments: argparse.Namespace) -> int:
    if not arguments.confirm_exact_chat_approval:
        print(
            "refused: record approval only after Andrew approved this exact proposal in chat",
            file=sys.stderr,
        )
        return 2
    store = _store(arguments)
    proposal = store.get_proposal(arguments.proposal_id)
    if proposal.policy_version.startswith("fixture-"):
        print("refused: fixture proposals cannot be approved for live apply", file=sys.stderr)
        return 2
    now = workflow_now()
    expiry = min(proposal.expires_at, now + timedelta(minutes=20))
    if expiry <= now:
        print("refused: proposal has expired", file=sys.stderr)
        return 2
    approval = Approval.create(
        proposal_digest=proposal.proposal_digest,
        chat_reference=arguments.approval_ref,
        approved_at=now,
        expires_at=expiry,
    )
    store.record_approval(approval)
    _print(approval)
    return 0


def apply_disabled(arguments: argparse.Namespace) -> int:
    proposal = _store(arguments).get_proposal(arguments.proposal_id)
    print(
        f"refused: live write contract is disabled for {proposal.platform.value}/"
        f"{proposal.operation}; approval was not consumed",
        file=sys.stderr,
    )
    return 2


def audit_show(arguments: argparse.Namespace) -> int:
    store = _store(arguments)
    events = [
        event
        for event in store.audit_events()
        if event["execution_id"] == arguments.execution_id
    ]
    _print(events)
    return 0


def execution_show(arguments: argparse.Namespace) -> int:
    execution = _store(arguments).get_execution(arguments.execution_id)
    _print(execution)
    return 0


def reconcile_disabled(arguments: argparse.Namespace) -> int:
    execution = _store(arguments).get_execution(arguments.execution_id)
    print(
        f"refused: no enabled read-only reconciliation contract for {execution.platform}/"
        f"{execution.operation}; execution remains {execution.status.value}",
        file=sys.stderr,
    )
    return 2


def limacharlie_inspect(arguments: argparse.Namespace) -> int:
    rule = load_rule(Path(arguments.rule_file))
    _print(
        {
            "name": rule.name,
            "digest": rule.digest,
            "enabled": rule.enabled,
            "stateful": rule.stateful,
            "event_types": rule.event_types,
            "responses": rule.respond,
            "metadata": rule.usr_mtd,
        }
    )
    return 0


def limacharlie_plan_fixture_create(arguments: argparse.Namespace) -> int:
    rule = load_rule(Path(arguments.rule_file))
    event_type = sorted(rule.event_types)[0]
    validation = validate_rule_results(
        rule,
        validator_rule_digest=rule.digest,
        validator_passed=True,
        tests=(
            RuleTestResult("fixture expected match", event_type, True, True),
            RuleTestResult("fixture expected non-match", event_type, False, False),
        ),
    )
    validation["source"] = "fixture-only; not a LimaCharlie validator response"
    proposal = build_rule_proposal(
        organization_id=arguments.organization_id,
        operation="create",
        desired=rule,
        current=None,
        validation=validation,
        replay=None,
        policy_version="fixture-1",
        created_at=workflow_now(),
    )
    return _save_proposal(arguments, proposal)


def velociraptor_plan_collection(arguments: argparse.Namespace) -> int:
    specification = load_collection_spec(Path(arguments.spec))
    scope = ResolvedClientScope(
        tuple(arguments.client_id),
        resolved_at=workflow_now(),
        source_label=arguments.source_label,
    )
    proposal = build_collection_proposal(
        scope=scope,
        specification=specification,
        policy_version="1",
        server_identity=arguments.server_identity,
        created_at=workflow_now(),
    )
    return _save_proposal(arguments, proposal)


def velociraptor_plan_hunt(arguments: argparse.Namespace) -> int:
    specification = load_collection_spec(Path(arguments.spec))
    if arguments.standing_label is not None:
        scope: ResolvedClientScope | StandingHuntScope = StandingHuntScope(
            arguments.standing_label,
            tuple(arguments.client_id or ()),
        )
    else:
        scope = ResolvedClientScope(tuple(arguments.client_id), resolved_at=workflow_now())
    proposal = build_hunt_proposal(
        scope=scope,
        specification=specification,
        policy_version="1",
        server_identity=arguments.server_identity,
        created_at=workflow_now(),
    )
    return _save_proposal(arguments, proposal)


def velociraptor_plan_export(arguments: argparse.Namespace) -> int:
    state_root = Path(arguments.state_root).resolve()
    allowed = state_root / "velociraptor" / "exports"
    destination = allowed / f"{arguments.identifier}-{uuid4().hex[:8]}"
    proposal = build_export_proposal(
        kind=arguments.kind,
        identifier=arguments.identifier,
        client=arguments.client_id,
        server_identity=arguments.server_identity,
        destination_root=destination,
        allowed_export_root=allowed,
        policy_version="1",
        created_at=workflow_now(),
    )
    return _save_proposal(arguments, proposal)


def splunk_plan_fixture_csv(arguments: argparse.Namespace) -> int:
    state_root = Path(arguments.state_root).resolve()
    destination = state_root / "splunk" / "normalized" / f"{uuid4().hex}.csv"
    timestamp = TimestampPolicy(
        arguments.timestamp_field,
        source_zone=arguments.source_zone,
        fold=arguments.fold,
        rationale=arguments.source_zone_rationale,
    )
    dataset = normalize_csv(
        Path(arguments.source),
        destination,
        timestamp=timestamp,
        host_mapping=HostMapping(mode="constant", constant=arguments.host),
        delimiter=arguments.delimiter,
    )
    coverage = classify_coverage(
        dataset,
        CoverageEvidence((), indexed_search_complete=True, monitor_inventory_complete=True),
    )
    budget = evaluate_budget(
        now=workflow_now(),
        measured_bytes=0,
        pending_bytes=0,
        competing_bytes=0,
        proposed_bytes=dataset.normalized_bytes,
        measurement_complete=True,
        reset_boundary_confirmed=True,
    )
    parsing_hash = hashlib.sha256(arguments.sourcetype.encode("utf-8")).hexdigest()
    proposal = build_ingest_proposal(
        dataset=dataset,
        coverage=coverage,
        budget=budget,
        index="dfir",
        sourcetype=arguments.sourcetype,
        policy_version="fixture-1",
        parsing_contract_sha256=parsing_hash,
        before_state={"fixture_indexed_coverage": "empty"},
        created_at=workflow_now(),
    )
    return _save_proposal(arguments, proposal)


def action1_plan_fixture_deployment(arguments: argparse.Namespace) -> int:
    endpoint = EndpointIdentity(
        action1_endpoint_id=arguments.endpoint_id,
        velociraptor_client_id=arguments.velociraptor_client_id,
        action1_hostname=arguments.hostname,
        velociraptor_hostname=arguments.hostname,
        action1_machine_id=arguments.machine_id,
        velociraptor_machine_id=arguments.machine_id,
    )
    package = DeploymentPackage(
        package_id=arguments.package_id,
        version=arguments.version,
        upstream_sha256=arguments.upstream_sha256,
        repackaged_sha256=arguments.repackaged_sha256,
        client_configuration_sha256=arguments.client_configuration_sha256,
        provenance=arguments.provenance,
    )
    proposal = build_deployment_proposal(
        organization_id=arguments.organization_id,
        automation_id=arguments.automation_id,
        endpoint=endpoint,
        package=package,
        expected_checkin_window_seconds=arguments.checkin_window_seconds,
        deployment_settings={"source": "fixture-cli"},
        current_deployment_state={"source": "fixture-cli", "status": "unknown"},
        policy_version="fixture-1",
        created_at=workflow_now(),
    )
    return _save_proposal(arguments, proposal)
