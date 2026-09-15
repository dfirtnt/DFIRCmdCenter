"""Command-line entry point for DFIR Command Center."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from dfircmdcenter import __version__
from dfircmdcenter.commands import (
    DEFAULT_STATE_ROOT,
    action1_plan_fixture_deployment,
    apply_disabled,
    audit_show,
    execution_show,
    limacharlie_inspect,
    limacharlie_plan_fixture_create,
    proposal_approve,
    proposal_show,
    reconcile_disabled,
    splunk_plan_fixture_csv,
    velociraptor_plan_collection,
    velociraptor_plan_export,
    velociraptor_plan_hunt,
)
from dfircmdcenter.core.canonical import canonical_json
from dfircmdcenter.core.records import Platform
from dfircmdcenter.core.time import workflow_now
from dfircmdcenter.status import status_reports


def build_parser() -> argparse.ArgumentParser:
    """Build the credential-free top-level parser."""

    parser = argparse.ArgumentParser(
        prog="dfirctl",
        description=(
            "Approval-gated local control plane for Action1, LimaCharlie, "
            "Velociraptor, and Splunk Free."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--state-root",
        type=Path,
        default=DEFAULT_STATE_ROOT,
        help=argparse.SUPPRESS,
    )
    commands = parser.add_subparsers(dest="command")
    status = commands.add_parser("status", help="read bounded platform status")
    status.add_argument("platform", nargs="?", choices=[item.value for item in Platform])
    status.add_argument(
        "--fixture-root",
        type=Path,
        help="read version-controlled fixture status instead of live read-only status",
    )
    status.add_argument("--pretty", action="store_true", help="indent JSON output")

    proposal = commands.add_parser("proposal", help="show or record approval for a proposal")
    proposal_commands = proposal.add_subparsers(dest="proposal_command", required=True)
    show = proposal_commands.add_parser("show")
    show.add_argument("proposal_id")
    show.set_defaults(handler=proposal_show)
    approve = proposal_commands.add_parser("approve")
    approve.add_argument("proposal_id")
    approve.add_argument("--approval-ref", required=True)
    approve.add_argument("--confirm-exact-chat-approval", action="store_true")
    approve.set_defaults(handler=proposal_approve)

    apply = commands.add_parser("apply", help="apply an enabled exact proposal")
    apply.add_argument("proposal_id")
    apply.set_defaults(handler=apply_disabled)

    verify = commands.add_parser("verify", help="show current execution verification state")
    verify.add_argument("execution_id")
    verify.set_defaults(handler=execution_show)

    reconcile = commands.add_parser("reconcile", help="read-reconcile an unknown execution")
    reconcile.add_argument("execution_id")
    reconcile.set_defaults(handler=reconcile_disabled)

    audit = commands.add_parser("audit", help="read execution audit events")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)
    audit_show_parser = audit_commands.add_parser("show")
    audit_show_parser.add_argument("execution_id")
    audit_show_parser.set_defaults(handler=audit_show)

    limacharlie = commands.add_parser("limacharlie")
    lc_commands = limacharlie.add_subparsers(dest="lc_command", required=True)
    lc_inspect = lc_commands.add_parser("inspect-rule")
    lc_inspect.add_argument("rule_file")
    lc_inspect.set_defaults(handler=limacharlie_inspect)
    lc_plan = lc_commands.add_parser("plan")
    lc_plan_operations = lc_plan.add_subparsers(dest="lc_plan_operation", required=True)
    lc_create = lc_plan_operations.add_parser("fixture-create")
    lc_create.add_argument("rule_file")
    lc_create.add_argument("--organization-id", required=True)
    lc_create.set_defaults(handler=limacharlie_plan_fixture_create)

    velociraptor = commands.add_parser("velociraptor")
    velo_commands = velociraptor.add_subparsers(dest="velo_command", required=True)
    velo_plan = velo_commands.add_parser("plan")
    velo_operations = velo_plan.add_subparsers(dest="velo_operation", required=True)
    velo_collection = velo_operations.add_parser("collection")
    velo_collection.add_argument("--spec", required=True)
    velo_collection.add_argument("--client-id", action="append", required=True)
    velo_collection.add_argument("--source-label")
    velo_collection.add_argument("--server-identity", default="local-velociraptor-0.77.2")
    velo_collection.set_defaults(handler=velociraptor_plan_collection)
    velo_hunt = velo_operations.add_parser("hunt")
    velo_hunt.add_argument("--spec", required=True)
    velo_target = velo_hunt.add_mutually_exclusive_group(required=True)
    velo_target.add_argument("--client-id", action="append")
    velo_target.add_argument("--standing-label")
    velo_hunt.add_argument("--server-identity", default="local-velociraptor-0.77.2")
    velo_hunt.set_defaults(handler=velociraptor_plan_hunt)
    velo_export = velo_operations.add_parser("export")
    velo_export.add_argument("kind", choices=("flow", "hunt"))
    velo_export.add_argument("identifier")
    velo_export.add_argument("--client-id")
    velo_export.add_argument("--server-identity", default="local-velociraptor-0.77.2")
    velo_export.set_defaults(handler=velociraptor_plan_export)

    splunk = commands.add_parser("splunk")
    splunk_commands = splunk.add_subparsers(dest="splunk_command", required=True)
    splunk_plan = splunk_commands.add_parser("plan")
    splunk_operations = splunk_plan.add_subparsers(dest="splunk_operation", required=True)
    splunk_csv = splunk_operations.add_parser("fixture-csv")
    splunk_csv.add_argument("source")
    splunk_csv.add_argument("--timestamp-field", required=True)
    splunk_csv.add_argument("--host", required=True)
    splunk_csv.add_argument("--sourcetype", required=True)
    splunk_csv.add_argument("--delimiter", default=",")
    splunk_csv.add_argument("--source-zone")
    splunk_csv.add_argument("--source-zone-rationale")
    splunk_csv.add_argument("--fold", type=int, choices=(0, 1))
    splunk_csv.set_defaults(handler=splunk_plan_fixture_csv)

    action1 = commands.add_parser("action1")
    action1_commands = action1.add_subparsers(dest="action1_command", required=True)
    action1_plan = action1_commands.add_parser("plan")
    action1_operations = action1_plan.add_subparsers(dest="action1_operation", required=True)
    deployment = action1_operations.add_parser("fixture-deployment")
    deployment.add_argument("--organization-id", required=True)
    deployment.add_argument("--automation-id", required=True)
    deployment.add_argument("--endpoint-id", required=True)
    deployment.add_argument("--velociraptor-client-id", required=True)
    deployment.add_argument("--hostname", required=True)
    deployment.add_argument("--machine-id", required=True)
    deployment.add_argument("--package-id", required=True)
    deployment.add_argument("--version", required=True)
    deployment.add_argument("--upstream-sha256", required=True)
    deployment.add_argument("--repackaged-sha256", required=True)
    deployment.add_argument("--client-configuration-sha256", required=True)
    deployment.add_argument("--provenance", required=True)
    deployment.add_argument("--checkin-window-seconds", type=int, default=600)
    deployment.set_defaults(handler=action1_plan_fixture_deployment)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI."""

    arguments = build_parser().parse_args(argv)
    if arguments.command == "status":
        selected = (
            (Platform(arguments.platform),)
            if arguments.platform is not None
            else tuple(Platform)
        )
        reports = status_reports(
            selected,
            captured_at=workflow_now(),
            fixture_root=arguments.fixture_root,
        )
        payload = [report.to_mapping() for report in reports]
        if arguments.pretty:
            print(json.dumps(json.loads(canonical_json(payload)), indent=2, ensure_ascii=False))
        else:
            print(canonical_json(payload))
        return 0
    handler = getattr(arguments, "handler", None)
    if handler is not None:
        return int(handler(arguments))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
