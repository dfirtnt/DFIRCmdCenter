"""Command-line entry point for DFIR Command Center."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from dfircmdcenter import __version__
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
    commands = parser.add_subparsers(dest="command")
    status = commands.add_parser("status", help="read bounded platform status")
    status.add_argument("platform", nargs="?", choices=[item.value for item in Platform])
    status.add_argument(
        "--fixture-root",
        type=Path,
        help="read version-controlled fixture status instead of live read-only status",
    )
    status.add_argument("--pretty", action="store_true", help="indent JSON output")
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


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
