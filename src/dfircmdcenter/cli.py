"""Command-line entry point for DFIR Command Center."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from dfircmdcenter import __version__


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI."""

    build_parser().parse_args(argv)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

