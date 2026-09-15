"""Fixed Splunk command shapes; live submission remains execution-engine only."""

from __future__ import annotations

from pathlib import Path

from dfircmdcenter.core.transport import ExecutablePolicy

SPLUNK_BINARY = Path("/Users/starlord/splunk/bin/splunk")


def oneshot_policy(*, allowed_input_root: Path) -> ExecutablePolicy:
    return ExecutablePolicy(
        executable=SPLUNK_BINARY,
        allowed_argument_prefixes=(("add", "oneshot"),),
        allowed_cwd_roots=(allowed_input_root,),
        stdout_line_allowlist=(r"^(?:Added|WARNING:|Splunk>)[^\r\n]*$",),
        stderr_line_allowlist=(r"^(?:WARNING:|ERROR:)[^\r\n]*$",),
    )

