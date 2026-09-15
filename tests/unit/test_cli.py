from __future__ import annotations

import pytest

import dfircmdcenter
from dfircmdcenter.cli import main


def test_package_imports() -> None:
    assert dfircmdcenter.__version__ == "0.1.0"


def test_help_succeeds_without_platform_access(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "Action1" in output
    assert "LimaCharlie" in output
    assert "Velociraptor" in output
    assert "Splunk Free" in output

