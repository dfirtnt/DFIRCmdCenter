from __future__ import annotations

from typing import Any, cast

import pytest

from dfircmdcenter.mcp import action1_server


def test_build_client_from_env_requires_credentials() -> None:
    with pytest.raises(action1_server.Action1ConfigurationError):
        action1_server.build_client_from_env({})


def test_build_client_from_env_rejects_unknown_region() -> None:
    env = {
        "ACTION1_CLIENT_ID": "id",
        "ACTION1_CLIENT_SECRET": "secret",
        "ACTION1_REGION": "mars",
    }
    with pytest.raises(ValueError, match="unknown Action1 region"):
        action1_server.build_client_from_env(env)


def test_build_client_from_env_defaults_to_na_region() -> None:
    env = {"ACTION1_CLIENT_ID": "id", "ACTION1_CLIENT_SECRET": "secret"}
    client = action1_server.build_client_from_env(env)
    assert client._transport._base_url == "https://app.action1.com/api/3.0"


def test_resolve_organization_id_prefers_explicit_argument(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACTION1_ORGANIZATION_ID", "env-org")
    assert action1_server._resolve_organization_id("explicit-org") == "explicit-org"


def test_resolve_organization_id_falls_back_to_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACTION1_ORGANIZATION_ID", "env-org")
    assert action1_server._resolve_organization_id(None) == "env-org"


def test_resolve_organization_id_raises_without_any_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ACTION1_ORGANIZATION_ID", raising=False)
    with pytest.raises(ValueError, match="organization_id"):
        action1_server._resolve_organization_id(None)


def test_bounded_limit_caps_at_maximum() -> None:
    assert action1_server._bounded_limit(10_000) == action1_server._MAX_LIMIT


def test_bounded_limit_rejects_non_positive() -> None:
    with pytest.raises(ValueError, match="positive"):
        action1_server._bounded_limit(0)


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []

    def list_endpoints(
        self, organization_id: str, **kwargs: object
    ) -> tuple[dict[str, Any], ...]:
        self.calls.append(("list_endpoints", (organization_id,), kwargs))
        return (
            {
                "id": "1",
                "name": "box-1",
                "device_name": "WKSTA-1",
                "update_status": "SUCCESS",
                "reboot_required": "No",
                "missing_updates": {"critical": 0, "other": 0},
                "last_seen": "2026-09-20_08-00-00",
            },
        )

    def get_missing_updates(
        self, organization_id: str, endpoint_id: str, **kwargs: object
    ) -> tuple[dict[str, Any], ...]:
        self.calls.append(("get_missing_updates", (organization_id, endpoint_id), kwargs))
        return ({"package_id": "pkg-1"},)

    def get_vulnerabilities(
        self, organization_id: str, **kwargs: object
    ) -> tuple[dict[str, Any], ...]:
        self.calls.append(("get_vulnerabilities", (organization_id,), kwargs))
        return ({"cve_id": "CVE-2024-0001"},)

    def get_alerts(
        self, organization_id: str, **kwargs: object
    ) -> tuple[dict[str, Any], ...]:
        self.calls.append(("get_alerts", (organization_id,), kwargs))
        return ({"id": "2", "derived_alert_reasons": ["reboot_required"]},)

    def get_software_inventory(
        self, organization_id: str, **kwargs: object
    ) -> tuple[dict[str, Any], ...]:
        self.calls.append(("get_software_inventory", (organization_id,), kwargs))
        return ({"fields": {"Name": "7-Zip"}},)

    def get_audit_log(self, **kwargs: object) -> tuple[dict[str, Any], ...]:
        self.calls.append(("get_audit_log", (), kwargs))
        return ({"id": "1", "event": "Login"},)


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr(action1_server, "_client_singleton", lambda: client)
    monkeypatch.setenv("ACTION1_ORGANIZATION_ID", "org-1")
    return client


def _rows(payload: dict[str, object], key: str) -> list[dict[str, Any]]:
    return cast("list[dict[str, Any]]", payload[key])


def test_list_endpoints_tool_returns_wrapped_payload(fake_client: _FakeClient) -> None:
    result = action1_server.list_endpoints(limit=50)
    assert result["organization_id"] == "org-1"
    assert result["count"] == 1
    assert _rows(result, "endpoints")[0]["device_name"] == "WKSTA-1"
    assert fake_client.calls[0][0] == "list_endpoints"


def test_get_patch_status_without_endpoint_id_summarizes_fleet(fake_client: _FakeClient) -> None:
    result = action1_server.get_patch_status()
    assert result["count"] == 1
    endpoint = _rows(result, "endpoints")[0]
    assert endpoint == {
        "id": "1",
        "name": "box-1",
        "device_name": "WKSTA-1",
        "update_status": "SUCCESS",
        "reboot_required": "No",
        "missing_updates": {"critical": 0, "other": 0},
        "last_seen": "2026-09-20_08-00-00",
    }
    assert fake_client.calls[0][0] == "list_endpoints"


def test_get_patch_status_with_endpoint_id_drills_down(fake_client: _FakeClient) -> None:
    result = action1_server.get_patch_status(endpoint_id="endpoint-9")
    assert result["endpoint_id"] == "endpoint-9"
    assert result["missing_updates"] == ({"package_id": "pkg-1"},)
    assert fake_client.calls[0] == (
        "get_missing_updates",
        ("org-1", "endpoint-9"),
        {"limit": 100},
    )


def test_get_vulnerabilities_tool(fake_client: _FakeClient) -> None:
    result = action1_server.get_vulnerabilities()
    assert _rows(result, "vulnerabilities")[0]["cve_id"] == "CVE-2024-0001"


def test_get_alerts_tool_includes_note(fake_client: _FakeClient) -> None:
    result = action1_server.get_alerts()
    assert "note" in result
    assert _rows(result, "alerts")[0]["derived_alert_reasons"] == ["reboot_required"]


def test_get_software_inventory_tool(fake_client: _FakeClient) -> None:
    result = action1_server.get_software_inventory(live_only=True)
    assert _rows(result, "software")[0]["fields"]["Name"] == "7-Zip"
    assert fake_client.calls[0][2]["live_only"] is True


def test_get_audit_log_tool_defaults_organization_from_env(fake_client: _FakeClient) -> None:
    result = action1_server.get_audit_log()
    assert result["organization_id"] == "org-1"
    assert fake_client.calls[0][2]["organization_id"] == "org-1"


def test_get_audit_log_tool_allows_no_organization_scope(
    monkeypatch: pytest.MonkeyPatch, fake_client: _FakeClient
) -> None:
    monkeypatch.delenv("ACTION1_ORGANIZATION_ID", raising=False)
    result = action1_server.get_audit_log()
    assert result["organization_id"] is None
    assert fake_client.calls[0][2]["organization_id"] is None
