from __future__ import annotations

import time
from collections.abc import Callable
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from dfircmdcenter.adapters.action1.client import Action1ResponseError
from dfircmdcenter.adapters.action1.live_client import (
    ACTION1_REGIONS,
    Action1Credentials,
    Action1LiveClient,
    region_base_url,
)

BASE_URL = "https://app.action1.com/api/3.0"


def _credentials() -> Action1Credentials:
    return Action1Credentials(client_id="client-1", client_secret="s3cr3t")


def _client(
    handler: Callable[[httpx.Request], httpx.Response], *, clock: Callable[[], float] | None = None
) -> Action1LiveClient:
    from dfircmdcenter.core.transport import HttpPolicy, HttpTransport

    transport = HttpTransport(
        HttpPolicy(
            base_url=BASE_URL,
            allowed_origins=frozenset({"https://app.action1.com"}),
            allowed_query_keys=frozenset(
                {
                    "from",
                    "limit",
                    "filter",
                    "live_only",
                    "event",
                    "timefrom",
                    "timeto",
                    "sortby",
                    "from_id",
                }
            ),
        ),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    return Action1LiveClient(
        base_url=BASE_URL,
        credentials=_credentials(),
        transport=transport,
        clock=clock if clock is not None else time.monotonic,
    )


def _token_response(*, expires_in: int = 3600) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "access_token": "tok-abc",
            "refresh_token": "refresh-abc",
            "expires_in": expires_in,
            "token_type": "Bearer",
        },
    )


def _query(request: httpx.Request) -> dict[str, str]:
    parsed = parse_qs(urlsplit(str(request.url)).query)
    return {key: values[0] for key, values in parsed.items()}


def test_region_base_url_known_and_unknown() -> None:
    assert region_base_url("eu") == ACTION1_REGIONS["eu"]
    with pytest.raises(ValueError, match="unknown Action1 region"):
        region_base_url("mars")


def test_list_endpoints_authenticates_once_and_paginates_by_offset() -> None:
    token_calls = 0
    page_calls: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_calls
        if request.url.path == "/api/3.0/oauth2/token":
            token_calls += 1
            assert "authorization" not in request.headers
            return _token_response()
        assert request.url.path == "/api/3.0/endpoints/managed/org-1"
        assert request.headers["authorization"] == "Bearer tok-abc"
        query = _query(request)
        page_calls.append(query)
        offset = int(query["from"])
        limit = int(query["limit"])
        assert limit == 2
        all_items = [{"id": "1"}, {"id": "2"}, {"id": "3"}]
        page = all_items[offset : offset + limit]
        return httpx.Response(
            200,
            json={"total_items": len(all_items), "limit": limit, "items": page},
        )

    client = _client(handler)
    result = client.list_endpoints("org-1", limit=2)

    assert [item["id"] for item in result] == ["1", "2", "3"]
    assert token_calls == 1
    assert [call["from"] for call in page_calls] == ["0", "2"]


def test_token_is_cached_until_near_expiry() -> None:
    now = [1000.0]
    token_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_calls
        if request.url.path == "/api/3.0/oauth2/token":
            token_calls += 1
            return _token_response(expires_in=60)
        return httpx.Response(200, json={"total_items": 0, "limit": 100, "items": []})

    client = _client(handler, clock=lambda: now[0])
    client.list_endpoints("org-1")
    assert token_calls == 1

    now[0] += 10  # well inside the 60s TTL minus the 30s safety margin
    client.list_endpoints("org-1")
    assert token_calls == 1

    now[0] += 40  # now past (60 - 30) seconds since issuance
    client.list_endpoints("org-1")
    assert token_calls == 2


def test_oauth_failure_raises_credential_free_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"user_message": "invalid client credentials"})

    client = _client(handler)
    with pytest.raises(Action1ResponseError) as excinfo:
        client.list_endpoints("org-1")
    message = str(excinfo.value)
    assert "401" in message
    assert "client-1" not in message
    assert "s3cr3t" not in message


def test_pagination_rejects_total_items_drift() -> None:
    call = [0]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/3.0/oauth2/token":
            return _token_response()
        call[0] += 1
        total = 5 if call[0] == 1 else 6
        return httpx.Response(200, json={"total_items": total, "limit": 1, "items": [{"id": "x"}]})

    client = _client(handler)
    with pytest.raises(Action1ResponseError, match="total changed"):
        client.list_endpoints("org-1", limit=1)


def test_pagination_bounds_max_items() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/3.0/oauth2/token":
            return _token_response()
        query = _query(request)
        offset = int(query["from"])
        page = [{"id": str(offset + i)} for i in range(10)]
        return httpx.Response(200, json={"total_items": 1000, "limit": 10, "items": page})

    client = _client(handler)
    result = client.list_endpoints("org-1", limit=10, max_items=25)
    assert len(result) == 25


def test_redaction_strips_secret_fields_from_items() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/3.0/oauth2/token":
            return _token_response()
        return httpx.Response(
            200,
            json={
                "total_items": 1,
                "limit": 100,
                "items": [{"id": "1", "api_key": "super-secret", "name": "box"}],
            },
        )

    client = _client(handler)
    result = client.list_endpoints("org-1")
    assert result[0]["api_key"] == "[REDACTED]"
    assert result[0]["name"] == "box"


def test_get_missing_updates_targets_one_endpoint() -> None:
    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/3.0/oauth2/token":
            return _token_response()
        seen_paths.append(request.url.path)
        return httpx.Response(200, json={"total_items": 1, "limit": 100, "items": [{"kb": "KB1"}]})

    client = _client(handler)
    result = client.get_missing_updates("org-1", "endpoint-9")
    assert result == ({"kb": "KB1"},)
    assert seen_paths == ["/api/3.0/endpoints/managed/org-1/endpoint-9/missing-updates"]


def test_get_missing_updates_rejects_unsafe_endpoint_id() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _token_response()

    client = _client(handler)
    with pytest.raises(ValueError, match="endpoint_id"):
        client.get_missing_updates("org-1", "../etc/passwd")


def test_get_vulnerabilities_uses_org_scoped_path() -> None:
    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/3.0/oauth2/token":
            return _token_response()
        seen_paths.append(request.url.path)
        return httpx.Response(
            200, json={"total_items": 1, "limit": 100, "items": [{"cve_id": "CVE-2024-0001"}]}
        )

    client = _client(handler)
    result = client.get_vulnerabilities("org-1")
    assert result[0]["cve_id"] == "CVE-2024-0001"
    assert seen_paths == ["/api/3.0/vulnerabilities/org-1"]


def test_get_software_inventory_passes_live_only_flag() -> None:
    seen_queries: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/3.0/oauth2/token":
            return _token_response()
        seen_queries.append(_query(request))
        return httpx.Response(200, json={"total_items": 0, "limit": 100, "items": []})

    client = _client(handler)
    client.get_software_inventory("org-1", live_only=True)
    assert seen_queries[0]["live_only"] == "Yes"


def test_get_audit_log_filters_by_organization_id_client_side() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/3.0/oauth2/token":
            return _token_response()
        assert request.url.path == "/api/3.0/audit/events"
        return httpx.Response(
            200,
            json={
                "total_items": 2,
                "limit": 100,
                "items": [
                    {"id": "1", "org_id": "org-1"},
                    {"id": "2", "org_id": "org-2"},
                ],
            },
        )

    client = _client(handler)
    result = client.get_audit_log(organization_id="org-1")
    assert [event["id"] for event in result] == ["1"]


def test_get_alerts_flags_endpoints_needing_attention() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/3.0/oauth2/token":
            return _token_response()
        items = [
            {
                "id": "1",
                "name": "healthy-box",
                "status": "Connected",
                "update_status": "SUCCESS",
                "vulnerability_status": "SUCCESS",
                "reboot_required": "No",
            },
            {
                "id": "2",
                "name": "needs-reboot",
                "status": "Connected",
                "update_status": "SUCCESS",
                "vulnerability_status": "SUCCESS",
                "reboot_required": "Yes",
            },
            {
                "id": "3",
                "name": "critical-vulns",
                "status": "Connected",
                "update_status": "SUCCESS",
                "vulnerability_status": "SUCCESS",
                "reboot_required": "No",
                "vulnerabilities": {"critical": 3, "other": 0},
            },
        ]
        return httpx.Response(200, json={"total_items": len(items), "limit": 100, "items": items})

    client = _client(handler)
    alerts = client.get_alerts("org-1")
    names = {alert["name"] for alert in alerts}
    assert names == {"needs-reboot", "critical-vulns"}
    reboot_alert = next(alert for alert in alerts if alert["name"] == "needs-reboot")
    assert reboot_alert["derived_alert_reasons"] == ["reboot_required"]


def test_malformed_json_response_raises_action1_response_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/3.0/oauth2/token":
            return _token_response()
        return httpx.Response(200, content=b"not json")

    client = _client(handler)
    with pytest.raises(Action1ResponseError, match="malformed JSON"):
        client.list_endpoints("org-1")
