"""Read-only, credentialed Action1 API client for MCP Server A.

Server A is always-on and read-only: it never submits a proposal, never
writes, and never handles the OAuth-token bytes anywhere but in memory. Every
response passes through :func:`dfircmdcenter.core.redaction.redact` before it
leaves this module, and every error raised here is credential-free.

Action1 has no first-class "alerts" API resource (confirmed against the
published OAS 3.1 spec at ``https://app.action1.com/apidocs/`` on
2026-09-25). ``get_alerts`` is therefore a derived view over
``list_endpoints``: it flags endpoints whose own reported fields indicate
they need attention (failed patch or vulnerability scans, a pending reboot,
or outstanding critical items) rather than calling a vendor "alerts" path
that does not exist. See ``_ALERT_REASONS`` for the exact rules.

Pagination note: Action1's list responses are not uniformly shaped -- some
carry a ``next_page`` continuation URL, others only ``total_items``/``limit``
with an implicit offset. Rather than follow a server-supplied URL (which
would reopen the "arbitrary URL" surface `HttpTransport` is built to close),
every list call here walks bounded ``from``/``limit`` offsets itself and
stops on an empty page, a short page, or the declared total.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

from dfircmdcenter.adapters.action1.client import (
    Action1ResponseError,
    managed_endpoints_path,
    safe_identifier,
    safe_oauth_error,
)
from dfircmdcenter.core.redaction import redact
from dfircmdcenter.core.transport import HttpLimits, HttpPolicy, HttpTransport, QueryValue

#: Base URLs Action1 publishes for its regional API deployments.
ACTION1_REGIONS: Mapping[str, str] = {
    "na": "https://app.action1.com/api/3.0",
    "na-2": "https://app.na-2.action1.com/api/3.0",
    "eu": "https://app.eu.action1.com/api/3.0",
    "uk": "https://app.uk.action1.com/api/3.0",
    "au": "https://app.au.action1.com/api/3.0",
}

_TOKEN_PATH = "/oauth2/token"
_DEFAULT_PAGE_LIMIT = 100
_DEFAULT_MAX_ITEMS = 2000
_DEFAULT_MAX_PAGES = 50
_TOKEN_EXPIRY_SAFETY_SECONDS = 30.0

_ALLOWED_QUERY_KEYS = frozenset(
    {"from", "limit", "filter", "live_only", "event", "timefrom", "timeto", "sortby", "from_id"}
)


@dataclass(frozen=True, slots=True)
class Action1Credentials:
    """OAuth client-credentials pair. Never rendered in ``repr`` or logs."""

    client_id: str
    client_secret: str

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "Action1Credentials(client_id=[REDACTED], client_secret=[REDACTED])"


def region_base_url(region: str) -> str:
    try:
        return ACTION1_REGIONS[region]
    except KeyError as exc:
        allowed = ", ".join(sorted(ACTION1_REGIONS))
        raise ValueError(f"unknown Action1 region {region!r}; expected one of: {allowed}") from exc


def _coerce_int(value: object, *, field: str) -> int:
    if isinstance(value, bool):
        raise Action1ResponseError(f"Action1 {field} field is malformed")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError as exc:
            raise Action1ResponseError(f"Action1 {field} field is malformed") from exc
    raise Action1ResponseError(f"Action1 {field} field is malformed")


class Action1LiveClient:
    """Bounded, read-only Action1 API client.

    Every public method returns a redacted tuple of plain mappings. No method
    on this class ever issues a POST/PATCH/PUT/DELETE against Action1.
    """

    def __init__(
        self,
        *,
        base_url: str,
        credentials: Action1Credentials,
        limits: HttpLimits | None = None,
        transport: HttpTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._credentials = credentials
        self._clock = clock
        self._token: str | None = None
        self._token_expires_at: float = 0.0
        self._owns_transport = transport is None
        parsed_base = urlsplit(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
        self._transport = transport or HttpTransport(
            HttpPolicy(
                base_url=base_url,
                allowed_origins=frozenset({origin}),
                allowed_query_keys=_ALLOWED_QUERY_KEYS,
                allowed_request_headers=frozenset(
                    {"accept", "authorization", "content-type", "user-agent"}
                ),
            ),
            limits=limits,
        )

    def close(self) -> None:
        if self._owns_transport:
            self._transport.close()

    def __enter__(self) -> Action1LiveClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- authentication -----------------------------------------------

    def _ensure_token(self) -> str:
        now = self._clock()
        if self._token is not None and now < self._token_expires_at:
            return self._token
        body = urlencode(
            {
                "client_id": self._credentials.client_id,
                "client_secret": self._credentials.client_secret,
            }
        ).encode("ascii")
        response = self._transport.request(
            "POST",
            _TOKEN_PATH,
            headers={"content-type": "application/x-www-form-urlencoded"},
            content=body,
            sensitive_response=True,
        )
        if response.status_code != 200:
            raise safe_oauth_error(response.status_code)
        try:
            payload = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Action1ResponseError("Action1 OAuth response was not valid JSON") from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        expires_in = payload.get("expires_in") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise Action1ResponseError("Action1 OAuth response did not include an access token")
        ttl = _coerce_int(expires_in, field="expires_in") if expires_in is not None else 3600
        self._token = token
        self._token_expires_at = now + max(ttl - _TOKEN_EXPIRY_SAFETY_SECONDS, 0.0)
        return token

    # -- transport -----------------------------------------------------

    def _get(
        self, path: str, *, query: Mapping[str, QueryValue | None]
    ) -> Mapping[str, object]:
        token = self._ensure_token()
        clean_query: dict[str, QueryValue] = {
            key: value for key, value in query.items() if value is not None
        }
        response = self._transport.request(
            "GET",
            path,
            query=clean_query,
            headers={"authorization": f"Bearer {token}"},
        )
        if response.status_code != 200:
            raise Action1ResponseError(f"Action1 request failed with status {response.status_code}")
        try:
            payload = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Action1ResponseError("Action1 returned malformed JSON") from exc
        if not isinstance(payload, dict):
            raise Action1ResponseError("Action1 response root is malformed")
        return payload

    def _paginate(
        self,
        path: str,
        *,
        query: Mapping[str, QueryValue | None],
        limit: int,
        max_items: int,
        max_pages: int,
    ) -> tuple[Mapping[str, object], ...]:
        if limit <= 0 or max_items <= 0 or max_pages <= 0:
            raise ValueError("limit, max_items, and max_pages must be positive")
        items: list[Mapping[str, object]] = []
        declared_total: int | None = None
        offset = 0
        for _ in range(max_pages):
            page = self._get(path, query={**query, "from": offset, "limit": limit})
            page_items = page.get("items")
            if not isinstance(page_items, list) or any(
                not isinstance(item, dict) for item in page_items
            ):
                raise Action1ResponseError("Action1 page items are malformed")
            total_raw = page.get("total_items")
            if total_raw is not None:
                total = _coerce_int(total_raw, field="total_items")
                if declared_total is None:
                    declared_total = total
                elif declared_total != total:
                    raise Action1ResponseError("Action1 total changed during pagination")
            items.extend(page_items)
            offset += len(page_items)
            exhausted = (
                len(page_items) == 0
                or len(page_items) < limit
                or (declared_total is not None and offset >= declared_total)
            )
            if exhausted or len(items) >= max_items:
                break
        else:
            raise Action1ResponseError("Action1 pagination exceeded the configured page limit")
        sanitized = redact(items[:max_items])
        assert isinstance(sanitized, list)
        return tuple(sanitized)

    # -- read-only operations -------------------------------------------

    def list_endpoints(
        self,
        organization_id: str,
        *,
        filter_text: str | None = None,
        limit: int = _DEFAULT_PAGE_LIMIT,
        max_items: int = _DEFAULT_MAX_ITEMS,
    ) -> tuple[Mapping[str, object], ...]:
        """List managed endpoints for one organization, newest data first."""

        return self._paginate(
            managed_endpoints_path(organization_id),
            query={"filter": filter_text},
            limit=limit,
            max_items=max_items,
            max_pages=_DEFAULT_MAX_PAGES,
        )

    def get_missing_updates(
        self,
        organization_id: str,
        endpoint_id: str,
        *,
        limit: int = _DEFAULT_PAGE_LIMIT,
        max_items: int = _DEFAULT_MAX_ITEMS,
    ) -> tuple[Mapping[str, object], ...]:
        """List missing updates for one specific endpoint."""

        path = (
            f"{managed_endpoints_path(organization_id)}"
            f"/{safe_identifier(endpoint_id, 'endpoint_id')}/missing-updates"
        )
        return self._paginate(
            path, query={}, limit=limit, max_items=max_items, max_pages=_DEFAULT_MAX_PAGES
        )

    def get_vulnerabilities(
        self,
        organization_id: str,
        *,
        filter_text: str | None = None,
        limit: int = _DEFAULT_PAGE_LIMIT,
        max_items: int = _DEFAULT_MAX_ITEMS,
    ) -> tuple[Mapping[str, object], ...]:
        """List CVE-level vulnerable software detected across the organization."""

        path = f"/vulnerabilities/{safe_identifier(organization_id, 'organization_id')}"
        return self._paginate(
            path,
            query={"filter": filter_text},
            limit=limit,
            max_items=max_items,
            max_pages=_DEFAULT_MAX_PAGES,
        )

    def get_software_inventory(
        self,
        organization_id: str,
        *,
        filter_text: str | None = None,
        live_only: bool | None = None,
        limit: int = _DEFAULT_PAGE_LIMIT,
        max_items: int = _DEFAULT_MAX_ITEMS,
    ) -> tuple[Mapping[str, object], ...]:
        """List installed software across the organization's endpoints."""

        path = f"/installed-software/{safe_identifier(organization_id, 'organization_id')}/data"
        query: dict[str, QueryValue | None] = {"filter": filter_text}
        if live_only is not None:
            query["live_only"] = "Yes" if live_only else "No"
        return self._paginate(
            path, query=query, limit=limit, max_items=max_items, max_pages=_DEFAULT_MAX_PAGES
        )

    def get_audit_log(
        self,
        *,
        organization_id: str | None = None,
        event: str | None = None,
        timefrom: str | None = None,
        timeto: str | None = None,
        filter_text: str | None = None,
        limit: int = _DEFAULT_PAGE_LIMIT,
        max_items: int = _DEFAULT_MAX_ITEMS,
    ) -> tuple[Mapping[str, object], ...]:
        """List audit-trail events.

        Action1's ``/audit/events`` is enterprise-scoped, not
        organization-scoped: there is no ``orgId`` path or query parameter.
        When ``organization_id`` is given, this method fetches normally and
        filters the returned events on their own ``org_id`` field instead of
        asking the server to scope the query.
        """

        events = self._paginate(
            "/audit/events",
            query={"event": event, "timefrom": timefrom, "timeto": timeto, "filter": filter_text},
            limit=limit,
            max_items=max_items,
            max_pages=_DEFAULT_MAX_PAGES,
        )
        if organization_id is None:
            return events
        safe_org = safe_identifier(organization_id, "organization_id")
        return tuple(event for event in events if event.get("org_id") == safe_org)

    def get_alerts(
        self,
        organization_id: str,
        *,
        limit: int = _DEFAULT_PAGE_LIMIT,
        max_items: int = _DEFAULT_MAX_ITEMS,
    ) -> tuple[Mapping[str, object], ...]:
        """Derive an "alerts" view from endpoint health; Action1 has no alerts API.

        An endpoint is included when it reports a pending reboot, a failed
        update or vulnerability scan, or an outstanding critical item. Each
        returned entry keeps the original endpoint fields and adds a
        ``derived_alert_reasons`` list explaining why it was flagged.
        """

        endpoints = self.list_endpoints(organization_id, limit=limit, max_items=max_items)
        alerts: list[Mapping[str, object]] = []
        for endpoint in endpoints:
            reasons = _alert_reasons(endpoint)
            if reasons:
                alerts.append({**endpoint, "derived_alert_reasons": reasons})
        return tuple(alerts)


def _alert_reasons(endpoint: Mapping[str, object]) -> list[str]:
    reasons: list[str] = []
    if str(endpoint.get("reboot_required", "")).strip().lower() == "yes":
        reasons.append("reboot_required")
    update_status = endpoint.get("update_status")
    if isinstance(update_status, str) and update_status.upper() not in {"SUCCESS", ""}:
        reasons.append(f"update_status={update_status}")
    vulnerability_status = endpoint.get("vulnerability_status")
    if isinstance(vulnerability_status, str) and vulnerability_status.upper() not in {
        "SUCCESS",
        "",
    }:
        reasons.append(f"vulnerability_status={vulnerability_status}")
    status = endpoint.get("status")
    if isinstance(status, str) and status not in {"Connected", ""}:
        reasons.append(f"status={status}")
    missing_updates = endpoint.get("missing_updates")
    if isinstance(missing_updates, dict):
        critical = missing_updates.get("critical")
        if isinstance(critical, int) and critical > 0:
            reasons.append(f"missing_critical_updates={critical}")
    vulnerabilities = endpoint.get("vulnerabilities")
    if isinstance(vulnerabilities, dict):
        critical = vulnerabilities.get("critical")
        if isinstance(critical, int) and critical > 0:
            reasons.append(f"critical_vulnerabilities={critical}")
    return reasons


__all__ = [
    "ACTION1_REGIONS",
    "Action1Credentials",
    "Action1LiveClient",
    "region_base_url",
]
