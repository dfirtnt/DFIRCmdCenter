"""MCP Server A: always-on, read-only Action1 fleet visibility.

Exposes six read-only tools over Action1's live API: ``list_endpoints``,
``get_patch_status``, ``get_vulnerabilities``, ``get_alerts``,
``get_software_inventory``, and ``get_audit_log``. Nothing here writes to
Action1, approves anything, or touches the approval-gated proposal engine
used elsewhere in this repository -- Server A only reads.

Credentials come from the process environment, never from a repository
file:

  ACTION1_CLIENT_ID      required
  ACTION1_CLIENT_SECRET  required
  ACTION1_REGION         optional, one of na|na-2|eu|uk|au (default: na)
  ACTION1_ORGANIZATION_ID  optional default organization for every tool

Run directly for local stdio use (e.g. from a Claude Desktop MCP config):

  uv run dfirctl-action1-mcp
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from mcp.server.mcpserver import MCPServer

from dfircmdcenter.adapters.action1.live_client import (
    Action1Credentials,
    Action1LiveClient,
    region_base_url,
)

_DEFAULT_LIMIT = 100
_MAX_LIMIT = 500

server = MCPServer(
    name="action1-readonly",
    title="Action1 (read-only)",
    description=(
        "Always-on, read-only visibility into a personal Action1 RMM tenant: "
        "managed endpoints, patch status, vulnerabilities, derived alerts, "
        "installed software, and the audit trail. No write capability."
    ),
)

_client: Action1LiveClient | None = None


class Action1ConfigurationError(RuntimeError):
    """Raised when required Action1 credentials are missing from the environment."""


def build_client_from_env(env: Mapping[str, str] | None = None) -> Action1LiveClient:
    """Build a live client from process environment variables.

    Never accepts credentials as function arguments from a caller-controlled
    path; this is the only place environment variables are read.
    """

    source = env if env is not None else os.environ
    client_id = source.get("ACTION1_CLIENT_ID", "")
    client_secret = source.get("ACTION1_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        raise Action1ConfigurationError(
            "ACTION1_CLIENT_ID and ACTION1_CLIENT_SECRET must be set in the process "
            "environment; Action1 credentials are never read from a repository file."
        )
    region = source.get("ACTION1_REGION", "na")
    base_url = region_base_url(region)
    return Action1LiveClient(
        base_url=base_url,
        credentials=Action1Credentials(client_id=client_id, client_secret=client_secret),
    )


def _client_singleton() -> Action1LiveClient:
    global _client
    if _client is None:
        _client = build_client_from_env()
    return _client


def _resolve_organization_id(organization_id: str | None) -> str:
    if organization_id:
        return organization_id
    default = os.environ.get("ACTION1_ORGANIZATION_ID", "")
    if default:
        return default
    raise ValueError(
        "organization_id was not provided and ACTION1_ORGANIZATION_ID is not set"
    )


def _bounded_limit(limit: int) -> int:
    if limit <= 0:
        raise ValueError("limit must be positive")
    return min(limit, _MAX_LIMIT)


@server.tool()
def list_endpoints(
    organization_id: str | None = None,
    filter_text: str | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> dict[str, object]:
    """List managed Action1 endpoints in one organization.

    ``filter_text`` is a case-insensitive substring match against endpoint
    fields (hostname, OS, user, etc.), matching Action1's own ``filter``
    query parameter.
    """

    org_id = _resolve_organization_id(organization_id)
    items = _client_singleton().list_endpoints(
        org_id, filter_text=filter_text, limit=_bounded_limit(limit)
    )
    return {"organization_id": org_id, "count": len(items), "endpoints": items}


@server.tool()
def get_patch_status(
    organization_id: str | None = None,
    endpoint_id: str | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> dict[str, object]:
    """Get patch/update status.

    Without ``endpoint_id``, returns a fleet-wide summary (per-endpoint
    missing-update counts, update status, and reboot-required flag) derived
    from the endpoint list. With ``endpoint_id``, returns the exact list of
    missing updates for that one endpoint.
    """

    org_id = _resolve_organization_id(organization_id)
    client = _client_singleton()
    if endpoint_id:
        updates = client.get_missing_updates(org_id, endpoint_id, limit=_bounded_limit(limit))
        return {
            "organization_id": org_id,
            "endpoint_id": endpoint_id,
            "count": len(updates),
            "missing_updates": updates,
        }
    endpoints = client.list_endpoints(org_id, limit=_bounded_limit(limit))
    summary = [
        {
            "id": endpoint.get("id"),
            "name": endpoint.get("name"),
            "device_name": endpoint.get("device_name"),
            "update_status": endpoint.get("update_status"),
            "reboot_required": endpoint.get("reboot_required"),
            "missing_updates": endpoint.get("missing_updates"),
            "last_seen": endpoint.get("last_seen"),
        }
        for endpoint in endpoints
    ]
    return {"organization_id": org_id, "count": len(summary), "endpoints": summary}


@server.tool()
def get_vulnerabilities(
    organization_id: str | None = None,
    filter_text: str | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> dict[str, object]:
    """List CVE-level vulnerable software detected across the organization."""

    org_id = _resolve_organization_id(organization_id)
    items = _client_singleton().get_vulnerabilities(
        org_id, filter_text=filter_text, limit=_bounded_limit(limit)
    )
    return {"organization_id": org_id, "count": len(items), "vulnerabilities": items}


@server.tool()
def get_alerts(
    organization_id: str | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> dict[str, object]:
    """List endpoints that need attention.

    Action1 has no dedicated "alerts" API. This derives an alerts view from
    each endpoint's own reported health: a pending reboot, a failed update or
    vulnerability scan, a non-"Connected" status, or outstanding critical
    items. Each returned entry carries ``derived_alert_reasons`` explaining
    why it was included.
    """

    org_id = _resolve_organization_id(organization_id)
    items = _client_singleton().get_alerts(org_id, limit=_bounded_limit(limit))
    return {
        "organization_id": org_id,
        "count": len(items),
        "alerts": items,
        "note": "Derived from endpoint health; Action1 has no native alerts API.",
    }


@server.tool()
def get_software_inventory(
    organization_id: str | None = None,
    filter_text: str | None = None,
    live_only: bool | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> dict[str, object]:
    """List installed software across the organization's endpoints."""

    org_id = _resolve_organization_id(organization_id)
    items = _client_singleton().get_software_inventory(
        org_id, filter_text=filter_text, live_only=live_only, limit=_bounded_limit(limit)
    )
    return {"organization_id": org_id, "count": len(items), "software": items}


@server.tool()
def get_audit_log(
    organization_id: str | None = None,
    event: str | None = None,
    timefrom: str | None = None,
    timeto: str | None = None,
    filter_text: str | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> dict[str, object]:
    """List Action1 audit-trail events (user actions and configuration changes).

    ``timefrom``/``timeto`` use Action1's own format: YYYY-MM-DD_HH-MM-SS.
    ``event`` is a comma-separated list of Action1 event names (for example
    "Login,Create User"). ``organization_id`` filters client-side on each
    event's own ``org_id`` field, since Action1's audit API is
    enterprise-scoped and has no ``orgId`` parameter.
    """

    org_id = organization_id or os.environ.get("ACTION1_ORGANIZATION_ID") or None
    items = _client_singleton().get_audit_log(
        organization_id=org_id,
        event=event,
        timefrom=timefrom,
        timeto=timeto,
        filter_text=filter_text,
        limit=_bounded_limit(limit),
    )
    return {"organization_id": org_id, "count": len(items), "audit_events": items}


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":  # pragma: no cover
    main()
