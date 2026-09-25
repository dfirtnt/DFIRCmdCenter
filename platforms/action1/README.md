# Action1 runbook

The Action1 adapter is aimed at one exact automation, organization, endpoint, package,
and version. OAuth client credentials stay outside this repository. Status output must
never include token responses, authorization headers, or a client identifier paired
with secret material.

Deployment proposals pin the upstream installer hash, repackaged MSI hash, client
configuration hash, package and automation IDs, deployment settings, and a strong
Action1-to-Velociraptor endpoint correlation. Matching hostnames alone do not establish
identity.

The personal MSI may produce `0x800B0100` because it has no publisher signature. Keep
that warning visible. It is neither a failed download nor evidence that the installer
is trusted. Verification requires both the exact installed Velociraptor version and a
fresh check-in from the strongly correlated Velociraptor client.

Writes never retry automatically. A timeout after transmission becomes `unknown`; use
read-only Action1 deployment status and Velociraptor check-in state to reconcile it.
Removal or redeployment is a new proposal and approval.

## MCP Server A (read-only fleet visibility)

`src/dfircmdcenter/mcp/action1_server.py` is a standalone MCP stdio server, separate
from `dfirctl` and the approval-gated proposal engine. It has no write capability: it
only calls Action1's `GET` endpoints through `dfircmdcenter.adapters.action1.live_client`
and returns redacted JSON. Run it directly:

```console
uv run dfirctl-action1-mcp
```

Configuration comes from the process environment only, never from a repository file:

- `ACTION1_CLIENT_ID`, `ACTION1_CLIENT_SECRET` -- required OAuth client-credentials
  pair, created in Action1 under Configuration > Users & API Credentials.
- `ACTION1_REGION` -- optional, one of `na` (default), `na-2`, `eu`, `uk`, `au`.
- `ACTION1_ORGANIZATION_ID` -- optional default organization; every tool also accepts
  an explicit `organization_id` argument that overrides it.

Six tools: `list_endpoints`, `get_patch_status`, `get_vulnerabilities`, `get_alerts`,
`get_software_inventory`, `get_audit_log`. All of them read from Action1's REST API 3.0
(confirmed against `https://app.action1.com/apidocs/` on 2026-09-25):

- `list_endpoints` / `get_patch_status` (fleet-wide) / `get_vulnerabilities` /
  `get_software_inventory` call `GET /endpoints/managed/{orgId}`,
  `GET /vulnerabilities/{orgId}`, and `GET /installed-software/{orgId}/data`
  respectively. `get_patch_status` with an `endpoint_id` instead drills down through
  `GET /endpoints/managed/{orgId}/{endpointId}/missing-updates`.
- `get_audit_log` calls `GET /audit/events`, which is enterprise-scoped (no `orgId`
  parameter); an `organization_id` argument filters the returned events on their own
  `org_id` field client-side.
- `get_alerts` is **not** a native Action1 endpoint -- Action1's API has no dedicated
  alerts resource. It derives an alerts view from `list_endpoints`, flagging any
  endpoint with a pending reboot, a failed update or vulnerability scan, a
  non-"Connected" status, or an outstanding critical item, and labels each result with
  `derived_alert_reasons`. Treat it as a best-effort summary, not a vendor-verified
  alert feed.

All list calls page themselves by `from`/`limit` offset rather than following Action1's
own `next_page`/`self` URLs, and every response is redacted before it leaves the client.

## Managed MCP clients

The repository carries project-scoped client configuration for the local read-only
server:

- Claude Code: `.mcp.json`
- Codex: `.codex/config.toml`
- Hermes: the native `action1-readonly` entry in `~/.hermes/config.yaml`, registered
  from this repository because Hermes does not currently load project-local MCP config

All three launch the same entry point, `uv run --directory
/Users/starlord/Code/Active/DFIRcmdCenter dfirctl-action1-mcp`. Credentials are never
stored in this repository. Each client must have `ACTION1_CLIENT_ID` and
`ACTION1_CLIENT_SECRET` available in its process environment; `ACTION1_REGION` and
`ACTION1_ORGANIZATION_ID` are optional. Claude Code requires approving the project
server the first time it is opened.

After changing the server or its dependencies, restart the relevant client. Verify the
registrations with `claude mcp get action1-readonly`, `codex mcp get action1-readonly`,
and `hermes mcp test action1-readonly`.

