# LimaCharlie runbook

The initial rule set under `rules/` is disabled by default and permits only `report`
responses. Endpoint actions are not allowed. Each rule has a versioned digest and must
pass LimaCharlie's validator plus meaningful expected-match and expected-non-match
tests for the declared event type.

Before any change, export the complete current rule data and `usr_mtd`. LimaCharlie
metadata POST replaces the object, so send the complete reviewed metadata—not a partial
patch. A changed rule or metadata digest invalidates approval.

Stateful rules require Replay against exact sensor IDs and an exact UTC time range.
Creating the Replay job and deploying the validated rule are separate actions with
separate approvals. A rule update, enable, disable, metadata change, and delete are also
separate operations.

Use `dfirctl limacharlie inspect-rule FILE` for local structural review. The
`fixture-create` planner is non-live test scaffolding and cannot be approved for apply.

## Windows Event Log desired state

`artifact-rules/family-windows-wel-v1.yaml` is a non-pushable desired-state
template, not a LimaCharlie API payload. It separates core, Sysmon, App Control,
and Defender sources into independent rules and tags. A future proposal must
export the supported live schema and complete before-state, privately resolve
the exact impacted sensor IDs and selected patterns, re-read tag membership
immediately before the write, and abort on drift.

Endpoint tag assignment and shared collection-rule lifecycle are separate
actions. Removing one endpoint's tag must never update or delete a rule shared
by other sensors. Event Collection/Exfil WEL enablement and any LimaCharlie
sensor restart after Sysmon installation are also separate actions.
