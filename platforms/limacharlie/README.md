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

