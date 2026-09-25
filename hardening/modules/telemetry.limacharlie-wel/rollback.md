# telemetry.limacharlie-wel rollback

Rollback has two separate lifecycles. It is never automatic and is not triggered
solely because a local source is unavailable or a fresh test event has not arrived.

Endpoint rollback restores only the exact sensor's before-state for the exact
group-tag assignment. It must not create, update, restore, or delete a shared
Artifact Collection rule. Each tag rollback is a separate endpoint proposal
bound to a strong sensor identity, approved change digest, reason, and expected
effect.

Shared group-rule rollback is a separate shared-platform proposal. It requires
the exact rule before-state, post-change digest, and a fresh complete resolved set
of every impacted sensor SID. Re-read the exact tag membership immediately before
the write and abort on drift. Never infer shared-rule safety merely because one
endpoint has had its tag removed.

Rollback does not disable the shared LimaCharlie Artifact Extension or Windows
Event Log capability. It does not delete already retained telemetry, alter local
Windows log channels, remove Sysmon, change audit policy, or remove unrelated
rules and tags. If the live rule or tag state no longer matches the recorded
post-change state, stop and reconcile it read-only instead of overwriting drift.
