# telemetry.limacharlie-wel 1.0.0

This is an offline-staged Windows 11 x64 endpoint module for the Windows Event
Log sources intended for LimaCharlie. It contains a parameterless, read-only
local source preflight plus a non-pushable shared-platform desired state. It is
not uploaded to Action1, applied to LimaCharlie, live-schema validated, approved
for deployment, or release-eligible.

The desired state separates four channel groups into four independent rules and
tags so conditional sources are never accidentally included in one combined rule:

- `core`: Security, System, Windows PowerShell Operational, Task Scheduler
  Operational, and WMI Activity Operational.
- `sysmon`: conditional on the separately managed Sysmon module.
- `appcontrol`: conditional on future Code Integrity or AppLocker audit policy.
- `defender`: deferred while a third-party antivirus product is primary.

The local preflight calls `Get-WinEvent -ListLog` and emits only channel name,
group, bounded status, and enabled state. It does not read events or event
bodies, alter a channel, contact LimaCharlie, or establish that a cloud sensor
received anything.

## Apply boundary

The YAML under `platforms/limacharlie/artifact-rules/` is desired state, not a
vendor API payload. Before any platform proposal, export the complete current
Artifact Collection rules and supported live schema, pin their digests, resolve
the exact test sensor by strong identifiers, and privately record the exact SID,
selected groups, exact patterns, group tags, and complete impacted-SID set.
Re-read tag membership immediately before the write and abort on drift. Tags are
filters, not identity authority. Confirm that Reliable Tasking and the Artifact
extension are enabled and read back that Exfil/Event Collection permits WEL for
the applicable Windows rule. Enabling WEL is a separate approved platform action.
Do not infer scope from a hostname.

Each shared group-rule proposal, endpoint group-tag assignment, rule application,
active test-event generation step, LimaCharlie sensor restart after Sysmon
installation, and rollback is a separate consequential action. An ambiguous
write is reconciled read-only and is never retried automatically.

## Privacy and evidence

Security 4688, PowerShell 4103/4104, Sysmon, Task Scheduler, and WMI events can
contain usernames, command lines, scripts, file paths, network information, and
host identifiers. This version excludes the Application log, PowerShell
transcripts, raw EVTX collection, and PowerShellCore. Validation receipts record
only bounded routing, channel, event-ID, and timing evidence; they do not copy
event bodies.

Platform rule success is not ingestion proof. Promotion requires a fresh event
from the exact correlated sensor, exact channel and event ID, and a post-change
UTC window. Report-only expectations never authorize endpoint response.

Sources:

- [LimaCharlie Windows Event Logs](https://docs.limacharlie.io/2-sensors-deployment/tutorials/windows-event-logs/)
- [LimaCharlie Artifact Extension](https://docs.limacharlie.io/5-integrations/extensions/limacharlie/artifact/)
- [LimaCharlie data estimation and retention](https://docs.limacharlie.io/7-administration/billing/data-estimation/)
- [LimaCharlie privacy FAQ](https://docs.limacharlie.io/8-reference/faq/privacy/)
