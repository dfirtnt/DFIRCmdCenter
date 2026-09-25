# telemetry.windows-audit rollback

Rollback is a new endpoint-specific Action1 action. Before it runs, retain the prior
Action1 outcome, the local verification result, and any LimaCharlie observations. Do
not rerun a timed-out or ambiguous Action1 action.

Run `scripts/Uninstall-TelemetryWindowsAudit.ps1` only when the state file at
`%ProgramData%\FamilyHardening\telemetry.windows-audit\prechange-state.json` is present
and identifies `telemetry.windows-audit` schema version 1. The script restores only the
selected advanced-audit subcategory values and process-command-line registry value it
captured before the module's first apply. It does not use `auditpol /backup` or restore
any unowned audit setting.

The rollback retains its state file for review and does not modify Security-log capacity,
retention, archive, or deletion settings. After rollback, run
`Test-TelemetryWindowsAudit.ps1` as a state report and record the result before any later
reapplication.
