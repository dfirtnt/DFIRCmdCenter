# telemetry.powershell rollback

Rollback is a new endpoint-specific Action1 action. Before it runs, retain the prior
Action1 outcome, the local verification result, and any LimaCharlie observations. Do
not rerun a timed-out or ambiguous Action1 action.

Run `scripts/Uninstall-TelemetryPowerShell.ps1` only when the state file at
`%ProgramData%\FamilyHardening\telemetry.powershell\prechange-state.json` is present and
identifies `telemetry.powershell` schema version 1. The script restores only registry
values owned by this module. It does not delete policy keys that may now be used by
another control.

The rollback retains the transcript directory and existing transcript files. They can
contain sensitive values and require a separately approved retention-and-deletion
decision. If the directory existed before installation, its previous ACL is restored.

After rollback, run `Test-TelemetryPowerShell.ps1` as a state report, verify expected
Windows Event Log behavior, and record the result before any later reapplication.
