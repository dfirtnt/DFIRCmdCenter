# telemetry.sysmon rollback

Rollback is a separate, exact endpoint-specific Action1 action. It is not an
automatic response to an install or verification failure.

Run `scripts/Uninstall-TelemetrySysmon.ps1` only after a new proposal identifies
the exact endpoint, module version, canonical bundle hash, reason, and expected
effect. The script requires the ownership record at
`%ProgramData%\FamilyHardening\telemetry.sysmon\module-state.json`. It validates
that the state, bundled binary, installed binary, and Microsoft signature all
belong to this module before invoking ordinary `-u` removal.

The rollback refuses a missing or mismatched ownership record, a mismatched
installed binary, and unexplained state drift. It never uses force removal.
After uninstall, it confirms the Sysmon64 service and SysmonDrv driver are gone
and retains a `rolled-back` ownership record for audit and idempotent
reconciliation.

Do not use this rollback to remove a manually installed or separately managed
Sysmon instance. Do not delete the Operational log or already-retained
LimaCharlie telemetry. If Action1 reports an unknown result, reconcile service,
driver, state, and events read-only before proposing a retry or recovery.
