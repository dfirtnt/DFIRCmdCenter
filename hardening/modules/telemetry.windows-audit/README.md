# telemetry.windows-audit 1.0.1

This is an offline-staged, endpoint-scoped Action1 source module. It is not uploaded to
Action1, release-eligible, or approved for deployment.

The module uses `auditpol.exe` with audit-subcategory GUIDs, rather than localized names,
to configure only this bounded baseline:

| Audit subcategory | Value |
| --- | --- |
| Process Creation | Success |
| Logon, Account Lockout, Credential Validation | Success and Failure |
| Special Logon | Success |
| User Account Management, Security Group Management | Success and Failure |
| Audit Policy Change | Success and Failure |
| Authentication Policy Change, Authorization Policy Change | Success |
| Sensitive Privilege Use, Security System Extension, System Integrity | Success and Failure |

It also sets `ProcessCreationIncludeCmdLine_Enabled` to `1`. Together with Audit Process
Creation, that produces Security event `4688` with process command lines. Command lines
can contain passwords, tokens, private paths, and user data. Treat the Security channel as
sensitive, do not put secrets in Action1 arguments, and do not widen access to Security
events solely for this module.

The module deliberately does not configure file-system, registry, object-access, WMI,
task-scheduler, PowerShell, or domain-controller auditing. It also leaves Security-log
capacity and retention for a later dedicated module. These boundaries avoid turning a
small family baseline into an untested high-volume collection profile.

The installer captures only the selected audit subcategory values and the single command
line registry value before its first apply. Its rollback restores just those captured
values; it never restores a whole-system `auditpol` backup. Use `artifacts.yaml` to verify
immutable script hashes before creating an Action1 multi-file custom package. Package
staging and deployment each need their own approval.

Reference: [Microsoft's command-line process auditing guidance](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-auditsettings) and [auditpol guidance](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get).
