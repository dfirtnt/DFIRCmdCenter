# telemetry.powershell 1.0.0

This is an offline-staged, endpoint-scoped Action1 source module. It enables Windows
PowerShell 5.1 module logging, Script Block Logging, and transcription with invocation
headers. It is not uploaded to Action1, release-eligible, or approved for deployment.

The package intentionally does not enable Script Block Invocation Logging because the
start/stop events add substantial volume without being required for the initial family
baseline. It also does not configure PowerShell 7, Security audit policy, LimaCharlie,
or transcript shipping.

Transcripts are written under `%ProgramData%\FamilyHardening\PowerShellTranscripts` and
the directory ACL is limited to SYSTEM and BUILTIN\Administrators. Script blocks and
transcripts can contain passwords, tokens, and other sensitive data. Do not place
secrets in Action1 script arguments or collect transcripts centrally without a separate
retention and access decision.

Use `artifacts.yaml` to verify immutable script hashes before creating an Action1
multi-file custom package. Package staging and deployment each need their own approval.
