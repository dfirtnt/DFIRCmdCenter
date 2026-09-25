# Sysmon Action1 Module — Canonical 1.0.0 Test Candidate

Date: 2026-09-19  
Status: canonical source and private bundle staged offline; not uploaded, deployed, or Windows 11 validated

The earlier `v2` package was staged in Action1 but is now provenance only. It
lacks the canonical module's Windows 11 client guard and ownership-aware
rollback. Do not use that older package for a new deployment. The authoritative
contract is `hardening/modules/telemetry.sysmon/`.

## Decision

Use Microsoft Sysmon v15.22 with Olaf Hartong's pre-generated balanced
`sysmonconfig.xml`. This is an endpoint-scoped telemetry module. It is an
initial-install package for Windows 11 x64 clients only. It refuses Windows 10,
Windows Server, and any endpoint on which Sysmon is already present without the
exact module ownership record. Configuration or binary updates require a
separate reviewed module version and proposal.

The balanced configuration is the appropriate starting point for this small
personal-device fleet. Olaf explicitly describes it as the normal/balanced
configuration and recommends observation before broad rollout. The verbose and
research configurations are out of scope because their event volume and
resource cost are not appropriate for ordinary family endpoints.

## Immutable inputs

| Input | Identity |
| --- | --- |
| Sysmon | v15.22, published 2026-09-10 by Microsoft Sysinternals |
| Official source ZIP | `Sysmon.zip` SHA-256 `00ecf1b46aec99299d3ae0bca79dc621458bd014b20b509d7c5c8e8c8611aa54` |
| x64 executable | `Sysmon64.exe` SHA-256 `83d31f2478dc6716cfdbf69e5c384bf043072b5f0d8d7b2eea365f709fda4352` |
| Configuration | Olaf Hartong `sysmon-modular` commit `a5072591e173b7f7a9fe518ebd5c10e5313ef6f8` |
| Configuration schema | 4.90 |
| Configuration SHA-256 | `4516404fa30ee87cea558567820cdc78863cc4ab07889519e49eac3cca92e0d2` |

The canonical private bundle is intentionally held outside version control at
`var/staging/sysmon-2026-09-19/Sysmon-15.22-olaf-balanced-a507259-telemetry-sysmon-1.0.0.zip`.
Its SHA-256 is
`77bdecd54d2c4841c398a91dc08f505b459d9e83adef5e1efb144337857f861c`.
It contains only `Sysmon64.exe`, `sysmonconfig.xml`,
`Install-TelemetrySysmon.ps1`, and `Uninstall-TelemetrySysmon.ps1` at the ZIP
root. The standalone verifier is tracked separately and is not part of the
install bundle.

## Package safeguards

Before it installs or removes anything, the package verifies the bundled
executable's SHA-256 and Microsoft Authenticode signature. Installation also
verifies the configuration SHA-256 and checks Windows 11 x64 client scope. It
records a restricted module ownership state, refuses to adopt an existing
Sysmon instance, and treats an interrupted installation as ambiguous rather
than retrying. Rollback requires that exact state and never uses force removal.

The ZIP structure, member hashes, and XML syntax passed offline validation. A
Windows PowerShell runtime was not available on the packaging Mac, so the
scripts still require first execution on a supported Windows 11 test endpoint
before they are release-eligible.

## Action1 package settings for the test

Replace the older package with a new custom package using these values only
after a separate upload proposal is approved:

| Field | Value |
| --- | --- |
| Name | `Sysmon — Olaf Balanced` |
| Vendor | `Microsoft Sysinternals / Olaf Hartong configuration` |
| Version | `15.22` |
| Scope | current organization only |
| Target platform | Windows 11 x64 client only |
| Upload | the pinned ZIP above to private Action1 Cloud |
| Installation type | Other |
| Launch file | `Install-TelemetrySysmon.ps1` |
| Successful exit code | `0` |
| Reboot action | none |

Do not add Windows 10 or Windows Server, before/after actions, a reboot, broad
exclusions, or a recurring deployment. Do not assume Action1's
installed-software display-name detection proves Sysmon's presence.

## Required acceptance evidence

The test succeeds only when all of these are true for the same endpoint after
the Action1 job reaches a terminal success state:

1. The `Sysmon64` service is running and the Sysmon Operational log is enabled.
2. Event ID 16 records the configuration change and a subsequent normal event
   is present in `Microsoft-Windows-Sysmon/Operational`.
3. LimaCharlie receives both records from the expected sensor.
4. Action1, LimaCharlie, and Velociraptor continue to check in normally.
5. No Sysmon Event ID 255 errors appear during the observation period.

Only then may we create a fresh, target-specific proposal for PHANTOM. The
test result does not itself authorize a family-endpoint deployment.

## Recovery

For a confirmed bad test installation, use the bundle's
`Uninstall-TelemetrySysmon.ps1` as a separate Action1 package action after a
new rollback proposal. The ownership record must match. Do not use force
removal as a routine rollback.

## Sources

- [Microsoft Sysmon v15.22 documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Olaf Hartong Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
- [Microsoft Sysmon event reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Action1 multi-file Windows package documentation](https://www.action1.com/documentation/prepare-multi-file-custom-packages/multi-file-custom-pack-win/)
