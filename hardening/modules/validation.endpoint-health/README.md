# validation.endpoint-health 1.0.0

This is an offline-staged, endpoint-scoped, verify-only Action1 module for Windows 11
x64 clients. It collects a bounded local security preflight and performs no install,
configuration, remediation, or rollback action.

`Test-EndpointHealth.ps1` is one parameterless Action1 Script Library artifact. Its
internal collector reads the Windows build, Secure Boot, a restricted `Win32_Tpm`
projection, Windows Security Center product state, effective Windows Firewall profiles,
Memory Integrity, and the local service state of Action1, LimaCharlie, and Velociraptor.
Its internal verifier consumes only the collector's normalized JSON contract and emits a
reconstructed allowlisted observation. Provider-controlled names are reduced to fixed
enums. The script does not emit raw hostnames, users, serials, MAC/IP addresses, platform
IDs, executable paths, recovery material, TPM owner data, or error text.

The JSON seam is internal to this parameterless script. It does not accept observation
JSON from Action1 parameters, files, network sources, or other external input.

A disabled protection or stopped service is a finding; missing, malformed, contradictory,
or incomplete required evidence fails closed.

The result remains `partial` until fresh external evidence strongly correlates the
Action1 endpoint, LimaCharlie sensor, and Velociraptor client. Hostname-only matching is
not sufficient.

The antivirus result describes Windows Security Center registration and state. It does
not determine whether McAfee or another product is paid, licensed, expiring, or a trial.
When a third-party antivirus is active, the verifier reports Defender, ASR, and
Controlled Folder Access as deferred pending an operator decision.

Raw Action1 results and platform snapshots are private endpoint evidence. If exported,
store them only under ignored restricted `var/` state; never copy them into fixtures,
module files, logs, tickets, or source control.

PowerShell is unavailable in the current packaging environment, so the source and
contract can be validated offline but runtime behavior must still be tested on a
supported Windows 11 endpoint before release promotion.
