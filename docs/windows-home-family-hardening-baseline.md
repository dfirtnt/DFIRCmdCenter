# Family Windows Hardening Baseline

Date: 2026-09-15
Status: Design decisions recorded; no endpoint changes authorized by this document

## Purpose and scope

Define the security baseline for the replacement family laptop and a safe rollout path for other family Windows computers. The target device is Windows 11 Home. Action1 is the configuration and deployment plane; LimaCharlie is the EDR and centralized Windows-event telemetry plane; Velociraptor is used for validation, targeted triage, and evidence collection.

This is a personal-device baseline. It prioritizes prevention of remote-support abuse, malware execution, credential exposure, and ransomware while keeping normal family use supportable. It does not authorize a policy deployment, script, remote-control session, or endpoint change.

## Environment decisions

| Area | Decision |
| --- | --- |
| Final endpoint | Windows 11 Home; do not require a Pro upgrade for the initial baseline. |
| Management | Deploy approved, version-pinned, idempotent configuration through Action1. |
| Endpoint telemetry | Deploy LimaCharlie and explicitly configure Windows Event Log collection. Installing the sensor alone is insufficient. |
| Validation and triage | Use Velociraptor for pre/post-change checks, targeted collection, and incident response; do not use it as a continuous log shipper. |
| Sysmon | Use Olaf Hartong's balanced sysmonconfig.xml, pinned to a reviewed commit and checksum. Tune only from observed telemetry. |
| Test ring | The current test machine is Windows 10 Enterprise with Action1, LimaCharlie, and Velociraptor. It validates shared controls and telemetry, but cannot be final proof of Windows 11 Home behavior. |
| Production posture | Start detection and restrictive controls in audit mode; promote individual controls to block only after an observation period and validation. |

Windows 10 Enterprise standard servicing ended on 2025-10-14. Before relying on the test host beyond this work, record its winver version, build, and whether it is an LTSC release or covered by Extended Security Updates. A standard Windows 10 Enterprise host is useful for controlled testing but is not a substitute for a supported Windows 11 Home validation endpoint.

## Management and remote-support boundary

1. Protect the Action1 tenant with authenticator-app MFA and least-privilege roles. Review tenant audit history periodically.
2. Do not leave Action1 remote desktop at its default unattended behavior. Configure a Reject default with explicit acceptance after a known phone call, or hard-disable remote desktop if the tenant is used only for patching and deployment.
3. No other remote-support product is approved by default. Quick Assist is not an approved routine support channel and should be removed, restricted, or monitored according to the final support decision.
4. Never put Action1 organization-specific installers, certificate material, deployment keys, or API credentials in this repository, PowerShell command lines, or central transcript logs.

## Windows 11 Home-compatible controls

### Microsoft Defender Antivirus

Use Microsoft Defender as the single primary antivirus product. Remove expired or overlapping consumer AV products before enabling the baseline.

- Enable real-time, behavior, cloud-delivered, and script protection.
- Enable Potentially Unwanted Application blocking.
- Enable Network Protection in block mode after connectivity validation.
- Enable tamper protection through Windows Security and confirm it manually; a completed script alone is not proof.
- Do not add broad path exclusions for management products. Allow a narrowly justified, verified exclusion only for a reproducible false positive.

### Firewall

- Enable Microsoft Defender Firewall for Domain, Private, and Public profiles.
- Keep default inbound behavior as block and outbound behavior as allow.
- Do not create inbound exceptions for Action1, LimaCharlie, or Velociraptor; validate their required outbound connectivity instead.
- Disable or leave disabled RDP, WinRM, Remote Registry, and file/printer sharing unless a later approved use case requires each service.
- Log dropped connections. Start with a 20 MB-or-larger log per profile and adjust from actual retention needs.
- Do not adopt endpoint-wide outbound-default-deny for this family baseline; it is fragile and does not solve the application-control problem.

### Attack Surface Reduction

ASR is supported on Windows 11 Home and is deployed by Action1 PowerShell, not Local Group Policy. ASR controls risky behavior; it does not implement the allow-only-approved-RMM requirement.

Start these in audit mode, observe for 7-14 days, and promote rules one at a time after validating Action1 and LimaCharlie:

- abuse of exploited vulnerable signed drivers
- persistence through WMI event subscription
- potentially obfuscated scripts
- JavaScript or VBScript launching downloaded executables
- executable content from email client and webmail
- copied or impersonated Windows system tools
- rebooting into Safe Mode to bypass security features
- advanced ransomware protection
- Office and Adobe child-process/executable-content protections where installed
- prevalence, age, and trusted-list protection
- PSExec and WMI process-creation protection

Rules with Office, prevalence, PSExec, WMI, or management-tool implications remain in audit until their effects are reviewed. Do not broadly exclude PowerShell, cmd, Action1, or LimaCharlie to silence an alert.

### Application control and unapproved RMM tools

Use App Control for Business for the approved-software-only goal. It can enforce policies on Windows 11 Home, but its PowerShell policy-authoring commands are unavailable on Home. Create and review the policy on a separate supported Windows administrative environment, then deploy the resulting policy through Action1.

The initial policy stays in audit mode. It must account for:

- Microsoft-signed Windows components and required Store applications
- Action1 and LimaCharlie components
- approved browser, office, printer/scanner, backup, and accessibility software
- no broad allow rule for Downloads, Desktop, Temp, or browser caches

After audit review, enforce the policy and test normal work plus a portable, unapproved remote-support executable. That is the acceptance test for the RMM-control objective.

### Controlled Folder Access

1. Configure Controlled Folder Access in audit mode for Documents, Desktop, Pictures, and locations containing financial or family records.
2. Review audit events for at least 7 days.
3. Allow only exact, known applications that need to write to those folders.
4. Enable block mode and test an approved document workflow plus a benign protected-folder write test.

PowerShell, command prompt, and script engines must not receive broad Controlled Folder Access allow rules.

### Disk encryption and platform protections

- Verify Device Encryption is present and enabled in Windows Settings.
- Confirm the recovery key is retained in a separate, protected location before treating encryption as complete.
- If Device Encryption is unavailable, reassess a Windows Pro upgrade for manageable BitLocker Drive Encryption before storing sensitive records on the laptop.
- Confirm Secure Boot, TPM, and Memory Integrity where compatible with installed drivers. Test Memory Integrity before leaving it enabled.

## Logging and telemetry

The Malware Archaeology sheets are a coverage checklist, not a verbatim policy source. The settings below use current Windows channels and centralize relevant telemetry in LimaCharlie.

### Security and PowerShell logging

Configure:

- Security process-creation auditing with command-line capture (event 4688)
- account logon/logoff, account management, policy change, credential validation, sensitive privilege use, system integrity, and security-system extension auditing as applicable
- PowerShell module logging (4103) and Script Block Logging (4104)
- PowerShell transcription for all users, including invocation headers, to a directory writable only by SYSTEM and Administrators
- Task Scheduler Operational, WMI Activity Operational, Windows Defender Operational, Code Integrity Operational, and AppLocker Operational logs

PowerShell script-block logs and transcripts can contain passwords, tokens, and other sensitive data. Do not pass secrets in Action1 script arguments. Transcript files are not Windows Event Log records; retain them locally with restrictive ACLs and retrieve them only when needed unless a separate collection method is approved.

### Sysmon

Deploy Sysmon after hashing the installer and reviewed Olaf Hartong configuration commit. Use the balanced sysmonconfig.xml as the starting point, not a research/verbose configuration. Configure useful local retention and stream the Sysmon Operational channel to LimaCharlie. Review observed noise before adding exclusions.

### LimaCharlie Windows Event Log collection

Enable Windows Event Log collection in LimaCharlie and configure real-time collection rules for at least:

- wel://Security:*
- wel://System:*
- wel://Microsoft-Windows-PowerShell/Operational:*
- wel://Microsoft-Windows-Sysmon/Operational:*
- wel://Microsoft-Windows-Windows Defender/Operational:*
- wel://Microsoft-Windows-CodeIntegrity/Operational:*
- wel://Microsoft-Windows-AppLocker/MSI and Script:*
- wel://Microsoft-Windows-TaskScheduler/Operational:*
- wel://Microsoft-Windows-WMI-Activity/Operational:*

No separate Winlogbeat, WEF, or generic log-shipping agent is required if this collection is verified end-to-end. LimaCharlie is the log shipper in this design. Installing its endpoint sensor without the collection configuration does not meet the central-logging objective.

Initial LimaCharlie detections are alert-only. Create and validate alerts for:

- sensor offline or uninstall attempts
- Sysmon service/configuration changes
- Defender, ASR, Controlled Folder Access, or firewall tampering
- Security log clearing
- new services and scheduled tasks
- Quick Assist or unapproved remote-support software execution
- suspicious PowerShell and WMI activity

Do not enable automatic isolation, process termination, blocking, or remote tasking for this family baseline without a separate proposed and approved action.

## Recovery, browser, and home-network controls

- Maintain versioned cloud backup plus an encrypted, disconnected backup copy. Cloud synchronization by itself is not a backup.
- Test restoring a representative document and photo collection before calling backup complete.
- Keep browser SmartScreen/Safe Browsing enabled; minimize extensions and remove unused ones.
- Update router firmware; disable WAN administration, WPS, and unneeded UPnP; remove unnecessary port forwards; use WPA2/WPA3 and separate IoT/guest devices where practical.
- Establish a family support rule: unexpected support calls, pop-ups, or remote-access requests are refused; assistance starts only after the family initiates a known phone call.

## Staged rollout and acceptance criteria

### Stage 0: Record current state

Capture the exact Windows edition/build, installed software, Defender state, Device Encryption state, firewall state, Action1 endpoint identity, LimaCharlie sensor identity, and Velociraptor client identity. Confirm backups before enabling restrictive controls.

### Stage 1: Test machine

Validate Action1 deployment behavior, Sysmon install/update behavior, logging-policy syntax, LimaCharlie event ingestion, Velociraptor checks, Defender, and firewall changes. This stage does not authorize enforcing the same configuration on Windows 11 Home.

### Stage 2: Windows 11 Home audit ring

Apply logging, Sysmon, LimaCharlie, Defender, firewall, ASR-audit, Controlled Folder Access-audit, and App Control-audit to the replacement laptop. Validate:

1. Action1, LimaCharlie, and Velociraptor remain healthy.
2. Security, PowerShell, Sysmon, Defender, and Code Integrity events arrive in LimaCharlie.
3. Normal browser, printing, backup, and family application workflows operate.
4. No management scripts depend on secrets exposed through command lines or transcripts.

### Stage 3: Enforce and verify

Promote one control family at a time, with a recorded before/after state and rollback plan. Complete only when all of the following hold:

- tamper protection and Device Encryption are manually confirmed
- firewall profiles are enabled and unwanted inbound services are disabled
- ASR and Controlled Folder Access show the intended enforcement mode
- application control blocks a portable unapproved RMM without breaking Action1 or LimaCharlie
- a benign protected-folder write test is blocked while approved software works
- LimaCharlie receives expected telemetry and reports a test alert
- backup restoration succeeds

## Open items before enforcement

- Record the Windows 10 Enterprise test machine's exact version/build and servicing status.
- Confirm whether Action1 remote desktop will be disabled or configured for explicit acceptance after a family-initiated call.
- Confirm Device Encryption status and recovery-key storage for the replacement laptop.
- Inventory required family software before finalizing App Control allow rules.
- Decide retention and collection method for sensitive PowerShell transcripts.

## Reference material

- [Microsoft Defender ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft App Control feature availability](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/feature-availability)
- [Microsoft BitLocker and Device Encryption overview](https://support.microsoft.com/en-us/windows/security/encryption/bitlocker-overview)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Olaf Hartong Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
- [LimaCharlie Windows Event Log ingestion](https://docs.limacharlie.io/2-sensors-deployment/tutorials/windows-event-logs/)
- [Action1 remote desktop](https://www.action1.com/documentation/remote-desktop/)
- [Action1 supported operating systems](https://www.action1.com/patch-management/operating-system-patching/)
